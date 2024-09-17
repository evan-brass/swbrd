import { from_bytes, to_string } from '../src/id.js';
import { decoder_lossy, encoder } from '../src/util.js';
import {
	openssl,
	check_err,
	SSL_NOTHING, SSL_READING,
	BIO_CTRL_PENDING,
	BIO_CTRL_DGRAM_SET_PEER,
	AF_INET6,
} from './openssl.js';
import { CookieAckChunk, CookieChunk, DataChunk, HeartbeatAckChunk, HeartbeatChunk, InitAckChunk, InitChunk, Param, SackChunk, Sctp } from '../src/sctp.js';
import { sock, send, broadcast } from './sock.js';
import { Data } from '../src/turn.js';
import { Addr6, MAGIC_COOKIE, Stun, Attr } from '../src/stun.js';

// Timeout parameters
const check_freq = 30 * 1000; // Every 30 sec
const timeout = 3 * 60 * 1000; // 3 min

// Load the certificate and private key
const evp_sha256 = check_err(openssl.EVP_sha256());
let pkey, cert, id; {
	const pem = Deno.readFileSync('/var/swbrd/cert.pem');
	const bio = check_err(openssl.BIO_new_mem_buf(pem, pem.byteLength));
	pkey = check_err(openssl.PEM_read_bio_PrivateKey(bio, null, null, null));
	cert = check_err(openssl.PEM_read_bio_X509(bio, null, null, null));
	openssl.BIO_free(bio);
	
	const fingerprint = new Uint8Array(32);
	check_err(openssl.X509_digest(cert, evp_sha256, fingerprint, null));

	id = from_bytes(fingerprint);
}
export { id };

// Create an SSL context
let ctx; {
	const method = openssl.DTLS_server_method();
	ctx = openssl.SSL_CTX_new(method);
	if (ctx == null) throw new Error("Failed to create the SSL ctx");

	check_err(openssl.SSL_CTX_use_certificate(ctx, cert));
	check_err(openssl.SSL_CTX_use_PrivateKey(ctx, pkey));
	check_err(openssl.SSL_CTX_check_private_key(ctx));
}

// Create a pair of datagram BIOs for the SSL contexts to share
const bio_in = openssl.BIO_new(openssl.BIO_s_dgram_mem());
const bio_out = openssl.BIO_new(openssl.BIO_s_dgram_mem());
const bio_addr = openssl.BIO_ADDR_new();

// TODO: Read the peer certificate hash it, and store a mapping to its
// export const connected = new Map(); // id -> dtls context
const verifier = new Deno.UnsafeCallback(
	{ parameters: ['i32', 'pointer'], result: 'i32' },
	function verify(_preverify_ok, _store_ctx) { return 1; }
);
openssl.SSL_CTX_set_verify(ctx, 0b11, verifier.pointer);
openssl.SSL_CTX_set_verify_depth(ctx, 0);

export class Dtls {
	static connections = new Map(); // String(Dtls.key(Ip6, port, channel)) -> dtls
	static peers = new Map(); // pid -> dtls

	ip;
	port;
	sport;
	channel;

	// Start connections with only half the timeout remaining.
	recv_stamp = performance.now() - 0.5 * timeout;

	// We really only need the address to be set on the in_bio when we're setting/checking the DTLS HelloVerify cookie
	need_addr = true;

	static key(ip, port) { return `[${ip}]:${port}`; }
	static get(ip, port) {
		const key = this.key(ip, port);
		return this.connections.get(key) ?? new this(ip, port);
	}
	static get_ufrag(ufrag) {
		return this.peers.get(ufrag);
	}

	pid;
	sctp_state = crypto.getRandomValues(new Uint32Array(2)); // [vtag, tsn]

	#ssl;
	constructor(ip, port) {
		this.ip = ip;
		this.port = port;

		this.#ssl = openssl.SSL_new(ctx);
		if (!this.#ssl) throw new Error("");

		openssl.BIO_up_ref(bio_in);
		openssl.BIO_up_ref(bio_out);
		openssl.SSL_set_bio(this.#ssl, bio_in, bio_out);
		openssl.SSL_set_accept_state(this.#ssl);

		Dtls.connections.set(Dtls.key(this.ip, this.port), this);
	}
	delete() {
		Dtls.connections.delete(Dtls.key(this.ip, this.port));
		if (this.pid) Dtls.peers.delete(this.pid);
		openssl.SSL_free(this.#ssl);
		this.#ssl = null;
	}
	push(buffer) {
		if (!this.#ssl) return;
		// if (this.need_addr) {
		// 	openssl.BIO_ADDR_clear(bio_addr);
		// 	check_err(openssl.BIO_ADDR_rawmake(
		// 		bio_addr,
		// 		AF_INET6,
		// 		this.ip,
		// 		this.ip.byteLength,
		// 		this.port
		// 	));
		// 	// check_err(openssl.BIO_ctrl(bio_in, BIO_CTRL_DGRAM_SET_PEER, 0, bio_addr));
		// 	openssl.BIO_ctrl(bio_in, BIO_CTRL_DGRAM_SET_PEER, 0, bio_addr);
		// }
		check_err(openssl.BIO_write(bio_in, buffer, buffer.byteLength));
	}
	write(buffer) {
		if (!this.#ssl) return;
		check_err(openssl.SSL_write(this.#ssl, buffer, buffer.byteLength));
	}
	send(data) {
		const ppid = typeof data == 'string' ? 51 : 53;
		const bytes = typeof data == 'string' ? encoder.encode(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice();

		const sctp = new Sctp(send, {
			sport: 500, dport: 5000,
			vtag: this.sctp_state[0]
		});

		sctp.append(DataChunk, {
			setByteLength: DataChunk.minByteLength + bytes.byteLength,
			flags: 0b000_0_1_1_1,
			tsn: (this.sctp_state[1]++),
			stream: 0,
			seq: 0,
			ppid,
			data: bytes
		});

		if (sctp.children.length) {
			sctp.checksum = sctp.expected_checksum;
			const encoded = new Uint8Array(sctp.buffer, sctp.byteOffset, sctp.byteLength);
			this.write(encoded);
		}
	}
	#handle_sctp(buffer) {
		this.recv_stamp = performance.now();
		if (buffer.byteLength >= Sctp.minByteLength) {
			const sctp = new Sctp(buffer);
			const resp = new Sctp(send, {
				sport: sctp.dport,
				dport: sctp.sport,
			});
			for (const chunk of sctp.chunks) {
				if (chunk instanceof DataChunk) {
					resp.append(SackChunk, {
						flags: 0,
						cumtsn: chunk.tsn,
						rwnd: 6000,
						gaps: 0,
						dups: 0
					});
					// const data = chunk.ppid == 51 ? decoder_lossy.decode(chunk.data) : Array.from(chunk.data);
					// console.log('SCTP data', chunk.stream, chunk.seq, chunk.ppid, data);
				}
				else if (chunk instanceof InitChunk) {
					const [vtag, init_tsn] = crypto.getRandomValues(new Uint32Array(2));
					this.sctp_state.set([chunk.vtag, init_tsn]);
					const ack = resp.append(InitAckChunk, {
						flags: 0,
						vtag,
						rwnd: 6000,
						in: chunk.out,
						out: chunk.in,
						tsn: init_tsn
					});
					if (!ack) continue;
					ack.append(Param, {
						setByteLength: Param.minByteLength + 8,
						type: 7
					});
				}
				else if (chunk instanceof CookieChunk) {
					resp.append(CookieAckChunk, {
						flags: 0
					});
				}
				else if (chunk instanceof SackChunk) {
					// Reset the TSN to whatever they last received + 1
					// We don't retransmit data, but next time we have new data we'll overwrite the old TSN
					this.sctp_state[1] = chunk.cumtsn + 1;
				}
				else if (chunk instanceof HeartbeatChunk) {
					resp.append(HeartbeatAckChunk, {
						setByteLength: chunk.byteLength,
						info: chunk.info
					});
				}
				else if (chunk.type == 6) {
					this.delete();
				}
				else {
					console.log('Unhandled SCTP chunk type:', chunk.type);
				}
			}
			resp.vtag = this.sctp_state[0];
			resp.checksum = resp.expected_checksum;
			if (resp.children.length) {
				this.write(new Uint8Array(resp.buffer, resp.byteOffset, resp.byteLength));
			}
		}
	}
	async handle() {
		const buff = new Uint8Array(1200);
		try {
			while (1) {
				if (!this.#ssl) break;
	
				let result;
				/*if (this.need_addr) {
					result = openssl.DTLSv1_listen(this.#ssl, null);
					if (result > 0) {
						this.need_addr = false;
						continue;
					}
				}
				else*/ if (!openssl.SSL_is_init_finished(this.#ssl)) {
					result = openssl.SSL_accept(this.#ssl);
					if (result > 0) continue;
					result = openssl.SSL_get_error(this.#ssl, result);
				}
				else {
					if (!this.pid) {
						const fingerprint = new Uint8Array(32);
						const cert = openssl.SSL_get0_peer_certificate(this.#ssl);
						if (!cert) return; // TODO: Close the connection
						check_err(openssl.X509_digest(cert, evp_sha256, fingerprint, null));
						this.pid = to_string(from_bytes(fingerprint));
						const existing = Dtls.peers.get(this.pid);
						if (existing) existing.delete();
						Dtls.peers.set(this.pid, this);
					}
					result = openssl.SSL_read(this.#ssl, buff, buff.byteLength);
					if (result > 0) this.#handle_sctp(buff.subarray(0, result));
				}
	
				while (openssl.BIO_ctrl(bio_out, BIO_CTRL_PENDING, 0, null) > 0) {
					const n = openssl.BIO_read(bio_out, buff, buff.byteLength);
					if (n <= 0) throw new Error("");

					let msg;
					if (this.channel) {
						msg = new Data(send, {
							setByteLength: Data.minByteLength + n,
							channel: this.channel,
							data: buff.subarray(0, n)
						});
					}
					else if (this.sport) {
						msg = new Stun(send, {
							class: 'indication',
							method: 'data',
							cookie: MAGIC_COOKIE,
							length: 0
						});
						msg.append(Addr6, {
							type: 'peer',
							ip: broadcast,
							port: this.sport
						});
						msg.append(Attr, {
							type: 'data',
							setByteLength: Attr.minByteLength + n,
							value: buff.subarray(0, n)
						});
					}
					else { return; }
	
					try {
						await sock.send(new Uint8Array(send, 0, msg.byteLength), {
							transport: 'udp',
							hostname: String(this.ip),
							port: this.port
						});
					} catch (e) {
						console.error(e);
					}
				}
	
				const want = openssl.SSL_want(this.#ssl);
				if (want == SSL_READING || want == SSL_NOTHING) break;
				check_err(openssl.SSL_get_error(this.#ssl, result));
				return;
			}
		} catch (e) {
			console.warn(e);
			this.delete();
		}
	}
}

// Timeout DTLS connections
setInterval(() => {
	// TODO: There seem to be a lot of dtls contexts that are not becoming peers.  Is this something to do with ice restarts creating DTLS contexts that only ever receive bad application data messages, and never any DTLS handshake messages?
	console.log('Checking timeouts for', Dtls.connections.size, 'contexts,', Dtls.peers.size, 'of those are peers');
	const now = performance.now();
	for (const dtls of Dtls.connections.values()) {
		if ((now - dtls.recv_stamp) < timeout) continue;
		console.log('Peer timed out', Dtls.key(dtls.ip, dtls.port, dtls.channel), dtls.pid);
		dtls.delete();
	}
}, check_freq);
