import { from_bytes } from '../src/id.js';
import { decoder_lossy } from '../src/util.js';
import {
	openssl,
	check_err,
	SSL_NOTHING, SSL_READING,
	BIO_CTRL_PENDING
} from './openssl.js';
import { CookieAckChunk, CookieChunk, DataChunk, HeartbeatAckChunk, HeartbeatChunk, InitAckChunk, InitChunk, Param, SackChunk, Sctp } from '../src/sctp.js';
import { sock, send } from './sock.js';
import { Data } from '../src/turn.js';
import { Ip6 } from '../src/ipaddr.js';

// Load the certificate and private key
let pkey, cert, id; {
	const pem = Deno.readFileSync('./cert.pem');
	const bio = check_err(openssl.BIO_new_mem_buf(pem, pem.byteLength));
	pkey = check_err(openssl.PEM_read_bio_PrivateKey(bio, null, null, null));
	cert = check_err(openssl.PEM_read_bio_X509(bio, null, null, null));
	openssl.BIO_free(bio);
	
	const fingerprint = new Uint8Array(32);
	const evp_sha256 = check_err(openssl.EVP_sha256());
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

// TODO: Read the peer certificate hash it, and store a mapping to its
// export const connected = new Map(); // id -> dtls context
const verifier = new Deno.UnsafeCallback(
	{ parameters: ['i32', 'pointer'], result: 'i32' },
	function verify(_preverify_ok, _store_ctx) { return 1; }
);
openssl.SSL_CTX_set_verify(ctx, 0b11, verifier.pointer);
openssl.SSL_CTX_set_verify_depth(ctx, 0);

export const connections = new Map(); // ids -> dtls;

const contexts = new Map(); // key (string version of ip+port+channel) -> { ptr, sctp_state, ip+port+channel }
export async function handle(sender, data) {
	const context = Dtls.get(sender);

	try {
		if (data) context.push(data);

		for await (const read of context) {
			if (read && read.byteLength >= Sctp.minByteLength) {
				const sctp = new Sctp(read);
				context.sctp_state ??= new Uint32Array(2); // [vtag, tsn]
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
						const data = chunk.ppid == 51 ? decoder_lossy.decode(chunk.data) : Array.from(chunk.data);
						console.log('SCTP data', chunk.stream, chunk.seq, chunk.ppid, data);
					}
					else if (chunk instanceof InitChunk) {
						const [vtag, init_tsn] = crypto.getRandomValues(new Uint32Array(2));
						context.sctp_state.set([chunk.vtag, init_tsn]);
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
						context.sctp_state[1] = chunk.cumtsn + 1;
					}
					else if (chunk instanceof HeartbeatChunk) {
						resp.append(HeartbeatAckChunk, {
							setByteLength: chunk.byteLength,
							info: chunk.info
						});
					}
					else {
						console.log('Unhandled SCTP chunk type:', chunk.type);
					}
				}
				resp.vtag = context.sctp_state[0];
				resp.checksum = resp.expected_checksum;
				if (resp.children.length) {
					// console.log('out sctp', new Uint8Array(resp.buffer, resp.byteOffset, resp.byteLength));
					context.write(new Uint8Array(resp.buffer, resp.byteOffset, resp.byteLength));
				}
			}
		}
	} catch (e) {
		console.error(e);
		context.delete();
	}
}

export class Dtls {
	static key(sender) { return String.fromCharCode(...new Uint8Array(sender.buffer, sender.byteOffset, sender.byteLength)); }
	static get(sender) {
		return contexts.get(this.key(sender)) ?? new this(sender);
	}

	sender;
	ids;
	sctp_state = crypto.getRandomValues(new Uint32Array(2));

	#in;
	#out;
	#ssl;
	constructor(sender) {
		this.sender = sender;
		this.#in = openssl.BIO_new(openssl.BIO_s_mem());
		this.#out = openssl.BIO_new(openssl.BIO_s_mem());
		this.#ssl = openssl.SSL_new(ctx);
		if (!(this.#in && this.#out && this.#ssl)) throw new Error("");
		openssl.SSL_set_accept_state(this.#ssl);
		openssl.SSL_set_bio(this.#ssl, this.#in, this.#out);

		contexts.set(Dtls.key(this.sender), this);
	}
	delete() {
		contexts.delete(Dtls.key(this.sender));
		openssl.SSL_free(this.#ssl);
	}
	push(buffer) {
		check_err(openssl.BIO_write(this.#in, buffer, buffer.byteLength));
	}
	write(buffer) {
		check_err(openssl.SSL_write(this.#ssl, buffer, buffer.byteLength));
	}
	async *[Symbol.asyncIterator]() {
		const buff = new Uint8Array(1200);
		while (1) {
			let result;
			if (!openssl.SSL_is_init_finished(this.#ssl)) {
				result = openssl.SSL_accept(this.#ssl);
				if (result > 0) continue;
				result = openssl.SSL_get_error(this.#ssl, result);
			}
			else {
				result = openssl.SSL_read(this.#ssl, buff, buff.byteLength);
				if (result > 0) yield buff.subarray(0, result);
			}

			while (openssl.BIO_ctrl(this.#out, BIO_CTRL_PENDING, 0, null) > 0) {
				const n = openssl.BIO_read(this.#out, buff, buff.byteLength);
				if (n <= 0) throw new Error("");
				
				const msg = new Data(send, {
					setByteLength: Data.minByteLength + n,
					channel: this.sender[9],
					data: buff.subarray(0, n)
				});

				try {
					await sock.send(new Uint8Array(send, 0, msg.byteLength), {
						transport: 'udp',
						hostname: String(new Ip6(...this.sender.subarray(0, 8))),
						port: this.sender[8]
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
	}
}
