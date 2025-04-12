import { from_bytes, from_string } from '../src/id.js';
import { Ip6, parse_ipaddr } from '../src/ipaddr.js';
import { Stun, Class, Method, Attr, AttrType, MAGIC_COOKIE } from '../src/stun.js';
import { encoder, write } from '../src/util.js';

import { mbedtls, mem8, memdv, check, check_non_null, func_ptr } from 'mbedtls';
import { default_ice_pwd } from '../src/const.js';

if (!import.meta.main) throw new Error("swbrd library code is in src");

const key_params = [
	{
		name: 'HMAC',
		hash: 'SHA-1',
	},
	true,
	['sign', 'verify'],
];
const turnKey = await crypto.subtle.importKey(
	'raw',
	new Uint8Array(
		// MD5(guest:none:password)
		[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173],
	),
	...key_params,
);
const iceKey = await crypto.subtle.importKey(
	'raw',
	encoder.encode(default_ice_pwd),
	...key_params,
);
const default_lifetime = 6000;
const broadcast = new Ip6(0xfe80, 0, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);

// Setup DTLS stuff
const ssl_config = check_non_null(mbedtls.new_ssl_config());
let our_id;
{
	check(mbedtls.ssl_config_defaults(
		ssl_config,
		mbedtls.SSL_IS_CLIENT,
		mbedtls.SSL_TRANSPORT_DATAGRAM,
		mbedtls.SSL_PRESET_DEFAULT,
	));
	mbedtls.debug_set_threshold(3);
	mbedtls.ssl_conf_authmode(ssl_config, mbedtls.SSL_VERIFY_OPTIONAL);
	mbedtls.set_ssl_config_dbg(ssl_config);

	// Setup entropy
	const drbg = check_non_null(mbedtls.new_hmac_drbg_context());
	const drbg_f = func_ptr(mbedtls.hmac_drbg_random);
	{
		const entropy = check_non_null(mbedtls.new_entropy_context());
		const md_info = mbedtls.md_info_from_type(0x09 /* mbedtls_md_type_t.MBEDTLS_MD_SHA256 */);
		check(mbedtls.hmac_drbg_seed(drbg, md_info, func_ptr(mbedtls.entropy_func), entropy, null, 0));
	}
	mbedtls.ssl_conf_rng(ssl_config, drbg_f, drbg);

	// Parse our certificate and private key
	const cert = check_non_null(mbedtls.new_x509_crt());
	const pk = check_non_null(mbedtls.new_pk_context());
	{
		const pem = await Deno.readFile('./cert.pem');
		const pem_len = pem.byteLength + 1;
		const pem_ptr = check_non_null(mbedtls.malloc(pem_len));
		mem8(pem_ptr).set(pem);
		mem8(pem_ptr + pem.byteLength, 1).fill(0); // mbedtls expects 1 null byte at the end of PEM strings

		check(mbedtls.x509_crt_parse(cert, pem_ptr, pem_len));
		check(mbedtls.pk_parse_key(pk, pem_ptr, pem_len, null, 0, drbg_f, drbg));
		mbedtls.free(pem_ptr);
	}
	check(mbedtls.ssl_conf_own_cert(ssl_config, cert, pk));
	mbedtls.ssl_conf_ca_chain(ssl_config, cert, null);

	// Get our id:
	our_id = from_bytes(
		new Uint8Array(await crypto.subtle.digest('SHA-256', mbedtls.get_x509_crt_raw(cert)))
	);
	console.log('Our id', our_id);

	// More configuration options
	check(mbedtls.ssl_conf_cid(ssl_config, 32, true));
}

const dtls_contexts = new Map(); // peerid -> ssl_context

const all = new Map();

function make_key(ip, port) {
	return `[${ip}]:${port}`;
}

class Turn {
	ip;
	port;
	writer;
	mappings;
	dtls;
	constructor(conn) {
		conn.setNoDelay(true);
		this.writer = conn.writable.getWriter();
		this.ip = parse_ipaddr(conn.remoteAddr.hostname);
		this.port = conn.remoteAddr.port;

		const key = make_key(this.ip, this.port);
		all.set(key, this);
		this.#handle(conn.readable).finally(() => all.delete(key));
	}
	async #handle_dtls() {
		// Prep a TURN message for any DTLS data
		const msg = new Stun(new ArrayBuffer(2048));
		msg.class = Class.Ind;
		msg.method = Method.Data;
		msg.cookie = MAGIC_COOKIE;

		// NOTE: Because one DTLS can be shared by multiple Turn's our dtls may have been closed by someone else
		while (this.dtls) {
			const res = mbedtls.ssl_read(this.dtls, null, 0);
			if (res > 0) {
				// Application data is available:
				const app = mbedtls.get_ssl_context_application_data(this.dtls);
				console.log('DTLS', app);
				app.fill(0); // Zeroize the application data buffer.
			}
			else if (res == mbedtls.ERR_SSL_WANT_WRITE) {
				const out = mbedtls.get_ssl_context_send(this.dtls);
				if (out.byteLength <= 2000) {
					msg.length = 0;
					// NOTE: Evan - you dumbass - the txid affects xor-mapped addresses, therefore you must rewrite the Peer address if you modify the txid.
					crypto.getRandomValues(msg.txid);
					msg.append(AttrType.Peer, 'addr', { ip: broadcast, port: 65535 });
					msg.append(AttrType.Data, undefined, out)

					// Write the DTLS packet out:
					await write(this.writer, new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));
				}
				memdv(mbedtls.get_ssl_context_send_res(this.dtls)).setInt32(0, out.byteLength, true);
			}
			else if (res == mbedtls.ERR_SSL_WANT_READ) {
				// DTLS is fully handled, move on
				break;
			}
			else {
				// DTLS closed:
				mbedtls.ssl_free(this.dtls);
				mbedtls.free(this.dtls);
				// Clear the DTLS from dtls_contexts
				dtls_contexts.entries().forEach(([k, v]) => {
					if (v == this.dtls) dtls_contexts.delete(k);
				});
				// Delete the DTLS from other Turn's
				all.values().forEach(t => {
					if (t.dtls == this.dtls) t.dtls = null;
				});
				// Remove the DTLS from ourself
				this.dtls = null;
				break;
			}
		}
	}
	#dtls_clean() {
		// DTLS closed:
		mbedtls.ssl_free(this.dtls);
		mbedtls.free(this.dtls);
		// Clear the DTLS from dtls_contexts
		dtls_contexts.entries().forEach(([k, v]) => {
			if (v == this.dtls) dtls_contexts.delete(k);
		});
		// Delete the DTLS from other Turn's
		all.values().forEach(t => {
			if (t.dtls == this.dtls) t.dtls = null;
		});
		// Remove the DTLS from ourself
		this.dtls = null;
	}
	async #handle_msg(msg) {
		const ret = new Stun(new ArrayBuffer(100)); // All fixed-length responses have a maximum length of 100 bytes
		ret.class = Class.Suc;
		ret.method = msg.method;
		ret.length = 0;
		ret.cookie = msg.cookie;
		ret.txid = msg.txid;

		// Parse STUN Attributes
		const [
			[
				// Allocate / Refresh / CreatePermission / ChannelBind
				username, realm, nonce,
				// Allocate
				requestedTransport,
				// Allocate / Refresh
				lifetime,
				// Send / CreatePermission / ChannelBind
				peer,
				// Send
				data,
				// ChannelBind
				_channel,
			],
			[_integrity],
			[fingerprint],
			unknown
		] = msg.parse(
			[
				[AttrType.Username, 'text'],
				[AttrType.Realm, 'text'],
				[AttrType.Nonce, 'text'],
				[AttrType.RequestedTransport, 'fucky_u8'],
				[AttrType.Lifetime, 'u32'],
				[AttrType.Peer, 'addr'],
				[AttrType.Data],
				[AttrType.ChannelNumber, 4],
			],
			[[AttrType.Integrity, 20]],
			[[AttrType.Fingerprint, 'u32']],
		);

		// Drop anything with unknown comprehension required attributes
		if (unknown.length) return;

		// Send Indications
		else if (msg.class == Class.Ind && msg.method == Method.Send) {
			if (!(peer?.ip instanceof Ip6) || !data?.byteLength) return;
			const is_broadcast = peer.ip.every((v, i) => broadcast[i] == v);

			// Send indications get modified in place and then relayed
			msg.method = Method.Data;
			const offset = msg.byteOffset
				/* STUN Header */ + Stun.minByteLength
				/* XOR-PEER-ADDRESS Header */ + Attr.minByteLength
				/* - Value: Port + IP6 */ + 20
				/* DATA Header */ + Attr.minByteLength;
			const length = data.byteLength;

			// Shift the DataAttribute to where we want it (It's probably already there, but be sure)
			new Uint8Array(msg.buffer).copyWithin(offset, data.byteOffset, data.byteOffset + length);
			const moved_data = new Uint8Array(msg.buffer, offset, length);
			// console.log(moved_data);

			const relay = async turn => {
				let peer;
				if (Array.isArray(turn.mappings)) {
					let self_port = 1 + turn.mappings.indexOf(this);
					if (self_port == 0) {
						if (turn.mappings.length >= 2000) return;
						turn.mappings.push(this);
						self_port = turn.mappings.length;
					}
					peer = { ip: broadcast, port: self_port };
				}
				else {
					peer = { ip: this.ip, port: this.port };
				}
				msg.length = 0;
				msg.append(AttrType.Peer, 'addr', peer);
				msg.append(AttrType.Data, length);
				await write(turn.writer, new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));
			};

			// Broadcast
			if (is_broadcast && peer.port == 65535) {
				/**
				 * HACK: Needed because Firefox enforces TURN permissions locally.
				 * This means that it cannot receive packets from ips which it has not
				 * granted permission too.  It can however receive from unexpected ports
				 * so we map all peer ip+ports to an assigned port at a known ip.
				 * This is unneccessary state and we only have 2000 slots available, so
				 * we only perform this mapping for Firefox and not for Chrome.
				 *
				 * Also, once the connection opens and you trickle true ICE candidates,
				 * those will have proper permissions, and thus will not hit this mapping.
				 *
				 * ISSUE: https://bugzilla.mozilla.org/show_bug.cgi?id=1952664
				 */
				if (fingerprint) this.mappings ??= [];

				// Special treatment for [fe80::ffff:ffff:ffff:ffff]:65535
				const fb = moved_data[0];
				/* STUN */ if (fb < 3) {
					// Verify that the message is an ICE connection test
					const inner = new Stun(msg.buffer, {byteOffset: offset});
					if (inner.byteLength != length) return;
					if (inner.class != Class.Req) return;
					if (inner.method != Method.Binding) return;
					if (inner.cookie != MAGIC_COOKIE) return;

					const [
						[
							username,
							priority,
							iceControlled,
							iceControlling,
							useCandidate,
						],
						[integrity],
						[fingerprint],
						unknown,
					] = inner.parse(
						[
							[AttrType.Username, 'text'],
							[AttrType.Priority, 'u32'],
							[AttrType.IceControlled, 'u64'],
							[AttrType.IceControlling, 'u64'],
							[AttrType.UseCandidate, 'bool'],
						],
						[[AttrType.Integrity, 20]],
						[[AttrType.Fingerprint, 'u32']],
					);
					if (
						unknown.length ||
						!username || !priority || !integrity || !fingerprint ||
						(typeof iceControlled == typeof iceControlling)
					) { return; }

					const [dst_ufrag, src_ufrag, more] = username.split(':');
					if (!dst_ufrag || !src_ufrag || more) return;
					const [dpid, spid] = [dst_ufrag, src_ufrag].map(from_string);
					if (!dpid || !spid) return;

					// Handle Hosted ICE
					if (dpid == our_id) {
						// Verify the message integrity:
						if (!await inner.verify(iceKey)) return;

						inner.length = 0;
						// Switch role:
						if (iceControlled) {
							inner.class = Class.Err;
							inner.append(AttrType.Error, 4, [0, 0, 4, 87]);
						}
						// Success
						else {
							inner.class = Class.Suc;

							// Create a DTLS connection for this peer
							if (useCandidate) {
								this.dtls ??= dtls_contexts.get(src_ufrag);
								if (!this.dtls) {
									this.dtls = check_non_null(mbedtls.new_ssl_context());
									check(mbedtls.ssl_setup(this.dtls, ssl_config));
									dtls_contexts.set(src_ufrag, this.dtls);
									const cid_ptr = check_non_null(mbedtls.malloc(32));
									// TODO: Use peerid (as bytes) for the cid.
									crypto.getRandomValues(mem8(cid_ptr, 32));
									check(mbedtls.ssl_set_cid(this.dtls, mbedtls.SSL_CID_ENABLED, cid_ptr, 32));
									mbedtls.free(cid_ptr);
								}
							}
						}
						inner.append(AttrType.Mapped, 'addr', { ip: this.ip, port: this.port });
						await inner.sign(iceKey)
						inner.fingerprint();

						// Write out the ICE response
						msg.length = 0;
						msg.append(AttrType.Peer, 'addr', { ip: broadcast, port: 65535 });
						msg.append(AttrType.Data, inner.byteLength);
						await write(this.writer, new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));

						// Handle DTLS
						await this.#handle_dtls();
					}
					// Broadcast the ICE connection test so that it can be discovered
					else {
						// Broadcast the ICE connection test to everyone
						for (const turn of all.values()) {
							if (turn == this) continue;
							await relay(turn);
						}
					}
				}
				/* DTLS */ else if (20 < fb && fb < 64) {
					if (fb == 25) console.log('YAY! DTLS CID!');
					if (this.dtls) {
						// Copy the data into the ssl's recv buffer.
						const recv = mbedtls.get_ssl_context_recv(this.dtls);
						if (moved_data.byteLength < recv.byteLength) {
							recv.set(moved_data);
							memdv(mbedtls.get_ssl_context_recv_res(this.dtls)).setInt32(0, moved_data.byteLength, true);
						}
					}
					await this.#handle_dtls();
					return;
				}
				/* Drop */ else { return }
			}

			// Unicast
			else {
				const turn = is_broadcast ? this.mappings?.[peer.port - 1] : all.get(make_key(peer.ip, peer.port));
				if (!turn) return;
				await relay(turn);
			}

			// We've handled relaying / hosting whatever data already so don't respond
			return;
		}

		// Drop all other non-requests
		else if (msg.class != Class.Req) return;

		// Binding Requests
		else if (msg.method == Method.Binding) {
			ret.append(AttrType.Mapped, 'addr', {ip: this.ip.canonical(), port: this.port});
		}

		// Check username, realm, and nonce
		else if (username != 'guest' || realm != 'none' || nonce != 'none') {
			ret.class = Class.Err;
			ret.append(AttrType.Error, 4, [0, 0, 4, 1]);
			ret.append(AttrType.Realm, 'text', 'none');
			ret.append(AttrType.Nonce, 'text', 'none');
		}

		// All other requests require valid integrity
		else if (!await msg.verify(turnKey)) {
			ret.class = Class.Err;
			ret.append(AttrType.Error, 4, [0, 0, 4, 3]);
		}

		// Allocate
		else if (msg.method == Method.Allocate) {
			if (requestedTransport != 17 /* UDP */) return;
			ret.append(AttrType.Mapped, 'addr', {ip: this.ip.canonical(), port: this.port});
			ret.append(AttrType.Relayed, 'addr', {ip: this.ip, port: this.port});
			ret.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime)
			await ret.sign(turnKey);
		}

		// Refresh
		else if (msg.method == Method.Refresh) {
			if (lifetime == 0) return; // Close notification -> don't respond
			ret.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime);
			await ret.sign(turnKey);
		}

		// Create Permission
		else if (msg.method == Method.CreatePermission) {
			await ret.sign(turnKey);
		}

		// Channel Bind
		else if (msg.method == Method.ChannelBind) {
			ret.class = Class.Err;
			ret.append(AttrType.Error, 4, [0, 0, 4, 38]);
			await ret.sign(turnKey)
		}

		// Drop all other requests
		else return;

		// Send the response
		await write(this.writer, new Uint8Array(ret.buffer, ret.byteOffset, ret.byteLength));
	}
	async #handle(readable) {
		const maxByteLength = 4096;
		// FUCK: Deno's Conn is taking my resiziable buffer and returning a non-resiziable one... So we need to resize the buffer manually
		let buffer = new ArrayBuffer(40);
		const reader = readable.getReader({ mode: 'byob' });

		let available = 0;
		for (;;) {
			try {
				const {value, done} = await reader.read(new Uint8Array(buffer, available));
				if (value) {
					buffer = value.buffer; // The stream apis detach buffers alot (so that they can be in different workers)
					available += value.byteLength;

					const msg = new Stun(buffer);
					const msg_byteLength = msg.byteLength;
					// Check if the message exceeds our max buffer size:
					if (msg_byteLength > maxByteLength) break;

					// Resize the buffer if needed:
					else if (msg_byteLength > buffer.byteLength) {
						// Transfer to a larger buffer
						buffer = buffer.transfer(msg_byteLength);
					}

					// If we have enough data available for this message, then consume it:
					else if (msg_byteLength <= available) {
						await this.#handle_msg(msg);

						// Shift the data in the buffer:
						new Uint8Array(buffer).copyWithin(0, msg_byteLength, available);
						available -= msg_byteLength;
					}
				}
				if (done) break;
			} catch (e) {
				console.warn(e);
				break;
			}
		}

		this.#dtls_clean();
	}
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	console.log('new', conn.remoteAddr.hostname, conn.remoteAddr.port, 'existing', all.size);
	new Turn(conn);
}
