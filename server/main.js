import {
	Turn, Data,
} from '../src/turn.js';
import {
	Stun,
	Addr4, Addr6,
	TextAttr,
	ErrorCode,
	Sha1Integrity,
	U32Attr,
	FingerprintAttr,
	Attr,
} from '../src/stun.js';
import { parse_ipaddr } from "../src/ipaddr.js";
import { Ip4, Ip6 } from '../src/ipaddr.js';
import { md5 } from '../src/md5.js';
import { default_turn_username, default_turn_credential, default_ice_pwd } from "../src/const.js";
import { encoder } from "../src/util.js";
import { id } from './wrapper.js';
import { to_string } from "../src/id.js";

const realm = 'none';
const nonce = 'none';
const broadcast = new Ip6(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff);

// TODO: Replace async crypto sign with sync mbedtls hmac implementation:
const turn_key = await crypto.subtle.importKey('raw', md5(`${default_turn_username}:${realm}:${default_turn_credential}`), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);
const ice_key = await crypto.subtle.importKey('raw', encoder.encode(default_ice_pwd), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

const send = new ArrayBuffer(2048);

const hostname = '::ffff:127.0.0.1';
// const hostname = '::';

const our_lufrag = to_string(id);
const dtls_sessions = new Map(); // key -> DTLS pointer

const sock = Deno.listenDatagram({transport: 'udp', hostname, port: 3478});
console.log('listening on', sock.addr);
for await (const [datagram, sender] of sock) {
	if (datagram.byteLength < Turn.minByteLength) continue;

	const req = new Turn(datagram).specialize();
	if (req.byteLength > datagram.byteLength) continue;

	// 4 different representations of the same information
	const ip = parse_ipaddr(sender.hostname);
	const mapped = ip.mapped();
	const conn_id = new Uint16Array([sender.port, ...mapped]);
	const key = String.fromCharCode(...new Uint8Array(conn_id.buffer));

	let res, receiver = {
		transport: 'udp',
		hostname: String(mapped),
		port: sender.port
	};
	let in_integrity, in_fingerprint;

	async function answer_ice(stun, dest) {
		// Check if there's any errors:
		const ice_controlled = stun.attrs.find(a => a.type == 'ice controlled');
		let integrity = stun.attrs.find(a => a.type == 'integrity');
		
		const answer = dest.append(Stun, {
			method: 'binding',
			cookie: stun.cookie,
			txid: stun.txid
		});

		// ICE authentication
		if (!integrity || !await integrity.verify(ice_key)) {
			answer.class = 'error';
			answer.append(ErrorCode, {
				type: 'error',
				family: 0x00,
				code: 403
			});
			integrity = false;
		}

		// ICE role conflict
		else if (ice_controlled) {
			answer.class = 'error';
			answer.append(ErrorCode, {
				type: 'error',
				family: 0x00,
				code: 487
			});
		}

		// Successful binding
		else {
			answer.class = 'success';
			answer.append(Addr6, {
				type: 'mapped',
				ip: mapped,
				port: sender.port
			});

			// TODO: If there were multiple 
			dtls_sessions.set(key, {});
		}

		// Sign the response
		if (integrity) {
			await answer.append(Sha1Integrity, {
				type: 'integrity'
			}).sign(ice_key);
		}
		// Fingerprint the response
		const print = answer.append(FingerprintAttr, {
			type: 'fingerprint'
		});
		print.actual = print.expected();
	}
	// function answer_dtls() {}

	handlers:
	// TURN Channel Data messages
	if (req instanceof Data) {
		if (req.data.byteLength >= Stun.minByteLength && req.data[0] < 3) {
			const stun = new Stun(req.data);
			if (stun.class != 'request' || stun.method != 'binding') break handlers;
			res = new Data(send, {
				channel: req.channel,
				length: 0,
			});
			await answer_ice(stun, res);
		}
		else if (req.data.byteLength > 1 && 20 <= req.data[0] && req.data[0] < 64) {
			// TODO: Handle DTLS
		}
		else { break handlers; }
	}

	// STUN Send Indication
	else if (req instanceof Stun && req.class == 'indication' && req.method == 'send') {
		const peer = req.attrs.find(a => a.type == 'peer');
		const data = req.attrs.find(a => a.type == 'data');
		if (!(peer instanceof Addr6) || !data) break handlers;
		const {ip: pip, port} = peer;

		// Hosted
		if (pip.every((v, i) => v == broadcast[i])) {
			if (data.value.byteLength >= Stun.minByteLength && data.value[0] < 3) {
				const stun = new Stun(data.value);
				if (stun.class != 'request' || stun.method != 'binding') break handlers;
				if (data.byteLength < stun.byteLength) break handlers;
				const username = stun.attrs.find(a => a.type == 'username');
				const integrity = stun.attrs.find(a => a.type == 'integrity');
				if (!username || !integrity) break handlers;

				const [lufrag, rufrag] = username.value.split(':');
				console.log(lufrag, rufrag);

				if (lufrag == our_lufrag) {
					// Wrap our answer in a data indication:
					res = new Stun(send, {
						length: 0,
						method: 'data',
						class: 'indication',
						cookie: req.cookie,
						txid: req.txid
					});
					res.append(Addr6, {
						type: 'peer',
						ip: pip,
						port
					});
					const data = res.append(Attr, {
						type: 'data',
						length: 0
					});
					await answer_ice(stun, data);
				}
				else {
					// TODO: Encapsulate the connection test into SCTP and send over DTLS, routing by lufrag
				}
			}
			else if (data.length > 1 && 20 <= data.value[0] && data.value[0] < 64) {
				// TODO: Handle DTLS
			}
			break handlers;
		}

		// Forward the packet
		receiver = {
			transport: 'udp',
			hostname: String(pip),
			port
		};

		res = new Stun(send, {
			length: 0,
			method: 'data',
			class: 'indication',
			cookie: req.cookie,
			txid: req.txid
		});
		res.append(Addr6, {
			type: 'peer',
			ip: ip.mapped(),
			port: sender.port
		});
		res.append(Attr, {
			setByteLength: data.byteLength,
			type: 'data',
			value: data.value
		});
	}

	// Ignore everything that isn't a STUN request:
	else if (!(req instanceof Stun) || req.class != 'request') {/* Drop */}

	// TODO: Add unreliability so that we cannot be abused for amplification attacks

	// STUN Binding Request:
	else if (req.method == 'binding') {
		res = new Stun(send, {
			length: 0,
			method: 'binding',
			class: 'success',
			cookie: req.cookie,
			txid: req.txid,
		});
		res.append(ip instanceof Ip4 ? Addr4 : Addr6, {
			type: 'mapped',
			port: sender.port,
			ip,
		});
	}

	// TURN Authentication:
	else if (req.attrs.find(a => a.type == 'realm')?.value != realm) {
		res = new Stun(send, {
			length: 0,
			method: req.method,
			class: 'error',
			cookie: req.cookie,
			txid: req.txid
		});
		res.append(ErrorCode, {
			type: 'error',
			family: 0x00,
			code: 401,
		});
		res.append(TextAttr, {
			setByteLength: TextAttr.minByteLength + realm.length,
			type: 'realm',
			value: realm
		});
		res.append(TextAttr, {
			setByteLength: TextAttr.minByteLength + nonce.length,
			type: 'nonce',
			value: nonce
		});
	}
	else if (!(in_integrity = req.attrs.find(a => a.type == 'integrity')) || !await in_integrity.verify(turn_key)) {
		res = new Stun(send, {
			length: 0,
			method: req.method,
			class: 'error',
			cookie: req.cookie,
			txid: req.txid
		});
		res.append(ErrorCode, {
			type: 'error',
			code: 403
		});
		in_integrity = false;
	}
	else if ((in_fingerprint = req.attrs.find(a => a.type == 'fingerprint')) && in_fingerprint.actual != in_fingerprint.expected()) {
		// STUN makes my skin crawl
		continue;
	}

	// TURN Allocate:
	else if (req.method == 'allocate') {
		const lifetime = req.attrs.find(a => a.type == 'lifetime')?.value ?? 3600;
		res = new Stun(send, {
			length: 0,
			method: req.method,
			class: 'success',
			cookie: req.cookie,
			txid: req.txid
		});
		res.append(ip instanceof Ip4 ? Addr4 : Addr6, {
			type: 'mapped',
			ip,
			port: sender.port
		});
		res.append(Addr6, {
			type: 'relayed',
			ip: ip.mapped(),
			port: sender.port
		});
		res.append(U32Attr, {
			type: 'lifetime',
			value: lifetime
		});
	}

	// TURN Create Permission
	else if (req.method == 'create permission') {
		// Re-use request buffer, because the response will be smaller then the request
		res = new Stun(req, {
			length: 0,
			class: 'success'
		});
	}

	// TURN Refresh
	else if (req.method == 'refresh') {
		const lifetime = req.attrs.find(a => a.type == 'lifetime')?.value ?? 3600;

		// Ignore lifetime == 0 because it is an optional close message, that we don't care about
		if (lifetime == 0) break handlers;

		res = new Stun(send, {
			length: 0,
			method: req.method,
			class: 'success',
			cookie: req.cookie,
			txid: req.txid
		});
		res.append(U32Attr, {
			type: 'lifetime',
			value: lifetime
		});
	}

	// TURN Channel Bind
	else if (req.method == 'channel bind') {
		const peer = req.attrs.find(a => a.type == 'peer');
		if (!dtls_sessions.has())
		if (!(peer instanceof Addr6)) break handlers;
		if (!peer.ip.every((v, i) => broadcast[i] == v)) break handlers;

		res = new Stun(send, {
			length: 0,
			method: req.method,
			class: 'success',
			cookie: req.cookie,
			txid: req.txid
		});
	}

	// Not implemented
	else {
		res = new Stun(send, {
			length: 0,
			method: req.method,
			class: 'error',
			cookie: req.cookie,
			txid: req.txid
		});
		res.append(ErrorCode, {
			type: 'error',
			code: 404
		});
	}

	// Send the packet
	if (res) {
		// Sign the packet if needed
		if (in_integrity) {
			const integrity = res.append(Sha1Integrity, {
				type: 'integrity'
			});
			await integrity.sign(turn_key);
		}
		// Fingerprint the packet if needed
		if (in_fingerprint) {
			const print = res.append(FingerprintAttr, {
				type: 'fingerprint'
			});
			print.actual = print.expected();
		}

		try { await sock.send(new Uint8Array(res.buffer, res.byteOffset, res.byteLength), receiver); }
		catch (e) { console.error(receiver, e); }
	}
}
