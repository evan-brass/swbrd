import { sock, send } from './sock.js';
import { encoder } from "../switch/util.js";
import { new_session, pull, push } from './support.js';
import { parse_ipaddr } from "../switch/ipaddr.js";
import { Stun, Class, Method } from "../switch/stun.js";
import { parse } from "../switch/turn.js";
import { mapped } from "../switch/util.js";
import { id } from "./support.js";
import { to_string } from "../src/id.js";

const hosted_ufrag = to_string(id) + ':';

const short_cred = await crypto.subtle.importKey('raw', encoder.encode('the/ice/password/constant'), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

const hosted_send = new ArrayBuffer(40, {maxByteLength: 1200})
const sessions = new Map(); // key -> { ptr, sctp state }

export async function handle(datagram, sender) {
	if (datagram.byteLength < 1) return;
	const fb = datagram[0];

	const ip = parse_ipaddr(sender.hostname);

	// STUN
	if (fb <= 3) {
		const msg = parse(datagram);

		// Connection Test:
		if (msg instanceof Stun && msg.class == Class.request && msg.method == Method.binding) {
			const ind = new Stun(send);
			crypto.getRandomValues(ind.txid);
			ind.magic = true;
			ind.class = Class.indication;
			ind.method = Method.data;
			ind.length = 0;
			ind.xpeer = { ip, port: 4666 };
			
			const resp = new Stun(hosted_send);
			resp.magic = true;
			resp.method = Method.binding;
			resp.txid.set(msg.txid);
			resp.length = 0;

			// Check ICE ufrag
			if (!msg.username || !msg.username.startsWith(hosted_ufrag)) {
				console.log('connection test but not for us.');
				// TODO: Encapsulate the packet and forward it to someone
				return;
			}
			// Check ICE pwd
			else if (!await msg.verify(short_cred)) {
				resp.class = Class.error;
				resp.errcode = 441;
			}
			// We are pseudo-ice-lite so require peer to be controlling
			else if (msg.controlled) {
				resp.class = Class.error;
				resp.errcode = 487;
				await resp.sign(short_cred);
			}
			// Bind
			else {
				resp.class = Class.success;
				resp.xmapped = { ip, port: sender.port };
				await resp.sign(short_cred);
			}

			resp.fingerprint = true;
			ind.data = resp.frame;

			await sock.send(ind.frame, sender);
		}
		// Drop any other STUN / TURN
		else { return }
	}
	// DTLS
	else if (20 <= fb && fb < 64) {
		const mip = mapped(ip);
		const key = `[${Array.from(mip, v => v.toString(16)).join(':')}]:${sender.port}\0`;

		let ptr = sessions.get(key);
		if (!ptr) sessions.set(key, ptr = new_session(key));
		if (!ptr) return;
		push(ptr, datagram);

		let pulled;
		while (1) {
			pulled = pull(ptr);
			if (pulled instanceof Uint8Array) {
				console.log('sctp', Array.from(pulled));
				continue;
			}
			if (pulled < 0) {
				console.log('Closing DTLS session');
				sessions.delete(key);
			}
			break;
		}
	}
	// Trap
	else {
		console.log('unhandled?', fb);
	}
}

export async function sample(datagram) {
	console.log('sample', datagram);
}
