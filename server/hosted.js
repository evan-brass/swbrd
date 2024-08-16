import { sock, send } from './sock.js';
import { encoder } from "../switch/util.js";
import { new_session, pull, push, send_buff, write } from './support.js';
import { parse_ipaddr } from "../switch/ipaddr.js";
import { Stun, Class, Method } from "../switch/stun.js";
import { parse } from "../switch/turn.js";
import { mapped } from "../switch/util.js";
import { id } from "./support.js";
import { to_string } from "../src/id.js";
import { Chunk, Cookie, Init, InitAck, Param, Sack, Sctp, Data } from "../switch/sctp.js";

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

		let {
			ptr,
			tsn = crypto.getRandomValues(new Uint32Array(1)),
			vtag = new Uint32Array(1),
		} = { ...sessions.get(key) };
		if (!ptr && (ptr = new_session(key))) {
			sessions.set(key, { ptr, tsn, vtag });
		}
		if (!ptr) return;
		push(ptr, datagram);

		let pulled;
		while (1) {
			pulled = pull(ptr);
			if (pulled instanceof Uint8Array) {
				if (pulled.byteLength < 12) continue;

				const sctp = new Sctp(pulled.buffer, pulled.byteOffset, pulled.byteLength);
				const sb = send_buff();

				let byteLength = 12;
				for (const chunk of sctp) {
					if (chunk instanceof Data && (sb.byteLength - byteLength) >= 16) {
						const sack = new Sack(sb.buffer, sb.byteOffset + byteLength, 16);
						byteLength += 16;
						sack.type = Sack.type;
						sack.flags = 0;
						sack.length = 16;
						sack.cum_tsn = chunk.tsn;
						sack.arwnd = 6000;
						sack.gaps = 0;
						sack.dups = 0;
						console.log('SCTP data', chunk.flags.toString(2), chunk.stream, chunk.seq, chunk.ppi, Array.from(chunk.buffer))
					}
					else if (chunk instanceof Init && (sb.byteLength - byteLength) >= 32) {
						vtag[0] = chunk.init_vtag;

						const ack = new InitAck(sb.buffer, sb.byteOffset + byteLength, 20);
						byteLength += 20;
						ack.type = InitAck.type;
						ack.flags = 0;
						ack.length = 32;
						ack.init_vtag = crypto.getRandomValues(new Uint32Array(1))[0];
						ack.arwnd = 6000;
						ack.out_count = 65535;
						ack.in_count = 65535;
						ack.init_tsn = tsn[0];

						const cookie = new Param(sb.buffer, sb.byteOffset + byteLength, 12);
						byteLength += 12;
						cookie.type = 7;
						cookie.length = 12;
						crypto.getRandomValues(cookie.value);
					}
					else if (chunk instanceof Cookie && (sb.byteLength - byteLength) >= 4) {
						const cookie_ack = new Chunk(sb.buffer, sb.byteOffset + byteLength, 4);
						byteLength += 4;
						cookie_ack.type = 11;
						cookie_ack.flags = 0;
						cookie_ack.length = 4;
					}
					else {
						console.log('ignored SCTP chunk', chunk.type);
					}
				}

				// Only queue the response if we added at least one chunk.
				if (byteLength <= 12) continue;

				const resp = new Sctp(sb.buffer, sb.byteOffset, byteLength);
				resp.dport = sctp.sport;
				resp.sport = sctp.dport;
				resp.vtag = vtag[0];
				resp.checksum = true;

				const ret = write(ptr, byteLength);
				if (ret == 0) console.warn("Didn't send SCTP");
				if (ret < 0) {
					sessions.delete(key);
				}
			}
			if (pulled < 0) {
				sessions.delete(key);
			}
			break;
		}
	}
	// Trap
	else {
		console.log('unhandled hosted fb:', fb);
	}
}
