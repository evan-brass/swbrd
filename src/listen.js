import { cert, idf } from './cert.js';
import { Stun, Method, Class } from './stun.js';
import { Addr } from './addr.js';

export class Listener {
	#answered = new Set();
	#ws = new WebSocket('ws://local.evan-brass.net:8000/listen');
	#ice_key;
	constructor() {
		this.#ws.binaryType = 'arraybuffer';
	}
	get address() {
		return new Addr(`turn:${cert}@local.evan-brass.net`);
	}
	async *[Symbol.asyncIterator]() {
		this.#ice_key ??= await crypto.subtle.importKey('raw', new TextEncoder().encode("the/ice/password/constant"), {
			name: 'HMAC',
			hash: 'SHA-1'
		}, true, ['sign', 'verify']);
		
		while (this.#ws.readyState != WebSocket.CLOSED) {
			let msg;
			await new Promise(res => {
				this.#ws.addEventListener('message', ({data}) => {msg = new Stun(data); res(); }, {once: true});
				this.#ws.addEventListener('close', () => res(), {once: true});
				this.#ws.addEventListener('error', () => res(), {once: true});
			});
			if (msg) {
				if (msg.byteLength < msg.needed) continue;
				if (msg.method != Method.data || msg.class != Class.indication) continue;
				if (!msg.xpeer || !msg.data) continue;
				const sender = msg.get_addr(0x0012 /* xor-peer-address */, {ipv4_mapped: false});
				const inner = new Stun(msg.data.buffer, msg.data.byteOffset, msg.data.byteLength);
				if (inner.byteLength < inner.needed) continue;
				if (inner.method != Method.binding || inner.class != Class.request || !inner.fingerprint) continue;
				const [dst_id, src_id] = (inner.username ?? ':').split(':').map(s => idf.fromString(s));
				if (dst_id != BigInt(cert) || !src_id) continue;
				if (this.#answered.has(src_id)) continue;
				if (!await inner.verify(this.#ice_key)) continue;

				const conn = new Addr(`turn:${idf.toString(src_id)}@local.evan-brass.net?candidate=${encodeURIComponent(
					`candidate:foundataion 1 udp ${inner.priority} ${sender.hostname} ${sender.port} typ relay`
				)}`).connect();
				this.#answered.add(src_id);
				conn.addEventListener('close', () => this.#answered.delete(src_id));

				yield conn;
			}
		}
	}
}
