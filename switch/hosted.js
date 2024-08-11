import { short_term } from "./auth.js";
// import { Protocol } from "./proto.js";
import { Class, Method, Stun } from "./stun.js";
// import { allocations } from "./turn.js";
import { from_string, to_string } from "../src/id.js";
import { id, Dtls } from "./dtls.js";
import { SctpConn } from "./sctp.js";

const ice_ufrag = to_string(id);
console.log(ice_ufrag);
const short_key = await short_term();

// 1. Detect ICE connection tests
// 1.a if they are directed at us then respond (handling role conflicts if needed)
// 1.b if they are directed at someone else then check if we have a connection to them and forward it to them as a datachannel message
// 2. Filter out everything except DTLS packets
// 3. Pass DTLS packets onward
export class Hosted {
	#dtls;
	#inner;
	constructor(inner) {
		this.#inner = inner;
	}
	async transform(chunk, controller) {
		if (chunk.byteLength < 1) return;

		// We reuse the msg buffer for our response (if we're going to respond)
		const msg = new Stun(chunk.buffer, chunk.byteOffset, chunk.byteLength);
		const first_byte = msg.getUint8(0);

		// Pass DTLS packets up the stack
		if (this.#dtls && 20 < first_byte && first_byte < 64) {
			this.#dtls.data(chunk);
		}
		// Handle ICE connection tests
		if (
			msg.byteLength >= msg.needed &&
			msg.class == Class.request &&
			msg.method == Method.binding &&
			msg.username.indexOf(':') != -1 &&
			msg.fingerprint
		) {
			const [dst, src] = msg.username.split(':');
			// console.log(dst, '<-', src);

			// Respond ourselves
			if (dst == ice_ufrag) {
				const pid = from_string(src);

				if (!await msg.verify(short_key)) {
					msg.length = 0;
					msg.class = Class.error; msg.errcode = 401;
				}
				else if (msg.controlled) {
					msg.length = 0;
					msg.class = Class.error; msg.errcode = 487;
					await msg.sign(short_key);
				}
				else if (!pid) {
					msg.length = 0;
					msg.class = Class.error; msg.errcode = 403;
					await msg.sign(short_key);
				}
				else {
					msg.length = 0;
					msg.class = Class.success;
					msg.xmapped = this.#inner.remoteAddr;
					await msg.sign(short_key);

					if (!this.#dtls) {
						this.#dtls = new Dtls(pid, controller);
						const sctp = new SctpConn();
						const prom = this.#dtls.readable.pipeThrough(new TransformStream(sctp)).pipeTo(this.#dtls.writable);
						// TODO: do something with prom here.
					}
				}
				msg.fingerprint = true;
				controller.enqueue(msg.frame);
			}
			// Send the msg as a datachannel message to the dst
			else {
				// TODO: Remove this broadcasting and replace it with a datachannel message to the dst that src is trying to connect to them
				// for (const turn of allocations.values()) {
				// 	if (turn == this.inner) continue;
				// 	await turn.write(value, { xpeer: this.inner.remoteAddr });
				// }
			}
		} 
	}
}
