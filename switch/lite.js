import { short_term } from "./auth.js";
import { Protocol } from "./proto.js";
import { Class, Method, Stun } from "./stun.js";
import { allocations } from "./turn.js";

const ice_ufrag = 'ucCm6JK3s22XuCRiTZVFpWajUq0tIpB7lDn1Sv8dRv3';
const short_key = await short_term();

// 1. Detect ICE connection tests
// 1.a if they are directed at us then respond (handling role conflicts if needed)
// 1.b if they are directed at someone else then check if we have a connection to them and forward it to them as a datachannel message
// 2. Filter out everything except DTLS packets
// 3. Pass DTLS packets onward
export class IceLite extends Protocol {
	async pull(controller) {
		for (;;) {
			const { value, done } = await super.read();
			if (done) { controller.close(); return }
			if (value.byteLength < 1) continue;

			// We reuse the msg buffer for our response (if we're going to respond)
			const msg = new Stun(value.buffer, value.byteOffset, value.byteLength);
			const first_byte = msg.getUint8(0);

			// Pass DTLS packets up the stack
			if (20 < first_byte && first_byte < 64) {
				controller.enqueue(value);
				return;
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
					if (!await msg.verify(short_key)) {
						msg.length = 0;
						msg.class = Class.error; msg.errcode = 401;
					}
					else if (msg.controlled) {
						msg.length = 0;
						msg.class = Class.error; msg.errcode = 487;
						await msg.sign(short_key);
					}
					else {
						msg.length = 0;
						msg.class = Class.success;
						msg.xmapped = this.inner.remoteAddr;
						await msg.sign(short_key);
					}
					msg.fingerprint = true;
					await this.write(msg.frame);
				}
				// Send the msg as a datachannel message to the dst
				else {
					// TODO: Remove this broadcasting and replace it with a datachannel message to the dst that src is trying to connect to them
					for (const turn of allocations.values()) {
						if (turn == this.inner) continue;
						await turn.write(value, { xpeer: this.inner.remoteAddr });
					}
				}
			} 
		}
	}
}
