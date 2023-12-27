// import { parse_ipaddr } from "./ipaddr.mjs";
import { Turn } from "./turn.js";

class TurnListener {
	#inner;
	#waiters = [];
	constructor(inner) {
		this.#inner = inner;
	}
	get remoteAddr() { return this.#inner.remoteAddr; }
	async send(data) {
		// Wait until we can aquire a lock on the writable stream
		while (this.#inner.writable.locked) await new Promise(res => this.#waiters.push(res));
		const writer = this.#inner.writable.getWriter();
		try {
			await writer.ready;
			await writer.write(data);
			writer.releaseLock();
		} finally {
			const waiter = this.#waiters.shift();
			if (waiter) waiter();
		}
	}
	// Technically, this is yielding TURN message, but what I actually want it to yield are packets to relay and for it to handle all the TURN internally
	async *[Symbol.asyncIterator]() {
		const res = new Turn();
		for await(const msg of Turn.parse(this.#inner.readable)) {
			if (!msg.is_stun) continue;

			// Prepare the response
			res.length = 0;
			res.method = msg.method;
			res.class = 0b10;
			res.txid.set(msg.txid);

			// STUN Indication
			if (msg.class == 0b01) {
				// Send indication
				if (msg.method == 0x006) {
					yield [msg.xpeer, msg.data];
				} else {/* */}
			}
			// STUN Responses (Success or Error)
			else if (msg.class == 0b10 || msg.class == 0b11) {/* */}
			// TURN Allocate
			else if (msg.method == 0x003) {
				res.xmapped = this.remoteAddr;
				res.xrelay = this.remoteAddr;
				res.lifetime = 3600;
				await this.send(res.framed_packet);
			}
			// TURN Permission
			else if (msg.method == 0x008) {
				await this.send(res.framed_packet);
			}
			// Unknown message
			else {/* */}
		}
	}
}

const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const hostname = '::';

const listeners = new Set();
// for await (const stream of Deno.listen({ hostname, port: 3478, cert, key })) {
for await (const stream of Deno.listenTls({ hostname, port: 5349, cert, key })) {
	// Spawn a task for the sender:
	(async () => {
		const listener = new TurnListener(stream);
		try {
			listeners.add(listener);
			const data = new Turn();
			data.class = 0x01;
			data.method = 0x007;
			for await (const [dest, packet] of listener) {
				// Broadcast the message to every association at this TURN server
				crypto.getRandomValues(data.txid);
				data.length = 0;
				data.xpeer = stream.remoteAddr;
				data.data = packet;
				for (const l of listeners) {
					if (l == listener) continue;
					if (dest.hostname == '255.255.255.255' || l.remoteAddr.hostname.endsWith(dest.hostname)) {
						await l.send(data.framed_packet);
					} else {
						console.log('no send', dest.hostname, l.remoteAddr.hostname);
					}
				}
			}
		} finally {
			listeners.delete(listener);
		}
	})();
}
