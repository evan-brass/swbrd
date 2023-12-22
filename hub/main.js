// import { parse_ipaddr } from "./ipaddr.mjs";
import { Turn } from "./turn.js";

// const MAGIC = 0x2112A442;

// const m = method => (
// 	((method << 0) & 0b00_00000_0_000_0_1111) |
// 	((method << 1) & 0b00_00000_0_111_0_0000) |
// 	((method << 2) & 0b00_11111_0_000_0_0000)
// );
// export const req = method => m(method) | 0b00_00000_0_000_0_0000;
// export const ind = method => m(method) | 0b00_00000_0_000_1_0000;
// export const res = method => m(method) | 0b00_00000_1_000_0_0000;
// export const err = method => m(method) | 0b00_00000_1_000_1_0000;

// const INVALID = Symbol('Attribute parsing revealed the value to be invalid');
// function encode_text() {

// }
// function decode_text() {

// }


// class TurnListener {
// 	#inner;
// 	#waiters = [];
// 	constructor(inner) {
// 		this.#inner = inner;
// 	}
// 	async #send(data) {
// 		// Wait until we can aquire a lock on the writable stream
// 		while (this.#inner.writable.locked) await new Promise(res => this.#waiters.push(res));
// 		const writer = this.#inner.writable.getWriter();
// 		try {
// 			await writer.writer(data);
// 		} finally {
// 			writer.releaseLock();
// 			const waiter = this.#waiters.shift();
// 			if (waiter) waiter();
// 		}
// 	}
// 	async send(src, packet) {
// 		// TODO: wrap the packet in a TURN message and then #send it
// 	}
// 	// Technically, this is yielding TURN message, but what I actually want it to yield are packets to relay and for it to handle all the TURN internally
// 	async *[Symbol.asyncIterator](maxByteLength = 4096) {
// 		const reader = this.#inner.readable.getReader({mode: 'byob'});
// 		let buffer = new ArrayBuffer(100, {maxByteLength});
// 		let available = 0;
// 		try {
// 			while (1) {
// 				const {value, done} = await reader.read(new Uint8Array(buffer, available));
// 				if (value) {
// 					buffer = value.buffer;
// 					available += value.byteLength;
// 				}
// 				if (available < 4 && !done) continue;

// 				// Fields common for both types of TURN messages
// 				const view = new DataView(buffer);
// 				const typ = view.getUint16(0);
// 				const length = view.getUint16(2);

// 				// Calculate how big the message is
// 				let needed; if (typ < 0x4000) {
// 					needed = 20 + length;
// 				} else if (typ < 0x7ffe) {
// 					needed = 4 + length;
// 				} else { break; /* Not a TURN message */ }
// 				// Pad out needed
// 				while (needed % 4) needed += 1;

// 				// Resize the buffer if we need more space
// 				if (needed > buffer.byteLength) buffer.resize(needed);

// 				// If we have what we need then parse a message
// 				if (available >= needed) {
// 					// STUN
// 					if (typ < 0x4000) {
// 						if (length % 4) break; // STUN messages must be 4 byte aligned
// 						if (view.getUint32(4) != MAGIC) break; // STUN magic value
// 						const txid = new Uint8Array(buffer, 8, 12);
// 						const attrs = new Map();
						
// 						for (let i = 20; i < needed;) {
// 							// Attribute header
// 							const attr_type = view.getUint16(i);
// 							const attr_len = view.getUint16(i + 2);
// 							i += 4;
// 							if (i + attr_len > needed) break; // STUN Attr is longer than the packet

// 							// Decode / 
// 							const known = known_attributes.get(attr_type);
// 							const data_view = new DataView(buffer, i, attr_len);
// 							const value = known ? known.decode(data_view) : data_view;
// 							if (value == INVALID) break;
// 							attrs.set(known?.name ?? attr_type, value);

// 							i += attr_len;
// 							while (i % 4) i += 1;
// 						}

// 						yield { type: typ, txid, attrs };
// 					}
// 					// Channel Data
// 					else if (typ < 0x7ffe) {
// 						// TODO: Channel Data messages
// 					}

// 					// Copy an unused data to the beginning of the buffer
// 					const extra = available - needed;
// 					if (extra) {
// 						new Uint8Array(buffer).set(new Uint8Array(buffer, needed, extra));
// 					}
// 					available = extra;
// 				}
// 				if (done) break;
// 			}
// 		} finally {
// 			reader.releaseLock();
// 		}
// 	}
// }

const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const hostname = '::';

for await (const stream of Deno.listenTls({ hostname, port: 5349, cert, key })) {
	// const listener = new TurnListener(stream);
	// Spawn a task for the sender:
	(async () => {
		for await (const msg of Turn.parse(stream.readable)) {
			console.log(msg.type, msg.length, msg.attrs);
		}
	})();
}
