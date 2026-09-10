// The extension side of the switchboard channel protocol.
//
// The daemon dials one Unix stream socket per datachannel, so a listener here
// accepts one connection per channel and the connection's lifetime is the
// channel's.  The first frame is always a control `open` naming the peer.
//
//   const listener = Deno.listen({ path: '/run/swbrd/ext/chat.sock', transport: 'unix' });
//   for await (const conn of listener) serve(conn);
//
//   async function serve(conn) {
//     const chan = await Channel.accept(conn);
//     console.log('peer', chan.open.id, 'wants', chan.open.protocol);
//     for await (const { data, ppid } of chan) {
//       await chan.send(data, { ppid });
//     }
//   }
//
// Backpressure needs no cooperation: the daemon writes into this socket and
// stops reading the peer when it fills, so simply reading slowly is enough.

export const HEADER_LEN = 12;
export const MAX_PAYLOAD = 64 * 1024;

export const EOR = 0x0001;
export const UNORDERED = 0x0002;
export const ABANDON = 0x0004;
export const CONTROL = 0x8000;

// WebRTC payload protocol ids (RFC 8831).
export const PPID_STRING = 51;
export const PPID_BINARY = 53;
export const PPID_STRING_EMPTY = 56;
export const PPID_BINARY_EMPTY = 57;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encode(ppid, flags, payload) {
	const frame = new Uint8Array(HEADER_LEN + payload.length);
	const view = new DataView(frame.buffer);
	view.setUint32(0, payload.length);
	view.setUint32(4, ppid);
	view.setUint16(8, flags);
	view.setUint16(10, 0);
	frame.set(payload, HEADER_LEN);
	return frame;
}

// Returns null when `buf` does not yet hold a whole frame.
export function decode(buf) {
	if (buf.length < HEADER_LEN) return null;
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const length = view.getUint32(0);
	if (length > MAX_PAYLOAD) {
		throw new Error(
			`frame claims ${length} bytes, over the ${MAX_PAYLOAD} limit`,
		);
	}
	if (buf.length < HEADER_LEN + length) return null;
	return {
		ppid: view.getUint32(4),
		flags: view.getUint16(8),
		payload: buf.subarray(HEADER_LEN, HEADER_LEN + length),
		wireLength: HEADER_LEN + length,
	};
}

export class Channel {
	#conn;
	#buf = new Uint8Array(0);
	#eof = false;

	/** The control `open` the daemon sent: who the peer is and what they asked for. */
	open;

	constructor(conn, open) {
		this.#conn = conn;
		this.open = open;
	}

	/** Read the opening control frame, then hand back a ready channel. */
	static async accept(conn) {
		const chan = new Channel(conn, null);
		const first = await chan.#frame();
		if (!first || !(first.flags & CONTROL)) {
			conn.close();
			throw new Error('channel did not begin with a control frame');
		}
		const control = JSON.parse(decoder.decode(first.payload));
		if (control.op !== 'open') {
			conn.close();
			throw new Error(`expected an open, got ${control.op}`);
		}
		chan.open = control;
		return chan;
	}

	async #fill() {
		const chunk = new Uint8Array(64 * 1024);
		const n = await this.#conn.read(chunk);
		if (n === null) {
			this.#eof = true;
			return false;
		}
		const grown = new Uint8Array(this.#buf.length + n);
		grown.set(this.#buf);
		grown.set(chunk.subarray(0, n), this.#buf.length);
		this.#buf = grown;
		return true;
	}

	async #frame() {
		for (;;) {
			const frame = decode(this.#buf);
			if (frame) {
				this.#buf = this.#buf.subarray(frame.wireLength);
				return frame;
			}
			if (this.#eof) return null;
			if (!await this.#fill()) return null;
		}
	}

	/** Messages from the peer. Control frames are handled here, not yielded. */
	async *[Symbol.asyncIterator]() {
		for (;;) {
			const frame = await this.#frame();
			if (!frame) return;
			if (frame.flags & CONTROL) continue;
			const binary = frame.ppid === PPID_BINARY ||
				frame.ppid === PPID_BINARY_EMPTY;
			yield {
				ppid: frame.ppid,
				flags: frame.flags,
				data: frame.payload,
				text: binary ? null : decoder.decode(frame.payload),
			};
		}
	}

	/**
	 * Send one message to the peer.  A string goes as a WebRTC string message
	 * and bytes as binary, matching what the browser will see.
	 */
	async send(body, { ppid, unordered = false } = {}) {
		const payload = typeof body === 'string' ? encoder.encode(body) : body;
		const chosen = ppid ??
			(typeof body === 'string'
				? (payload.length ? PPID_STRING : PPID_STRING_EMPTY)
				: (payload.length ? PPID_BINARY : PPID_BINARY_EMPTY));
		let flags = EOR;
		if (unordered) flags |= UNORDERED;
		await writeAll(this.#conn, encode(chosen, flags, payload));
	}

	/** Refuse the channel before doing anything with it. */
	async reject(reason) {
		const body = encoder.encode(
			JSON.stringify({ op: 'reject', reason: reason ?? null }),
		);
		await writeAll(this.#conn, encode(0, CONTROL | EOR, body));
		this.#conn.close();
	}

	/** Stop sending; the peer sees our half of the stream reset. */
	async closeWrite() {
		await this.#conn.closeWrite();
	}

	close() {
		try {
			this.#conn.close();
		} catch {
			// Already closed by the daemon.
		}
	}
}

async function writeAll(conn, bytes) {
	let off = 0;
	while (off < bytes.length) {
		off += await conn.write(bytes.subarray(off));
	}
}
