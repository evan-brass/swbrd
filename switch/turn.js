import { Stun } from './stun.js';

export class ChannelData extends DataView {
	get channel() {
		return this.getUint16(0);
	}
	set channel(value) {
		this.setUint16(0, value);
	}
	get length() {
		return this.getUint16(2);
	}
	set length(len) {
		let packet_len = 4 + len;
		while (packet_len % 4 != 0) packet_len += 1;
		if (packet_len > this.byteLength) this.buffer.resize(this.byteOffset + packet_len);
		this.setUint16(2, len);
	}
	get needed() {
		if (this.byteLength < 4) return 4;
		if (this.channel < 0x4000) return Infinity;
		if (this.channel < 0x8000) {
			let ret = 4 + this.length;
			while (ret % 4 != 0) ret += 1;
			return ret;
		}
		return Infinity;
	}
	get frame() {
		return new Uint8Array(this.buffer, this.byteOffset, this.needed);
	}
	get data() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, this.length);
	}
}

export function parse(data) {
	const stun = new Stun(data.buffer, data.byteOffset, data.byteLength);
	const channel = new ChannelData(data.buffer, data.byteOffset, data.byteLength);
	const needed = Math.min(stun.needed, channel.needed);
	if (data.byteLength < needed) {
		return needed;
	}
	else if (stun.needed < Infinity) {
		return stun;
	}
	else if (channel.needed < Infinity) {
		return channel;
	}
}

export async function* parse_readable(readable, {recv}) {
	const reader = readable.getReader({mode: 'byob'});
	let available = 0;
	while (true) {
		try {
			const {value, done} = await reader.read(new Uint8Array(recv, available));
			if (done) break;
			available += value.byteLength; recv = value.buffer;
		} catch { break; }

		const res = parse(new Uint8Array(recv, 0, available));
		if (typeof res == 'number') {
			// Try to resize recv to accomodate the required size:
			if (res > recv.maxByteLength) break;
			recv.resize(res);
			continue;
		}

		yield res;

		// Shift unused data to the front of the buffer
		available -= res.needed;
		new Uint8Array(recv, 0).set(new Uint8Array(recv, res.needed));
	}
}
