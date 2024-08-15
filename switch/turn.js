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
			return 4 + this.length;
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
