import { crc32 } from "./crc32.js";
import { parse_ipaddr } from "./ipaddr.js";

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export const Magic = 0x2112A442;

export const Class = {
	request: 0b00,
	indication: 0b01,
	success: 0b10,
	error: 0b11
};
export const Method = {
	binding: 0x001,
	
	allocate: 0x003,
	refresh: 0x004,
	send: 0x006,
	data: 0x007,
	createPermission: 0x008,
	channelBind: 0x009
};

export class Attr extends DataView {
	#parent;
	constructor(parent, i) {
		super(parent.buffer, parent.byteOffset + i + 4);
		this.#parent = parent;
	}
	get #header() {
		return new DataView(this.buffer, this.byteOffset - 4, 4);
	}
	get type() {
		return this.#header.getUint16(0);
	}
	set type(value) {
		this.#header.setUint16(0, value);
	}
	get length() {
		return this.#header.getUint16(2);
	}
	set length(value) {
		this.#parent.length = (this.byteOffset - this.#parent.byteOffset - 20 + value);
		this.#header.setUint16(2, value);
	}
	get prefix() {
		return new Uint8Array(this.buffer, this.#parent.byteOffset, this.byteOffset - this.#parent.byteOffset - 4);
	}
	get bytes() {
		return new Uint8Array(this.buffer, this.byteOffset, this.length);
	}
}

export class Stun extends DataView {
	// Getters
	get type() {
		return this.getUint16(0);
	}
	set type(value) {
		this.setUint16(0, value);
	}
	#set_type(cls, method) {
		this.type = (
			(method & 0x1F80) << 2 |
			(cls & 0b10) << 7 |
			(method & 0x0070) << 1 |
			(cls & 0b01) << 4 |
			(method & 0x000F)
		);
	}
	get class() {
		return (this.type & 0x0100) >> 7 | (this.type & 0x0010) >> 4;
	}
	set class(cls) {
		this.#set_type(cls, this.method);
	}
	get method() {
		return (this.type & 0x3E00) >> 2 | (this.type & 0x00E0) >> 1 | (this.type & 0x000F);
	}
	set method(method) {
		this.#set_type(this.class, method);
	}
	get length() {
		return this.getUint16(2);
	}
	set length(len) {
		while (len % 4 != 0) len += 1;
		const packet_len = 20 + len;
		if (packet_len > this.byteLength) this.buffer.resize(this.byteOffset + packet_len);
		this.setUint16(2, len);
	}
	get needed() {
		if (this.byteLength < 4) return 4;
		if (this.type < 0x4000) return 20 + this.length;
		return Infinity;
	}
	get magic() {
		return this.getUint32(4) === Magic;
	}
	set magic(_) {
		this.setUint32(4, Magic);
	}
	get txid() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, 16);
	}
	#attrs;
	get attrs() {
		if (!this.#attrs) {
			this.#attrs = new Map();

			let end = Math.min(20 + this.length, this.byteLength);
			while (end % 4 != 0) end -= 1;

			for (let i = 20; i < end;) {
				const attr_typ = this.getUint16(i);
				const attr_len = this.getUint16(i + 2);
				if (attr_len > end - i) break;
				const value = new Attr(this, i);
				i += 4 + attr_len;
				while (i % 4 != 0) i += 1;

				this.#attrs.set(attr_typ, value);
			}
		}
		return this.#attrs;
	}
	new_attr() {
		const i = 20 + this.length;
		this.length += 4;
		return new Attr(this, i);
	}
	get_txt(type) {
		const attr = this.attrs.get(type);
		if (!attr) return undefined;
		return decoder.decode(attr.bytes);
	}
	set_txt(type, value) {
		const buff = encoder.encode(value);
		const attr = this.new_attr();
		attr.type = type;
		attr.length = buff.byteLength;
		attr.bytes.set(buff);
	}
	get_addr(type, { transport = 'udp', xor = true } = {}) {
		const attr = this.attrs.get(type);
		if (!attr) return;
		if (attr.length < 4) return;
		const family = attr.getUint8(1);
		const port = attr.getUint16(2) ^ (xor ? this.getUint16(4) : 0);
		let hostname;
		// IPv4
		if (family == 0x01) {
			if (attr.length != 8) return;
			hostname = Array.from({length: 4}, (_, i) => attr.getUint8(4 + i) ^ (xor ? this.getUint8(4 + i) : 0))
				.join('.');
		}
		// IPv6
		else if (family == 0x02) {
			if (attr.length != 20) return;
			hostname = Array.from({length: 8}, (_, i) => attr.getUint16(4 + 2 * i) ^ (xor ? this.getUint16(4 + 2 * i) : 0))
				.map(n => n.toString(16))
				.join(':');
		}
		// Unknown
		else { return }

		return { hostname, port, transport };
	}
	set_addr(type, {hostname, port}, { xor = true} = {}) {
		const ip = parse_ipaddr(hostname).map((v, i, arr) => {
			const xv = xor ? (arr instanceof Uint8Array ? this.getUint8(4 + i) : this.getUint16(4 + 2 * i)) : 0;
			return v ^ xv
		});
		const attr = this.new_attr();
		attr.type = type;
		const family = ip instanceof Uint8Array ? 0x01 : 0x02;
		attr.length = ip instanceof Uint8Array ? 8 : 20;
		attr.setUint8(0, 0);
		attr.setUint8(1, family);
		attr.setUint16(2, port ^ (xor ? this.getUint16(4) : 0));
		ip.forEach((v, i, arr) => {
			if (arr instanceof Uint8Array) {
				attr.setUint8(4 + i, v);
			} else {
				attr.setUint16(4 + 2 * i, v);
			}
		});
	}
	get mapped() { return this.get_addr(0x0001, {xor: false}); }
	set mapped(value) { this.set_addr(0x0001, value, {xor: false}); }
	get username() { return this.get_txt(0x0006); }
	set username(value) { this.set_txt(0x0006, value); }
	get errcode() {
		const attr = this.attrs.get(0x0009);
		if (attr?.length != 4) return undefined;
		return attr.getUint8(2) * 100 + attr.getUint8(3);
	}
	set errcode(value) {
		const attr = this.new_attr();
		attr.type = 0x0009;
		attr.length = 4;
		attr.setUint16(0, 0);
		attr.setUint8(2, Math.trunc(value / 100));
		attr.setUint8(3, value % 100);
	}
	get realm() { return this.get_txt(0x0014); }
	set realm(value) { this.set_txt(0x0014, value); }
	get nonce() { return this.get_txt(0x0015); }
	set nonce(value) { this.set_txt(0x0015, value); }
	get xpeer() { return this.get_addr(0x0012); }
	set xpeer(value) { this.set_addr(0x0012, value); }
	get xmapped() { return this.get_addr(0x0020); }
	set xmapped(value) { this.set_addr(0x0020, value); }
	get software() { return this.get_txt(0x8022); }
	set software(value) { this.set_txt(0x8022, value); }
	get fingerprint() {
		const attr = this.attrs.get(0x8028);
		if (attr.length != 4) return false;
		
		const actual = attr.getInt32(0);
		const expected = crc32(attr.prefix) ^ 0x5354554e;

		return actual === expected;
	}
	set fingerprint(_) {
		const a = this.new_attr();
		a.type = 0x8028;
		a.length = 4;
		a.setInt32(crc32(a.prefix) ^ 0x5354554e);
	}
}
