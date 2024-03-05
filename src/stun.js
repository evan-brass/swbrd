import { crc32 } from "./crc32.js";

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

export const known = new Map();
known.set(0x0006, function username(buffer) {
	return decoder.decode(buffer);
});

export class Attr extends DataView {
	#parent;
	constructor(parent, i) {
		super(parent.buffer, parent.byteOffset + i);
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
				i += 4;
				const value = new Attr(this, i, attr_len);
				i += attr_len;
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
	get fingerprint() {
		const attr = this.attrs.get(0x8028);
		if (!attr) return false;
		
		const actual = value.getInt32(0);
		const expected = crc32(value.prefix) ^ 0x5354554e;

		return actual === expected;
	}
	set fingerprint(_) {
		const a = this.new_attr();
		a.type = 0x8028;
		a.length = 4;
		a.setInt32(crc32(a.prefix) ^ 0x5354554e);
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

	get username() { return this.get_txt(0x0006); }
	set username(value) { this.set_txt(0x0006, value); }
	get realm() { return this.get_txt(0x0014); }
	set realm(value) { this.set_txt(0x0014, value); }
	get nonce() { return this.get_txt(0x0015); }
	set nonce(value) { this.set_txt(0x0015, value); }
}
