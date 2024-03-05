import { crc32 } from "./crc32.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
	#msg;
	constructor(msg, i, len) {
		super(msg.buffer, msg.byteOffset + i, len);
		this.#msg = msg;
	}
	get prefix() {
		return new Uint8Array(this.buffer, this.#msg.byteOffset, this.byteOffset - this.#msg.byteOffset - 4);
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
		this.setUint16(2, len);
	}
	get magic() {
		return this.getUint32(4);
	}
	set magic(magic) {
		this.setUint32(4, magic);
	}
	get txid() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, 16);
	}
	*[Symbol.iterator]() {
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

			// Modify the length as we go
			this.length = i - 20;

			yield { type: attr_typ, value };
		}
	}
	add_attr(type, len) {

	}
	get fingerprint() {
		for (const {type, value} of this) {
			if (type == 0x8028) {
				const actual = value.getInt32(0);
				const expected = crc32(value.prefix) ^ 0x5354554e;

				return actual === expected;
			}
		}
		return undefined;
	}
	set fingerprint(_) {
		const value = this.add_attr(0x8028, 4);
		
	}
}
