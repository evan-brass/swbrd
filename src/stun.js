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
	get parent_length() {
		return this.byteOffset - this.#parent.byteOffset - 20 + this.length;
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
	get frame() {
		return new Uint8Array(this.buffer, this.byteOffset, this.needed);
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

				// Ignore certain attributes
				if (this.#attrs.has(attr_typ)) continue; // Ignore duplicated attributes
				if (this.#attrs.has(0x0008 /* Integrity */) && ![
					0x001C, // Integrity 256
					0x8028, // Fingerprint
				].includes(attr_typ)) continue; // Ignore most attrs after the integrity attribute
				if (this.#attrs.has(0x001C /* Integrity 256 */) && ![
					0x8028, // Fingerprint
				].includes(attr_typ)) continue; // Ignore most attrs after the integrity 256 attribute

				this.#attrs.set(attr_typ, value);

				if (attr_typ == 0x8028 /* Fingerprint */) break; // Ignore any attributes after the fingerprint
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
	get_addr(type, { transport = 'udp', xor = true, ipv4_mapped = true } = {}) {
		const attr = this.attrs.get(type);
		if (!attr) return;
		if (attr.length < 4) return;
		const family = attr.getUint8(1);
		const port = attr.getUint16(2) ^ (xor ? this.getUint16(4) : 0);
		let hostname;
		// IPv4
		if (family == 0x01) {
			if (attr.length != 8) return;
			hostname = (ipv4_mapped ? '::ffff:' : '') + Array.from({length: 4}, (_, i) => attr.getUint8(4 + i) ^ (xor ? this.getUint8(4 + i) : 0))
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
	get channel() {
		const attr = this.attrs.get(0x000C);
		if (attr?.length != 4) return undefined;
		return attr.getUint16(0);
	}
	set channel(value) {
		const attr = this.new_attr();
		attr.type = 0x000C;
		attr.length = 4;
		attr.setUint16(0, value);
		attr.setUint16(2, 0); // Future use padding
	}
	get lifetime() {
		const attr = this.attrs.get(0x000D);
		if (attr?.length != 4) return undefined;
		return attr.getUint32(0);
	}
	set lifetime(value) {
		const attr = this.new_attr();
		attr.type = 0x000D;
		attr.length = 4;
		attr.setUint32(0, value);
	}
	get xpeer() { return this.get_addr(0x0012); }
	set xpeer(value) { this.set_addr(0x0012, value); }
	get data() {
		const attr = this.attrs.get(0x0013);
		if (!attr) return undefined;
		return attr.bytes;
	}
	set data(value) {
		const attr = this.new_attr(0x0013);
		attr.type = 0x0013;
		attr.length = value.byteLength;
		attr.bytes.set(new Uint8Array(value.buffer ?? value, value.byteOffset, value.byteLength));
	}
	get realm() { return this.get_txt(0x0014); }
	set realm(value) { this.set_txt(0x0014, value); }
	get nonce() { return this.get_txt(0x0015); }
	set nonce(value) { this.set_txt(0x0015, value); }
	get xrelayed() { return this.get_addr(0x0016); }
	set xrelayed(value) { this.set_addr(0x0016, value); }
	get xmapped() { return this.get_addr(0x0020); }
	set xmapped(value) { this.set_addr(0x0020, value); }
	get priority() {
		const attr = this.attrs.get(0x0024);
		if (attr?.length != 4) return undefined;
		return attr.getUint32(0);
	}
	set priority(value) {
		const attr = this.new_attr();
		attr.type = 0x0024;
		attr.length = 4;
		attr.setUint32(0, value);
	}
	get software() { return this.get_txt(0x8022); }
	set software(value) { this.set_txt(0x8022, value); }
	get fingerprint() {
		const attr = this.attrs.get(0x8028);
		if (attr?.length != 4) return false;

		const save = this.getUint16(2);
		this.setUint16(2, attr.parent_length);
		
		const actual = attr.getInt32(0);
		const expected = crc32(attr.prefix) ^ 0x5354554e;

		this.setUint16(2, save);

		return actual === expected;
	}
	set fingerprint(_) {
		const attr = this.new_attr();
		attr.type = 0x8028;
		attr.length = 4;
		attr.setInt32(0, crc32(attr.prefix) ^ 0x5354554e);
	}

	async verify(key) {
		let type;
		if (key.algorithm.hash.name == 'SHA-1') {
			type = 0x0008;
		}
		else if (key.algorithm.hash.name == 'SHA-256') {
			type = 0x001C;
		}
		else { return false; }

		const attr = this.attrs.get(type);
		if (!attr) return false;

		const save = this.getUint16(2);
		this.setUint16(2, attr.parent_length);

		const ret = await crypto.subtle.verify('HMAC', key, attr.bytes, attr.prefix);

		this.setUint16(2, save);

		return ret;
	}
	async sign(key) {
		const attr = this.new_attr();
		if (key.algorithm.hash.name == 'SHA-1') {
			attr.type = 0x0008;
			attr.length = 20;
		}
		else if (key.algorithm.hash.name == 'SHA-256') {
			attr.type = 0x001C;
			attr.length = 32;
		}
		else { throw new Error('Unknwon integrity key type'); }

		const sig = await crypto.subtle.sign('HMAC', key, attr.prefix);
		attr.bytes.set(new Uint8Array(sig));
	}
}
