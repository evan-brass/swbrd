import { Wire } from './wire.js';
import { decoder_lossy, encoder } from "./util.js";
import { crc32 } from "./crc32.js";
import { Ip4, Ip6, parse_ipaddr } from "./ipaddr.js";

export const MAGIC_COOKIE = 0x2112A442;

export const Class = {
	Req: 0b00,
	Ind: 0b01,
	Suc: 0b10,
	Err: 0b11,
};
export const Method = {
	Binding: 0x001,
	Allocate: 0x003,
	Refresh: 0x004,
	Send: 0x006,
	Data: 0x007,
	CreatePermission: 0x008,
	ChannelBind: 0x009,
};
export const AttrType = {
	Username: 0x006,
	Integrity: 0x008,
	Error: 0x0009,
	Lifetime: 0x000D,
	Peer: 0x0012,
	Data: 0x0013,
	Realm: 0x0014,
	Nonce: 0x0015,
	Relayed: 0x0016,
	Integrity256: 0x001C,
	Mapped: 0x0020,
	Priority: 0x0024,
	Fingerprint: 0x8028,
	IceControlled: 0x8029,
	IceControlling: 0x802A,
};
function integrity_info(cryptoKey) {
	if (cryptoKey?.algorithm?.hash?.name == 'SHA-1') {
		return {type: AttrType.Integrity, length: 20};
	}
	if (cryptoKey?.algorithm?.hash?.name == 'SHA-256') {
		return {type: AttrType.Integrity256, length: 32};
	}
	throw new Error("Unknown key");
}

export class Stun extends Wire {
	get byteLength() {
		return Stun.minByteLength + this.length;
	}
	#set_type(cls, method) {
		this.type = (method & 0x1F80) << 2 | (method & 0x0070) << 1
			| (method & 0x000F) | (cls & 0x0002) << 7
			| (cls & 0x0001) << 4;
	}
	get class() {
		return ((this.type & 0x0100) >> 7) | ((this.type & 0x0010) >> 4);
	}
	set class(val) {
		this.#set_type(val, this.method);
	}
	get method() {
		return (this.type & 0x3E00) >> 2 | (this.type & 0x00E0) >> 1
			| (this.type & 0x000F);
	}
	set method(val) {
		this.#set_type(this.class, val);
	}
	*[Symbol.iterator]() {
		if (super.byteLength < this.byteLength) return;
		for (let offset = 0; offset < this.length;) {
			const ret = new Attr(this.buffer, { parent: this, byteOffset: this.byteOffset + Stun.minByteLength + offset });
			offset += ret.byteLength;
			if (offset > this.length) return;
			yield ret;
		}
	}
	append(values = null, constr = Attr) {
		const ret = new constr(this, { parent: this, byteOffset: this.byteOffset + this.byteLength, ...values });
		this.length += ret.byteLength;
		return ret;
	}
	async verify(cryptoKey) {
		const {type: attr_type} = integrity_info(cryptoKey);
		const attr = this[Symbol.iterator]().find(a => a.type == attr_type);
		if (!attr) return false;
		// Update the length to immediately follow the integrity attribute:
		this.length = (-Stun.minByteLength + attr.byteOffset - this.byteOffset + attr.byteLength);
		return await crypto.subtle.verify('HMAC', cryptoKey, attr.value, attr.prefix);
	}
	async sign(cryptoKey) {
		const attr = this.append(integrity_info(cryptoKey));
		attr.value = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, attr.prefix));
	}
	fingerprint() {
		const attr = this.append({type: AttrType.Fingerprint, length: 4});
		attr.setUint32(Attr.minByteLength, crc32(attr.prefix) ^ 0x5354554e);
	}
}
Stun.field('type', 'u16');
Stun.field('length', 'u16');
Stun.field('cookie', 'u32');
Stun.field('txid', '[12]');

export class Attr extends Wire {
	get comprehension_required() {
		return this.type < 0x8000;
	}
	get prefix() {
		return new Uint8Array(this.buffer, this.parent.byteOffset, this.byteOffset - this.parent.byteOffset);
	}
	get byteLength() {
		const padding = (4 - this.length % 4) % 4;
		return Attr.minByteLength + this.length + padding;
	}
}
Attr.field('type', 'u16');
Attr.field('length', 'u16');
Attr.field('value', '[]');

export class Addr extends Attr {
	get port() {
		return this.getUint16(6) ^ this.parent.getUint16(4);
	}
	set port(val) {
		this.setUint16(6, val ^ this.parent.getUint16(4));
	}
	get ip() {
		if (this.family == 0x01 && this.length == 8) {
			const vals = Array.from({ length: 4 }, (_, i) => this.getUint8(8 + i) ^ this.parent.getUint8(4 + i));
			return new Ip4(...vals);
		}
		else if (this.family == 0x02 && this.length == 20) {
			const vals = Array.from({length: 8}, (_, i) => this.getUint16(8 + 2*i) ^ this.parent.getUint16(4 + 2 * i));
			return new Ip6(...vals);
		}
		return null;
	}
	set ip(val) {
		if (typeof val == 'string') val = parse_ipaddr(val);
		if (val instanceof Ip4) {
			this.length = 8;
			this.family = 0x01;
			val.forEach((octet, i) => {
				this.setUint8(8 + i, octet ^ this.parent.getUint8(4 + i))
			});
		}
		else if (val instanceof Ip6) {
			this.length = 20;
			this.family = 0x02;
			val.forEach((u16, i) => {
				this.setUint16(8 + 2*i, u16 ^ this.parent.getUint16(4 + 2*i));
			});
		}
		else { throw new Error(); }
		this.setUint8(4, 0); // Clear the padding byte
	}
}
Addr.minByteLength += 1; // Padding
Addr.field('family', 'u8');
Addr.minByteLength += 2; // xport
Addr.minByteLength += 4; // Min 4 bytes for ipv4
