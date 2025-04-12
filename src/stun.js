import { Wire } from './wire.js';
import { decoder_lossy, encoder } from './util.js';
import { crc32 } from './crc32.js';
import { Ip4, Ip6, parse_ipaddr } from './ipaddr.js';

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
	ChannelNumber: 0x000C,
	Lifetime: 0x000D,
	Peer: 0x0012,
	Data: 0x0013,
	Realm: 0x0014,
	Nonce: 0x0015,
	Relayed: 0x0016,
	RequestedTransport: 0x0019,
	Integrity256: 0x001C,
	Mapped: 0x0020,
	Priority: 0x0024,
	UseCandidate: 0x0025,
	Fingerprint: 0x8028,
	IceControlled: 0x8029,
	IceControlling: 0x802A,
};
function integrity_info(cryptoKey) {
	if (cryptoKey?.algorithm?.hash?.name == 'SHA-1') {
		return { type: AttrType.Integrity, length: 20 };
	}
	if (cryptoKey?.algorithm?.hash?.name == 'SHA-256') {
		return { type: AttrType.Integrity256, length: 32 };
	}
	throw new Error('Unknown key');
}

export class Stun extends Wire {
	get byteLength() {
		return Stun.minByteLength + this.length;
	}
	#set_type(cls, method) {
		this.type = (method & 0x1F80) << 2 | (method & 0x0070) << 1 |
			(method & 0x000F) | (cls & 0x0002) << 7 |
			(cls & 0x0001) << 4;
	}
	get class() {
		return ((this.type & 0x0100) >> 7) | ((this.type & 0x0010) >> 4);
	}
	set class(val) {
		this.#set_type(val, this.method);
	}
	get method() {
		return (this.type & 0x3E00) >> 2 | (this.type & 0x00E0) >> 1 |
			(this.type & 0x000F);
	}
	set method(val) {
		this.#set_type(this.class, val);
	}
	*[Symbol.iterator]() {
		if (super.byteLength < this.byteLength) return;
		for (let offset = 0; offset < this.length;) {
			const ret = new Attr(this.buffer, {
				parent: this,
				byteOffset: this.byteOffset + Stun.minByteLength + offset,
			});
			offset += ret.byteLength;
			if (offset > this.length) return;
			yield ret;
		}
	}
	append(typ, kind, value) {
		const a = new Attr(this, { byteOffset: this.byteOffset + this.byteLength });
		a.type = typ;
		if (typeof kind == 'number') {
			a.length = kind;
			if (value) {
				a.value = value;
			}
		} else if (kind == 'text') {
			const encoded = encoder.encode(value);
			a.length = encoded.byteLength;
			a.value = encoded;
		} else if (kind == 'u32') {
			a.length = Uint32Array.BYTES_PER_ELEMENT;
			a.setUint32(Attr.minByteLength, value);
		} else if (kind == 'u64') {
			a.length = BigUint64Array.BYTES_PER_ELEMENT;
			a.setBigUint64(value);
		} else if (kind == 'addr' && typ != 0x0001) {
			const { ip = parse_ipaddr(value.hostname), port } = value;
			a.setUint8(Attr.minByteLength, 0);
			a.setUint16(Attr.minByteLength + 2, port ^ this.getUint16(4));
			if (ip instanceof Ip4) {
				a.length = 8;
				a.setUint8(Attr.minByteLength + 1, 0x01);
				for (let i = 0; i < ip.length; ++i) {
					a.setUint8(Attr.minByteLength + 4 + i, ip[i] ^ this.getUint8(4 + i));
				}
			} else if (ip instanceof Ip6) {
				a.length = 20;
				a.setUint8(Attr.minByteLength + 1, 0x02);
				for (let i = 0; i < ip.length; ++i) {
					a.setUint16(
						Attr.minByteLength + 4 + 2 * i,
						ip[i] ^ this.getUint16(4 + 2 * i),
					);
				}
			} else throw new Error('Unknown Address value');
		} else if (kind == undefined) {
			a.value = value;
		} else {
			throw new Error('Unknown Type');
		}

		this.length += a.byteLength;
		return a;
	}
	// NOTE: Calling .verify() truncates the packet to immediately following the integrity attribute if present.
	async verify(cryptoKey) {
		const { type: attr_type } = integrity_info(cryptoKey);
		const attr = this[Symbol.iterator]().find((a) => a.type == attr_type);
		if (!attr) return false;
		// Update the length to immediately follow the integrity attribute:
		this.length = -Stun.minByteLength + attr.byteOffset - this.byteOffset +
			attr.byteLength;
		const prefix = new Uint8Array(
			this.buffer,
			this.byteOffset,
			attr.byteOffset - this.byteOffset,
		);
		return await crypto.subtle.verify('HMAC', cryptoKey, attr.value, prefix);
	}
	async sign(cryptoKey) {
		const { type, length } = integrity_info(cryptoKey);
		const attr = this.append(type, length);
		const prefix = new Uint8Array(
			this.buffer,
			this.byteOffset,
			attr.byteOffset - this.byteOffset,
		);
		attr.value = new Uint8Array(
			await crypto.subtle.sign('HMAC', cryptoKey, prefix),
		);
	}
	fingerprint() {
		const attr = this.append(AttrType.Fingerprint, 4);
		const prefix = new Uint8Array(
			this.buffer,
			this.byteOffset,
			attr.byteOffset - this.byteOffset,
		);
		attr.setUint32(Attr.minByteLength, crc32(prefix) ^ 0x5354554e);
	}
	parse(...layers) {
		const values = layers.map((l) => new Array(l.length));
		const unknown = [];
		const unknown_opt = [];

		let layer = 0;

		next_attribute:
		for (const a of this) {
			for (let l = layer; l < layers.length; ++l) {
				for (let i = 0; i < layers[l].length; ++i) {
					if (values[l][i] !== undefined) continue;
					const [typ, kind] = layers[l][i];
					if (a.type != typ) continue;
					layer = l;

					let value;
					if (typeof kind == 'number') {
						if (a.length != kind) value = null;
						else value = a.value;
					} else if (kind == 'text') {
						value = decoder_lossy.decode(a.value);
					} else if (kind == 'u32') {
						if (a.length != Uint32Array.BYTES_PER_ELEMENT) value = null;
						else value = a.getUint32(Attr.minByteLength);
					} else if (kind == 'u64') {
						if (a.length != BigUint64Array.BYTES_PER_ELEMENT) value = null;
						else value = a.getBigUint64(Attr.minByteLength);
					} else if (kind == 'fucky_u8') {
						if (a.length != 4) value = null;
						else value = a.getUint8(Attr.minByteLength);
					} else if (kind == 'bool') {
						if (a.length != 0) value = null;
						else value = true;
					} // XOR'd Addresses
					else if (kind == 'addr' && typ != 0x0001) {
						if (a.length < 8) value = null;
						const port = a.getUint16(Attr.minByteLength + 2) ^
							this.getUint16(4);
						if (a.getUint8(Attr.minByteLength + 1) == 0x01 && a.length == 8) {
							const ip = new Ip4(
								a.getUint8(Attr.minByteLength + 4) ^ this.getUint8(4),
								a.getUint8(Attr.minByteLength + 5) ^ this.getUint8(5),
								a.getUint8(Attr.minByteLength + 6) ^ this.getUint8(6),
								a.getUint8(Attr.minByteLength + 7) ^ this.getUint8(7),
							);
							value = { ip, port };
						} else if (
							a.getUint8(Attr.minByteLength + 1) == 0x02 && a.length == 20
						) {
							const ip = new Ip6(
								a.getUint16(Attr.minByteLength + 4) ^ this.getUint16(4),
								a.getUint16(Attr.minByteLength + 6) ^ this.getUint16(6),
								a.getUint16(Attr.minByteLength + 8) ^ this.getUint16(8),
								a.getUint16(Attr.minByteLength + 10) ^ this.getUint16(10),
								a.getUint16(Attr.minByteLength + 12) ^ this.getUint16(12),
								a.getUint16(Attr.minByteLength + 14) ^ this.getUint16(14),
								a.getUint16(Attr.minByteLength + 16) ^ this.getUint16(16),
								a.getUint16(Attr.minByteLength + 18) ^ this.getUint16(18),
							);
							value = { ip, port };
						} else value = null;
					} else if (kind === undefined) {
						value = a.value;
					} else {
						throw new Error('Unknown Kind');
					}
					values[l][i] = value;

					continue next_attribute;
				}
			}
			(a.comprehension_required ? unknown : unknown_opt).push(a.type);
		}

		return [...values, unknown, unknown_opt];
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
	get byteLength() {
		const padding = (4 - this.length % 4) % 4;
		return Attr.minByteLength + this.length + padding;
	}
	get value() {
		return new Uint8Array(
			this.buffer,
			this.byteOffset + Attr.minByteLength,
			this.length,
		);
	}
	set value(val) {
		this.length = val.byteLength ?? val.length;
		this.value.set(val);
		this.padding.fill(0);
	}
	get padding() {
		return new Uint8Array(
			this.buffer,
			this.byteOffset + Attr.minByteLength + this.length,
			(4 - this.length % 4) % 4,
		);
	}
}
Attr.field('type', 'u16');
Attr.field('length', 'u16');
