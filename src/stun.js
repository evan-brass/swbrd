import { Wire } from './wire.js';
import { decoder, encoder } from "./util.js";
import { crc32 } from "./crc32.js";

export const MAGIC_COOKIE = 0x2112A442;

const classes = new Map([
	[0x0000, 'request'],
	[0x0010, 'indication'],
	[0x0100, 'success'],
	[0x0110, 'error'],
].map(a => [a, a.toReversed()]).flat(1));

const methods = new Map([
	[0x001, 'binding'],
	[0x003, 'allocate'],
	[0x004, 'refresh'],
	[0x006, 'send'],
	[0x007, 'data'],
	[0x008, 'create permission'],
	[0x009, 'channel bind'],
].map(a => [a, a.toReversed()]).flat(1));

const attrs = new Map([
	// [0x0001, 'old mapped'],
	[0x0006, 'username'],
	[0x0008, 'integrity'],
	[0x0009, 'error'],
	// [0x000A, 'unknown'],
	[0x000C, 'channel'],
	[0x000D, 'lifetime'],
	[0x0012, 'peer'],
	[0x0013, 'data'],
	[0x0014, 'realm'],
	[0x0015, 'nonce'],
	[0x0016, 'relayed'],
	[0x0017, 'requested family'],
	// [0x0018, 'even port'],
	// [0x0019, 'requested transport'],
	// [0x001A, 'dont fragment'],
	[0x0020, 'mapped'],
	[0x0022, 'reservation'],
	[0x0024, 'priority'],
	[0x0025, 'use candidate'],
	[0x8000, 'additional requested family'],
	[0x8003, 'alternate domain'],
	[0x8022, 'software'],
	[0x8023, 'alternate server'],
	[0x8028, 'fingerprint'],
	[0x8029, 'ice controlled'],
	[0x802A, 'ice controlling'],
].map(a => [a, a.toReversed()]).flat(1));

export class Stun extends Wire {
	get byteLength() { return 20 + this.length; }
	set byteLength(value) {
		// Attributes must handle the alignment so we don't do that here.
		super.byteLength = value;
		this.length = (value - 20);
	}
	get class() {
		return classes.get(this.type & 0x0110);
	}
	set class(value) {
		if (typeof value != 'string' || !classes.has(value)) throw new Error("Unknown class");
		this.type = (this.type & !0x0110) | classes.get(value);
	}
	get method() {
		return methods.get(this.type & ~0x0110);
	}
	set method(value) {
		if (typeof value != 'string' || !methods.has(value)) throw new Error("Unknown method");
		this.type = (this.type & 0x0110) | methods.get(value);
	}
}
Stun.field('type', 'u16');
Stun.field('length', 'u16');
Stun.field('cookie', 'u32');
Stun.field('txid', '[12]');

export class Attr extends Wire {
	get byteLength() {
		const len = this.length;
		const pad = (4 - len % 4) % 4;
		return 4 + len + pad;
	}
	set byteLength(value) {
		const pad = (4 - value % 4) % 4;
		super.byteLength = value + pad;
		this.length = value - 4;
		new Uint8Array(this.buffer, this.byteOffset + value, pad).fill(0);
	}
	get type() {
		const typ = this.getUint16(0);
		return attrs.get(typ) ?? typ;
	}
	set type(value) {
		this.setUint16(0, typeof value == 'string' ? attrs.get(value) : value);
	}
	get prefix() {
		// TODO: This copy sucks.
		const copy = new Uint8Array(this.buffer, this.parent.byteOffset, this.byteOffset - this.parent.byteOffset).slice();
		const length_at = copy.byteLength - Stun.minByteLength + this.byteLength;
		new DataView(copy.buffer, copy.byteOffset).setUint16(2, length_at);
		return copy;
	}
}
Stun.field('...attrs', Attr);
Attr.minByteLength += 2;
Attr.field('length', 'u16');

export class TextAttr extends Attr {
	get value() {
		return decoder.decode(new Uint8Array(this.buffer, this.byteOffset + 4, this.length));
	}
	set value(value) {
		encoder.encodeInto(value, new Uint8Array(this.buffer, this.byteOffset + 4, this.length));
	}
}

export class U32Attr extends Attr {}
U32Attr.field('value', 'u32');

export class U64Attr extends Attr {}
U64Attr.field('value', 'u64');

export class FingerprintAttr extends Attr {
	expected() {
		return (crc32(this.prefix) ^ 0x5354554e) >>> 0;
	}
}
FingerprintAttr.field('actual', 'u32');

export class Sha1Integrity extends Attr {
	async verify(key) {
		if (key?.algorithm?.hash?.name != 'SHA-1') return false;
		return await crypto.subtle.verify('HMAC', key, this.actual, this.prefix);
	}
	async sign(key) {
		if (key?.algorithm?.hash?.name != 'SHA-1') throw new Error("The key should be an HMAC key using the SHA-1 algorithm.");
		this.actual.set(new Uint8Array(await crypto.subtle.sign('HMAC', key, this.prefix)));
	}
}
Sha1Integrity.field('actual', '[20]');

Attr.prototype.specialize = function() {
	switch (this.type) {
		case 'username':
		case 'realm':
		case 'nonce':
		case 'alternate domain':
		case 'software':
			return new TextAttr(this);
		case 'priority':
		case 'lifetime':
			return this.byteLength >= U32Attr.minByteLength ? new U32Attr(this) : this;
		case 'ice controlled':
		case 'ice controlling':
			return this.byteLength >= U64Attr.minByteLength ? new U64Attr(this) : this;
		case 'fingerprint':
			return this.byteLength >= FingerprintAttr.minByteLength ? new FingerprintAttr(this) : this;
		case 'integrity':
			return this.byteLength >= Sha1Integrity.minByteLength ? new Sha1Integrity(this) : this;
		default:
			return this;
	}
};
