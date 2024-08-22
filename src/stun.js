import { Wire } from './wire.js';
import { decoder, encoder } from "./util.js";

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
		const pad = (4 - len % 4) % 4;
		super.byteLength = value + pad;
		this.length = value - 4;
		// TODO: fill the padding with zeros
	}
}
Stun.field('...attrs', Attr);
Attr.field('type', 'u16');
Attr.field('length', 'u16');

export class TextAttr extends Attr {
	get value() {
		return decoder.decode(new Uint8Array(this.buffer, this.byteOffset + 4, this.length));
	}
	set value(value) {
		encoder.encodeInto(value, new Uint8Array(this.buffer, this.byteOffset + 4, this.length));
	}
}

Attr.prototype.specialize = function() {
	switch (this.type) {
		case 0x0006: /* Username */
		case 0x0014: /* Realm */
		case 0x0015: /* Nonce */
		case 0x8003: /* Alternate Domain */
		case 0x8022: /* Software */
			return new TextAttr(this);
		default:
			return this;
	}
};
