import { Wire } from './wire.js';

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
		return 4 + this.length + pad;
	}
}
Stun.field('...attrs', Attr);
Attr.field('type', 'u16');
Attr.field('length', 'u16');
