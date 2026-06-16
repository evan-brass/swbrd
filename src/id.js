import { parseBigInt } from './util.js';

export class Id {
	#value;
	static radix = 36;
	static hash = 'sha-256';
	static bits = 256;
	static MAX_ID = 2n ** BigInt(this.bits) - 1n;
	static from(val) {
		if (typeof val == 'string') val = parseBigInt(val, this.radix);
		if (typeof val != 'bigint') val = BigInt(val);
		if (val > this.MAX_ID) return;

		return new this(val);
	}
	constructor(val) {
		this.#value = val;
	}
	get fingerprint() {
		return this.constructor.hash + ' ' +
			Array.from(
				this.#value.toString(16).padStart(Id.bits / 4, '0').matchAll(
					/[0-9a-f]{2}/ig,
				),
			).join(':');
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'string') {
			return this.#value.toString(Id.radix);
		} else {
			return this.#value;
		}
	}
}
