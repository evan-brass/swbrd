import { parseBigInt } from './util.js';

export class Id {
	#value;
	static radix = 36;
	static hash = 'sha-256';
	static bits = 256;
	static MAX_ID = 2n ** BigInt(this.bits);
	constructor(val) {
		if (typeof val == 'string') {
			this.#value = parseBigInt(val, Id.radix);
		} else {
			this.#value = BigInt(val);
		}
		if (this.#value > Id.MAX_ID) throw new Error("Id is too large.");
	}
	fingerprint() {
		return `${Id.hash} ${this.#value.toString(16).padStart(Id.bits / 4, '0').replace(
			/[0-9a-f]{2}/ig,
			':$&',
		).slice(1)
			}`;
	}
	[Symbol.toPrimitive](hint) {
		if (hint == "string") {
			return this.#value.toString(Id.radix);
		} else {
			return this.#value;
		}
	}
}
