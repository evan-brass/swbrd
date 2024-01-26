import { atob_url, btoa_url } from "./b64url.js";

const untagged = new Map([
	['sha-512', 64],
	['sha-384', 48],
	['sha-256', 32],
	['sha-1',   20],
].map(a => [a, a.toReversed()]).flat());

export class Id {
	['sha-256'];
	constructor() { Object.assign(this, ...arguments); }
	static from_str(s) {
		const fingerprints = Object.create(null);
		for (const value of s.split(',')) {
			try {
				const binstr = atob_url(value);
				const alg = untagged.get(binstr.length);
				if (!alg) continue;
				fingerprints[alg] = binstr;
			} catch {}
		}
		if (fingerprints['sha-256']) return new this(fingerprints);
	}
	static from_sdp(sdp) {
		const fingerprints = Object.create(null);
		for (const {1: tmp, 2: value} of sdp.matchAll(/^a=fingerprint:([^ ]+) ([0-9a-f]{2}(?:\:[0-9a-f]{2})+)/img)) {
			const alg = tmp.toLowerCase();
			const expected_len = untagged.get(alg);
			const bytes = value.split(':').map(s => parseInt(s, 16));
			if (expected_len !== bytes.length || bytes.some(b => b < 0 || 255 < b)) continue;
			fingerprints[alg] = String.fromCharCode(...bytes);
		}
		if (fingerprints['sha-256']) return new this(fingerprints);
	}
	#hex(alg) {
		return Array.from(this[alg], c => c.charCodeAt(0).toString(16).padStart(2, '0'));
	}
	*sdp() {
		for (const alg in this) {
			yield `a=fingerprint:${alg} ${this.#hex(alg).join(':')}`;
		}
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'number') {
			return BigInt('0x' + this.#hex('sha-256').join(''));
		} else {
			return btoa_url(this['sha-256']);
		}
	}
}
