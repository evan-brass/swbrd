import { base } from './base.js';

export const algorithm = 'sha-256';
export const bytes = 32;
export const bits = bytes * 8;

export function to_fingerprint(id) {
	return `${algorithm} ${
		BigInt(id).toString(16).padStart(2 * bytes, '0').replace(
			/[0-9a-f]{2}/ig,
			':$&',
		).slice(1)
	}`;
}

export function from_bytes(arr) {
	if (arr.length != bytes) return;

	return BigInt(
		arr.reduce((a, v) => a + v.toString(16).padStart(2, '0'), '0x')
	);
}

export function to_string(id) {
	return base(BigInt(id), { bits });
}

export function from_string(s) {
	return base(String(s), { bits });
}
