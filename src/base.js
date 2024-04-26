export const base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const base62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export const urlbase64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function base(input, {
	charset = base62,
	bits = 256,
	pad_len = false,
	// pad_len = Math.ceil(bits / Math.log2(charset.length)),
} = {}) {
	let ret;
	if (typeof input == 'string') {
		if (pad_len && input.length != pad_len) return;
		for (let i = 0; i < input.length; ++i) {
			ret ??= 0n;
			const d = charset.indexOf(input[i]);
			if (d == -1) return;
			ret += BigInt(charset.length) ** BigInt(i) * BigInt(d);
		}
		if (BigInt.asUintN(bits, ret) != ret) return;
	}
	else {
		input = BigInt(input);
		while (input > 0n) {
			ret ??= '';
			ret += charset.charAt(Number(input % BigInt(charset.length)));
			input /= BigInt(charset.length);
		}
		if (pad_len) ret.padStart(pad_len, charset[0]);
	}
	return ret;
}
