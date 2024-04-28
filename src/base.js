export const base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const base62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const base64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export const urlbase64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// base(0xdeadbeef01234567n, {charset: base64}) == 'N6tvu8BI0Vn'
// btoa(String.fromCharCode(0xde,0xad,0xbe,0xef,0x01,0x23,0x45,0x67)) == '3q2+7wEjRWc='
// Honestly, I don't really know why they are completely different.  I must not understand how base64 works.
// My current guess is that it has something to do with my implementation encoding numbers instead of bytes.

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
			ret += BigInt(d) * BigInt(charset.length) ** BigInt(input.length - i - 1);
		}
		if (BigInt.asUintN(bits, ret) != ret) return; // Make sure that the result is within the numbers representable with the given number of bits
	}
	else {
		input = BigInt(input);
		while (input > 0n) {
			ret ??= '';
			ret = charset.charAt(Number(input % BigInt(charset.length))) + ret;
			input /= BigInt(charset.length);
		}
		if (pad_len) ret.padStart(pad_len, charset[0]);
	}
	return ret;
}
