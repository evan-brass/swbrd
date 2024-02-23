const charset = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58(input) {
	let ret;
	if (typeof input == 'string') {
		for (let i = 0; i < input.length; ++i) {
			ret ??= 0n;
			const d = charset.indexOf(input[i]);
			if (d == -1) return;
			ret += 58n ** BigInt(i) * BigInt(d);
		}
		return ret;
	}
	else {
		input = BigInt(input);
		while (input > 0n) {
			ret ??= '';
			ret += charset.charAt(Number(input % 58n));
			input /= 58n;
		}
	}
	return ret;
}
