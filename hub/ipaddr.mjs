// Deno.NetAddr.hostname is a string that we need to parse into ipv4/ipv6 bytes (In order to encode it into STUN attributes)
// The Rust equivalent of what we need: (Not that I'm actually going to do as good a job as this)
// https://github.com/rust-lang/rust/blob/26089ba0a2d9dab8381ccb0d7b99e704bc5cb3ed/library/core/src/net/parser.rs#L224
function parse_ipv4(s) {
	const parts = s.split('.').map(s => parseInt(s, 10));
	if (parts.length == 4 && parts.every(b => b >= 0 && b < 2 ** 8)) {
		return new Uint8Array(parts);
	}
}
export function parse_ipaddr(s) {
	let v4 = parse_ipv4(s);
	if (v4) return v4;
	const parts = s.split(':');
	const ret = new Uint8Array(16);
	const retv = new DataView(ret.buffer, ret.byteOffset, ret.byteLength);
	if (s.startsWith('::')) parts.splice(0, 1); // Collapse dual empty strings
	// Check if the last part is an ipv4:
	let needed = 8;
	v4 = parse_ipv4(parts[parts.length - 1]);
	if (v4) {
		parts.pop();
		ret.set(v4, 12);
		needed = 6;
	}

	// Handle `::`
	const ind = parts.indexOf('');
	if (ind < 0 && parts.length < needed) return;
	if (ind >= 0) parts[ind] = '0';
	while (parts.length < needed) parts.splice(ind, 0, '0');

	const nums = parts.map(s => parseInt(s, 16));
	if (nums.every(n => n >= 0 && n < 2 ** 16)) {
		for (let i = 0; i < needed; ++i) {
			retv.setUint16(2 * i, nums[i]);
		}

		// Check for ipv4 mapped addresses:
		if ([0, 0, 0, 0, 0, 0xffff].every((v, i) => nums[i] == v)) {
			return new Uint8Array(ret.buffer, ret.byteOffset + 12, 4);
		}

		return ret;
	}
}
