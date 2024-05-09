const tables = new Map(); // Reversed Poly -> 8-bit lookup table
export function get_table(reversed_poly) {
	if (!tables.has(reversed_poly)) tables.set(reversed_poly, Uint32Array.from({length: 256}, (_, i) => {
		let v = i;
		for (let b = 0; b < 8; ++b) {
			v = (v & 1) ? (v >>> 1 ^ reversed_poly) >>> 0 : v >>> 1;
		}
		return v;
	}));
	return tables.get(reversed_poly);
}

export function crc32(data, reversed_poly = 0xEDB88320) {
	const table = get_table(reversed_poly);

	let crc = 0xFFFFFFFF;

	for (const b of data) {
		crc = table[(b ^ crc) & 0xFF] ^ (crc >> 8 & 0xFFFFFF);
	}

	return ~crc >>> 0;
}

export function crc32c(data) {
	return crc32(data, 0x82F63B78);
}
