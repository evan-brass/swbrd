export function crc32( data ) {
	let crc = 0xFFFFFFFF;

	for (let b of data) {
		for (let i = 0; i < 8; ++i) {
			crc = (b ^ crc) & 1 ? crc >>> 1 ^ 0xEDB88320 : crc >>> 1;
			b = b >>> 1;
		}
	}

	return ~crc >>> 0;
}
