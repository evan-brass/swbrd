// Per-Round Shifts:
const s = new Uint8Array([
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]);
// Sines of integers (Radians):
const K = new Uint32Array([
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]);

function add(x, y) {
	const lsw = (x & 0xffff) + (y & 0xffff);
	const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
	return (msw << 16) | (lsw & 0xffff);
}
function rotate_left(num, cnt) {
	return (num << cnt) | (num >>> (32 - cnt));
}

export function md5(input) {
	const state = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

	for (const block of blocks(input)) {
		// Update the state
		let [A, B, C, D] = state;
		for (let j = 0; j < 64; ++j) {
			let F, g;
			if (j < 16) {
				F = (B & C) | (~B & D);
				g = j;
			} else if (j < 32) {
				F = (B & D) | (C & ~D);
				g = (5 * j + 1) % 16;
			} else if (j < 48) {
				F = B ^ C ^ D;
				g = (3 * j + 5) % 16;
			} else {
				F = C ^ (B | ~D);
				g = (7 * j) % 16;
			}
			F = add(F, add(A, add(K[j], block[g])));
			A = D;
			D = C;
			C = B;
			B = add(B, rotate_left(F, s[j]));
		}

		state.set([
			add(state[0], A),
			add(state[1], B),
			add(state[2], C),
			add(state[3], D)
		]);
	}

	const retv = new DataView(state.buffer);
	for (let i = 0; i < state.length; ++i) {
		retv.setUint32(i * 4, state[i], true);
	}

	const ret = new Uint8Array(state.buffer);

	return ret;
}

const text_encoder = new TextEncoder();
function* blocks(input) {
	if (typeof input == 'string') {
		input = text_encoder.encode(input);
	} else if (!(input instanceof Uint8Array)) {
		input = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
	} else {
		throw new Error("Unrecognized input type.");
	}

	let length = 0n;
	let offset = 0;
	let last_block = false;

	const block = new Uint32Array(16);
	const block8 = new Uint8Array(block.buffer);
	const blockv = new DataView(block.buffer);

	while (!last_block) {
		// Copy the data into the block (Padding as needed)
		for (let i = 0; i < block8.byteLength; i += 1, offset += 1) {
			if (offset < input.byteLength) {
				block8[i] = input[offset];
				length += 8n;
			} else if (offset == input.byteLength) {
				block8[i] = 0x80;
			} else if (i == 56) {
				// Write the original bit-length:
				blockv.setBigUint64(56, length, true);
				last_block = true;
				break;
			} else {
				block8[i] = 0;
			}
		}
		// Convert the block from little-endian into native endian:
		for (let i = 0; i < block.length; ++i) {
			block[i] = blockv.getUint32(i * 4, true);
		}
		yield block;
	}
}
