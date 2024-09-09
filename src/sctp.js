import { crc32c } from './crc32.js';
import { Wire } from './wire.js';


export class Sctp extends Wire {
	get byteLength() {
		if (!this.children.length) return super.raw_byteLength;
		return super.byteLength;
	}
	set byteLength(value) {
		super.byteLength = value;
	}
	*#sum_bytes() {
		yield* new Uint8Array(this.buffer, this.byteOffset, 8);
		yield* [0, 0, 0, 0];
		yield* new Uint8Array(this.buffer, this.byteOffset + 12, this.byteLength - 12);
	}
	get expected_checksum() {
		return crc32c(this.#sum_bytes(), 0x82F63B78);
	}
}
Sctp.field('sport', 'u16');
Sctp.field('dport', 'u16');
Sctp.field('vtag', 'u32');
Sctp.field('checksum', 'u32_le'); // Fuck if I know why this is little endian.

export class Chunk extends Wire {
	get byteLength() {
		const length = this.length;
		const pad = (4 - length % 4) % 4;
		return Math.max(length + pad, this.constructor.minByteLength);
	}
	set byteLength(value) {
		const pad = (4 - value % 4) % 4;
		super.byteLength = value + pad;
		this.length = value;
		new Uint8Array(this.buffer, this.byteOffset + value, pad).fill(0);
	}
}
Chunk.field('type', 'u8');
Chunk.field('flags', 'u8');
Chunk.field('length', 'u16');
Sctp.field('...chunks', Chunk);

export class Param extends Wire {
	get byteLength() {
		const length = this.length;
		const pad = (4 - length % 4) % 4;
		return Math.max(length + pad, this.constructor.minByteLength);
	}
	set byteLength(value) {
		// WEIRD: Chrome's SCTP implementation doesn't include the padding of a parameter in the length of the parent chunk. So we only pad on read and let the chunk hnalde zeroing the bytes.
		super.byteLength = value;
		this.length = value;
	}
}
Param.field('type', 'u16');
Param.field('length', 'u16');
Param.field('value', '[]');

export class DataChunk extends Chunk {
	constructor() { super(...arguments); this.type = 0; }
	get params() { return []; }
}
DataChunk.field('tsn', 'u32');
DataChunk.field('stream', 'u16');
DataChunk.field('seq', 'u16');
DataChunk.field('ppid', 'u32');
DataChunk.field('data', '[]');

export class InitChunk extends Chunk {
	constructor() { super(...arguments); this.type = 1; }
}
InitChunk.field('vtag', 'u32');
InitChunk.field('rwnd', 'u32');
InitChunk.field('out', 'u16');
InitChunk.field('in', 'u16');
InitChunk.field('tsn', 'u32');

export class InitAckChunk extends Chunk {
	constructor() { super(...arguments); this.type = 2; }
}
InitAckChunk.field('vtag', 'u32');
InitAckChunk.field('rwnd', 'u32');
InitAckChunk.field('out', 'u16');
InitAckChunk.field('in', 'u16');
InitAckChunk.field('tsn', 'u32');

export class SackChunk extends Chunk {
	constructor() { super(...arguments); this.type = 3; }
	get params() { return []; }
}
SackChunk.field('cumtsn', 'u32');
SackChunk.field('rwnd', 'u32');
SackChunk.field('gaps', 'u16');
SackChunk.field('dups', 'u16');

export class HeartbeatChunk extends Chunk {
	constructor() { super(...arguments); this.type = 4; }
	get params() { return []; }
}
HeartbeatChunk.field('info', '[]');

export class HeartbeatAckChunk extends Chunk {
	constructor() { super(...arguments); this.type = 5; }
	get params() { return []; }
}
HeartbeatAckChunk.field('info', '[]');

export class CookieChunk extends Chunk {
	constructor() { super(...arguments); this.type = 10; }
}

export class CookieAckChunk extends Chunk {
	constructor() { super(...arguments); this.type = 11; }
}

Chunk.prototype.specialize = function() {
	switch (this.type) {
		case 0: return this.byteLength >= DataChunk.minByteLength ? new DataChunk(this) : this
		case 1: return this.byteLength >= InitChunk.minByteLength ? new InitChunk(this) : this
		case 2: return this.byteLength >= InitAckChunk.minByteLength ? new InitChunk(this) : this
		case 3: return this.byteLength >= SackChunk.minByteLength ? new SackChunk(this) : this
		case 4: return this.byteLength >= HeartbeatChunk.minByteLength ? new HeartbeatChunk(this) : this
		case 5: return this.byteLength >= HeartbeatAckChunk.minByteLength ? new HeartbeatAckChunk(this) : this
		case 10: return this.byteLength >= CookieChunk.minByteLength ? new CookieChunk(this) : this
		case 11: return this.byteLength >= CookieAckChunk.minByteLength ? new CookieAckChunk(this) : this
	}
	return this
};
Chunk.field('...params', Param);
