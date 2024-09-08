import { Wire } from './wire.js';


export class Sctp extends Wire {}
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
		const pad = (4 - value % 4) % 4;
		super.byteLength = value + pad;
		new Uint8Array(this.buffer, this.byteOffset + value, pad).fill(0);
	}
}
Param.field('type', 'u16');
Param.field('length', 'u16');

export class DataChunk extends Chunk {
	get params() { return []; }
}
DataChunk.field('tsn', 'u32');
DataChunk.field('stream', 'u16');
DataChunk.field('seq', 'u16');
DataChunk.field('ppid', 'u32');
DataChunk.field('data', '[]');

export class InitChunk extends Chunk {}
InitChunk.field('vtag', 'u32');
InitChunk.field('rwnd', 'u32');
InitChunk.field('num_out', 'u16');
InitChunk.field('num_in', 'u16');
InitChunk.field('tsn', 'u32');


Chunk.prototype.specialize = function() {
	switch (this.type) {
		case 0: return this.byteLength >= DataChunk.minByteLength ? new DataChunk(this) : this
		case 1: return this.byteLength >= InitChunk.minByteLength ? new InitChunk(this) : this
	}
	return this
};
Chunk.field('...params', Param);
