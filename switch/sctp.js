import { crc32c } from "./crc32.js";

const chunk_types = new Map();
export class Chunk extends DataView {
	static get fixed() { return 4; }
	get type() {
		return this.getUint8(0);
	}
	set type(value) {
		this.setUint8(0, value);
	}
	get flags() {
		return this.getUint8(1);
	}
	set flags(value) {
		this.setUint8(1, value);
	}
	get length() {
		if (this.byteLength < 4) return 4;
		return Math.max(this.getUint16(2), 4);
	}
	set length(value) {
		if (value < 4) throw new Error();
		this.setUint16(2, value);
	}
	*[Symbol.iterator]() {
		for (let i = this.constructor.fixed; i < this.length;) {
			let param = new Param(this.buffer, this.byteOffset + i);
			i += param.length;

			if (chunk_types.has(param.type)) param = new (chunk_types.get(param.type))(this.buffer, param.byteOffset, param.length);
			param.parent = this;

			yield param;
		}
	}
}

const param_types = new Map();
export class Param extends DataView {
	get type() {
		return this.getUint16(0);
	}
	set type(value) {
		this.setUint16(0, value);
	}
	get length() {
		if (this.byteLength < 4) return 4;
		return Math.max(this.getUint16(2), 4);
	}
	set length(value) {
		if (value < 4) throw new Error();
		this.setUint16(2, value);
	}
	get value() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, this.length - 4);
	}
}

export class Data extends Chunk {
	static get fixed() { return 16; }
	get tsn() {
		return this.getUint32(4);
	}
	set tsn(value) {
		this.setUint32(4, value);
	}
	get stream() {
		return this.getUint16(8);
	}
	set stream(value) {
		this.setUint16(8, value);
	}
	get seq() {
		return this.getUint16(10);
	}
	set seq(value) {
		this.setUint16(10, value);
	}
	get ppi() {
		return this.getUint32(12);
	}
	set ppi(value) {
		this.setUint32(12, value);
	}
	get data() {
		return new Uint8Array(this.buffer, this.byteOffset + this.constructor.fixed, this.length - this.constructor.fixed)
	}
}
chunk_types.set(0x00, Data);

export class Init extends Chunk {
	static get fixed() { return 20; }
	get init_vtag() {
		return this.getUint32(4);
	}
	set init_vtag(value) {
		this.setUint32(4, value);
	}
	get arwnd() {
		return this.getUint32(8);
	}
	set arwnd(value) {
		this.setUint32(8, value);
	}
	get out_count() {
		return this.getUint16(12);
	}
	set out_count(value) {
		this.setUint16(12, value);
	}
	get in_count() {
		return this.getUint16(14);
	}
	set in_count(value) {
		this.setUint16(14, value);
	}
	get init_tsn() {
		return this.getUint32(16);
	}
	set init_tsn(value) {
		this.setUint32(16, value);
	}
}
chunk_types.set(0x01, Init);

export class InitAck extends Init {
	static get type() { return 2; }
}
chunk_types.set(InitAck.type, InitAck);

export class Sack extends Chunk {
	static get type() { return 3; }
	static get fixed() { return 16; }
	get cum_tsn() {
		return this.getUint32(4);
	}
	set cum_tsn(value) {
		this.setUint32(4, value);
	}
	get arwnd() {
		return this.getUint32(8);
	}
	set arwnd(value) {
		this.setUint32(8, value);
	}
	get gaps() {
		return this.getUint16(12);
	}
	set gaps(value) {
		this.setUint16(12, value);
	}
	get dups() {
		return this.getUint16(14);
	}
	set dups(value) {
		this.setUint16(14, value);
	}
}
chunk_types.set(Sack.type, Sack);

export class Heartbeat extends Chunk {
	static get type() { return 4; }
	get value() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, this.length - 4);
	}
}
chunk_types.set(Heartbeat.type, Heartbeat);
export class HeartbeatAck extends Chunk {
	static get type() { return 5; }
	get value() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, this.length - 4);
	}
}
chunk_types.set(HeartbeatAck.type, HeartbeatAck);

export class Cookie extends Chunk {
	static get type() { return 10; }
}
chunk_types.set(Cookie.type, Cookie);

export class CookieAck extends Chunk {
	static get type() { return 11; }
}
chunk_types.set(CookieAck.type, CookieAck);


export class Sctp extends DataView {
	get sport() {
		return this.getUint16(0);
	}
	set sport(value) {
		this.setUint16(0, value);
	}
	get dport() {
		return this.getUint16(2);
	}
	set dport(value) {
		this.setUint16(2, value);
	}
	get vtag() {
		return this.getUint32(4);
	}
	set vtag(value) {
		this.setUint32(4, value);
	}
	*#sum_bytes() {
		yield* new Uint8Array(this.buffer, this.byteOffset, 8);
		yield* [0, 0, 0, 0];
		yield* new Uint8Array(this.buffer, this.byteOffset + 12, this.byteLength - 12);
	}
	get checksum() {
		const actual = this.getUint32(8, true); // Fuck if I know why this is little endian instead of big endian but whatever.
		const expected = crc32c(this.#sum_bytes(), 0x82F63B78);
		return actual === expected;
	}
	set checksum(_value) {
		this.setUint32(8, crc32c(this.#sum_bytes(), 0x82F63B78), true);
	}
	*[Symbol.iterator]() {
		for (let i = 12; i + 4 < this.byteLength;) {
			let chunk = new Chunk(this.buffer, this.byteOffset + i, this.byteLength - i);
			i += chunk.length;
			while (i % 4 != 0) i += 1;
			if (i > this.byteLength) break;

			if (chunk_types.has(chunk.type)) chunk = new (chunk_types.get(chunk.type))(this.buffer, chunk.byteOffset, chunk.length);

			yield chunk;
		}
	}
}
