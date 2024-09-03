import { Wire } from './wire.js';
import { Stun } from './stun.js';

export class Data extends Wire {
	get byteLength() {
		return this.constructor.minByteLength + this.length;
	}
}
Data.field('channel', 'u16');
Data.field('length', 'u16');
Data.field('data', '[]');

export class Turn extends Wire {
	specialize() {
		if (this.type < 0x4000) return this.raw_byteLength >= Stun.minByteLength ? new Stun(this) : this;
		if (this.type < 0x5000) return this.raw_byteLength >= Data.minByteLength ? new Data(this) : this;
		return this;
	}
}
Turn.field('type', 'u16');
