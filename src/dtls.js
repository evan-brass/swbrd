import { Wire } from './wire.js';

export const DTLS_1_0 = 0xfeff;
export const DTLS_1_2 = 0xfefd;

export class Dtls extends Wire {
	get byteLength() { return Dtls.minByteLength + this.length; }
	set byteLength(val) { super.byteLength = val; this.length = (val - Dtls.minByteLength); }
}
Dtls.field('type', 'u8');
Dtls.field('version', 'u16');
Dtls.field('epoch', 'u16');
Dtls.field('seq', '[6]'); // TODO: Probably also want a getter that returns as a u64?
Dtls.field('length', 'u16');

