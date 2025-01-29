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

export class Handshake extends Wire {
	get byteLength() {
		return Handshake.minByteLength + this.length;
	}
}
Handshake.field('type', 'u8');
Handshake.field('length', 'u24');
Handshake.field('seq', 'u16');
Handshake.field('offset', 'u24');
Handshake.field('total', 'u24');

export class ClientHello extends Handshake {
	get session() {
		if (ClientHello.minByteLength + 1 >= this.byteLength) return null;
		const len = this.getUint8(ClientHello.minByteLength)
		if (this.byteLength)
	}
	get #session_len() {
		return this.getUint8()
	}

}
ClientHello.field('version', 'u16');
ClientHello.field('random', '[32]');
// ClientHello.minByteLength += 1; // Session Length
// ClientHello.minByteLength += 1; // Cookie Length
// ClientHello.minByteLength += 2; // Cipher Suites length (in bytes so 1/2 the number of suites)
// ClientHello.minByteLength += 1; // Compression Methods length
// ClientHello.minByteLength += 1; // Compression Methods length

