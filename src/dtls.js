import { Wire } from './wire.js';

export const DTLS_1_0 = 0xfeff;
export const DTLS_1_2 = 0xfefd;

export class Dtls extends Wire {
	get byteLength() { return Dtls.minByteLength + this.length; }
	set byteLength(val) { super.byteLength = val; this.length = (val - Dtls.minByteLength); }
}
Dtls.field('typ', 'u8');
Dtls.field('version', 'u16');
Dtls.field('epoch', 'u16');
Dtls.field('seq', '[6]'); // TODO: Probably also want a getter that returns as a u64?
Dtls.field('length', 'u16');

export class DtlsCid extends Wire {
	#cid_len = 1;
	get byteLength() {
		return 13 + this.#cid_len + this.length;
	}
	set byteLength(val) {
		super.byteLength = val;
		this.length = val - this.#cid_len - 13;
	}

	get cid_len() { return this.#cid_len; }
	set cid_len(val) {
		if (typeof val != 'number' || val < 1 || val > 255) throw new Error("Invalid CID length");
		this.#cid_len = val;
		// TODO: Update the byteLength?
	}

	// CID is a classic array field which only has a getter:
	get cid() {
		return new Uint8Array(this.buffer, this.byteOffset + 11, this.#cid_len);
	}

	get length() { return this.getUint16(11 + this.#cid_len); }
	set length(val) { this.setUint16(11 + this.#cid_len, val); }
}
DtlsCid.field('typ', 'u8');
DtlsCid.field('version', 'u16');
DtlsCid.field('epoch', 'u16');
DtlsCid.field('seq', '[6]');
DtlsCid.minByteLength += 1; // CID is at least 1 byte
DtlsCid.minByteLength += 2; // Length (which appears after the CID)

export class DtlsHandshake extends Dtls {}
DtlsHandshake.field('h_typ', 'u8');
DtlsHandshake.field('h_length', '[3]');
DtlsHandshake.field('h_sequence', 'u16');
DtlsHandshake.field('frag_offset', '[3]');
DtlsHandshake.field('frag_length', '[3]');

export class DtlsChangeCipherSpec extends Dtls {}
export class DtlsAlert extends Dtls {}
export class DtlsApplicationData extends Dtls {}
export class DtlsHeartbeat extends Dtls {}
export class DtlsAck extends Dtls {}

Dtls.prototype.specialize = function() {
	if (this.constructor != Dtls) return this; // Huh: the specialize being recursive is a bit of a problem.
	switch (this.typ) {
		case 20: return this.byteLength >= DtlsChangeCipherSpec.minByteLength ? new DtlsChangeCipherSpec(this).specialize() : this; 
		case 21: return this.byteLength >= DtlsAlert.minByteLength ? new DtlsAlert(this).specialize() : this;
		case 22: return this.byteLength >= DtlsHandshake.minByteLength ? new DtlsHandshake(this).specialize() : this;
		case 23: return this.byteLength >= DtlsApplicationData.minByteLength ? new DtlsApplicationData(this).specialize() : this;
		case 24: return this.byteLength >= DtlsHeartbeat.minByteLength ? new DtlsHandshake(this).specialize() : this;
		case 25: return this.byteLength >= DtlsCid.minByteLength ? new DtlsCid(this).specialize() : this;
		case 26: return this.byteLength >= DtlsAck.minByteLength ? new DtlsAck(this).specialize() : this;
	}
	return this;
};
