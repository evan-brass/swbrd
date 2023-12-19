const MAGIC = 0x2112A442;

const m = method => (
	((method << 0) & 0b00_00000_0_000_0_1111) |
	((method << 1) & 0b00_00000_0_111_0_0000) |
	((method << 2) & 0b00_11111_0_000_0_0000)
);
export const req = method => m(method) | 0b00_00000_0_000_0_0000;
export const ind = method => m(method) | 0b00_00000_0_000_1_0000;
export const res = method => m(method) | 0b00_00000_1_000_0_0000;
export const err = method => m(method) | 0b00_00000_1_000_1_0000;

export class CredentialManager {
	// TODO: Should we cache the keys?
	async credential(username, realm, password = realm ? 'the/turn/password/constant' : 'the/ice/password/constant') {
		const key_data = realm ? 
			md5(`${username}:${realm}:${password}`) :
			encoder.encode(password);
		return await crypto.subtle.importKey('raw', key_data, {
			name: 'HMAC',
			hash: 'SHA-1'
		}, false, ['sign', 'verify']);
	}
}
const default_cm = new CredentialManager();

export class Turn {
	type;
	attrs = new Map();
	txid;
	constructor() { Object.assign(this, ...arguments); }

	encode(maxByteLength = 4096) {
		const header_size = (this.type < 0x4000) ? 20 : 4;
		const buffer = new ArrayBuffer(header_size, {maxByteLength});
		const view = new DataView(buffer);

		const set_length = new_length => {
			buffer.resize(header_size + new_length);
			view.setUint16(2, new_length);
		};

		// Set the type and zero the length
		view.setUint16(0, this.type);
		set_length(0);

		// Write the header:
		if (this.type < 0x4000) {
			view.setUint32(4, MAGIC);
			new Uint8Array(buffer, 8, 12).set(this.txid);
			let i = 20;
			for (const [attr_type, value] of this.attrs.entries()) {
				view.setUint16()
			}
		}
		else if (this.type < 0x7FFE) {
			const data = this.attrs.get()
		}
		else { throw new Error('Bad type') }



		// TODO: encode channel data messages
		if (this.type >= 0x4000) throw new Error('Not Implemented');
		
	}

	// key_data;
	static decode(view) {
		if (view.byteLength < 4) return;
		const ret = new Turn();
		ret.type = view.getUint16(0);
		const length = view.getUint16(2);

		// TURN-STUN
		if (ret.type < 0x4000) {
			if (length % 4 != 0) return;
			if (view.byteLength < 20 + length) return;
			const magic = view.getUint32(4);
			if (magic != MAGIC) return;
			ret.txid = new Uint8Array(view.buffer, view.byteOffset + 8, 12);

			// Read the attributes:
			let len = 0;
			while (len < length) {
				const attr_typ = view.getUint16(20 + len);
				const attr_len = view.getUint16(20 + len + 2);
				len += 4;
				if (attr_len > (length - len)) return;
				const value = new DataView(view.buffer, view.byteOffset + 20 + len, attr_len);
				len += attr_len;

				view.setUint16(2, len);

				ret.attrs.set(attr_typ, value);

				len += attr_len;
				// Pad out the attribute:
				while (len % 4 != 0) len += 1;
			}
		}
		// TURN-ChannelData
		else if (ret.type < 0x7FFE) {
			if (view.byteLength < 4 + length) return;
			ret.attrs.set('data', new Uint8Array(view.buffer, view.byteOffset + 4, length));
		}
		// Invalid Type:
		else {
			return;
		}
		return ret;
	}
	static async *decode_readable(readable, buff_len = 4096) {
		const reader = readable.getReader({mode: 'byob'});

		let buffer = new Uint8Array(buff_len);
		while (1) {
			const {done, value} = await reader.read(buffer);
			if (value) {
				let available = value.byteOffset + value.byteLength;
				if (available >= 4) {
					const view = new DataView(value.buffer, 0, available);
					const type = view.getUint16(0);
					const length = view.getUint16(2);
					let needed;
					// Is the message TURN-STUN?
					if (type < 0x4000) {
						needed = 20 + length;
					}
					// Or is it TURN-ChannelData?
					else if (type < 0x7FFE) {
						needed = 4 + length;
					}
					// Otherwise it isn't a TURN message at all:
					else { break; /* Not a TURN message */ }

					// Pad out the TURN message:
					while (needed % 4 != 0) needed += 1;
					// Check if the message can fit inside the read buffer:
					if (needed > buff_len) break;
					// If we have the full message
					if (available >= needed) {
						const turn = Turn.decode(view);
						if (turn) yield turn;
	
						available -= needed;
						new Uint8Array(value.buffer).set(new Uint8Array(value.buffer, needed, available))
					}
				}
				buffer = new Uint8Array(value.buffer, available);
			}
			if (done) break;
		}
	}
}
