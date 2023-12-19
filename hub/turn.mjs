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
	// key_data;
	static async decode(buff, cm = default_cm) {
		if (buff.byteLength < 4) return;
		const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength);
		const typ = view.getUint16(0);
		const ret = new Turn();
		ret.type = view.getUint16(0);
		const length = view.getUint16(2);

		// TURN-STUN
		if (ret.type < 0x4000) {
			if (length % 4 != 0) return;
			if (buff.byteLength < 20 + length) return;
			const magic = view.getUint32(4);
			if (magic != MAGIC) return;
			ret.txid = buff.slice(8, 20);

			// Read the attributes:
			let len = 0;
			while (len < length) {
				const attr_typ = view.getUint16(20 + len);
				const attr_len = view.getUint16(20 + len + 2);
				len += 4;
				if (attr_len > (length - len)) return;
				const value = new DataView(buff.buffer, buff.byteOffset + 20 + len, attr_len);
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
			if (buff.byteLength < 4 + length) return;
			ret.attrs.set('data', buff.slice(4, 4 + length));
		}
		// Invalid Type:
		else {
			return;
		}
		return ret;
	}
	static async *decode_stream(conn, cm = default_cm) {
		// Deframe the TURN messages
		const read_buff = new Uint8Array(4096);
		let available = 0;
		while (available < read_buff.byteLength) {
			const writable = new Uint8Array(read_buff.buffer, read_buff.byteOffset + available, read_buff.byteLength - available);
			const res = await conn.read(writable);
			if (typeof res != 'number') break;
			available += res;
			if (available < 4) continue;
			const view = new DataView(read_buff.buffer, read_buff.byteOffset, available);
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
			if (needed > read_buff.byteLength) break;
			// Continue reading if we don't have enough data available:
			if (available < needed) continue;

			const turn = await Turn.decode(new Uint8Array(read_buff.buffer, read_buff.byteOffset, needed), cm);
			if (turn) yield turn;

			// Copy unused available data:
			new Uint8Array(read_buff.buffer, read_buff.byteOffset, available - needed)
				.set(new Uint8Array(read_buff.buffer, read_buff.byteOffset + needed, available - needed));
			available -= needed;
		}
	}
}
