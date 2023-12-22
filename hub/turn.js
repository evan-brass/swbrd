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

const protocol_numbers = new Map([
	[17, 'udp'],
	[6, 'tcp']
].flatMap(v => [v, v.toReversed()]));

export const INVALID = Symbol("Invalid STUN attribute");
export const known_attributes = new Map([
	// RFC 5389:
	{type: 0x0001, name: 'mapped', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0006, name: 'username', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0008, name: 'integrity'}, // Integrity is checked separately (checking is async)
	{type: 0x0009, name: 'error', encode(turn) {}, decode(data, turn) {}},
	{type: 0x000A, name: 'unknown', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0014, name: 'realm', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0015, name: 'nonce', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0020, name: 'mapped', decode(data, turn) {}},
	{type: 0x8022, name: 'software', encode(turn) {}, decode(data, turn) {}},
	{type: 0x8023, name: 'alternate', encode(turn) {}, decode(data, turn) {}},
	{type: 0x8028, name: 'fingerprint'},
	
	// RFC 5766:
	{type: 0x000C, name: 'channel', encode(turn) {}, decode(data, turn) {}},
	{type: 0x000D, name: 'lifetime', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0012, name: 'peer', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0013, name: 'data', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0016, name: 'relayed', encode(turn) {}, decode(data, turn) {}},
	{type: 0x0018, name: 'evenport'},
	{type: 0x0019, name: 'transport', decode(data, _turn) {
		if (data.byteLength < 1) return INVALID;
		return protocol_numbers.get(data.getUint8(0));
	}},
	{type: 0x001A, name: 'fragment'},
	{type: 0x0022, name: 'reservation'},
	
	// RFC 5245 / 8445:
	{type: 0x0024, name: 'priority'},
	{type: 0x0025, name: 'use'},
	{type: 0x8029, name: 'controlled'},
	{type: 0x802A, name: 'controlling'},
].flatMap(v => [[v.type, v], [v.name, v]]));

export class CredentialManager {
	// TODO: Should we cache the keys?
	async credential(username, realm, password = realm ? 'the/turn/credential/constant' : 'the/ice/password/constant') {
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

export class Turn extends DataView {
	credential_manager = default_cm;
	constructor(buffer, byteOffset, byteLength) {
		super(buffer ?? new ArrayBuffer(20, {maxByteLength: 4096}), byteOffset, byteLength);
		// Initialize the packet if we're creating a brand new Turn message
		if (!buffer) this.init();
	}
	init(type = 0x0001) {
		this.type = type;
		this.length = 0;
		if (this.is_stun) {
			// Set the magic value
			this.setUint32(4, MAGIC);
			// Randomize the txid
			crypto.getRandomValues(this.txid);
		}
	}
	// Attributes shared by both STUN and ChannelData messages
	get type() {
		return this.getUint16(0);
	}
	set type(new_type) {
		this.setUint16(0, new_type);
	}
	get is_stun() { return this.type < 0x4000; }
	get is_channeldata() { return 0x4000 <= this.type && this.type < 0x7ffe; }
	get length() {
		return this.getUint16(2);
	}
	get packet_length() {
		if (this.byteLength < 4) return 4;
		if (this.is_stun) { return 20 + this.length; }
		else if (this.is_channeldata) { return 4 + this.length; }
		else { return Infinity; }
	}
	get framed_packet_length() {
		let ret = this.packet_length;
		while (ret % 4) ret += 1; // Infinity % 4 == NaN which is falsy
		return ret;
	}
	// deno-lint-ignore adjacent-overload-signatures
	set length(new_length) {
		// For STUN messages we must pad out the length to a 4 byte boundary
		while (this.is_stun && new_length % 4) new_length += 1;

		const size = new_length + (this.is_stun ? 20 : 4);
		
		// Resize the buffer if it's too small
		if (size > this.byteLength && this.buffer.resizable) this.buffer.resize(this.byteOffset + new_length);
		if (size > this.byteLength) throw new Error("The new length doesn't fit in this view / buffer.");
		
		this.setUint16(2, new_length);
	}
	// Attributes for channel_data messages
	get channeldata() {
		if (!this.is_channeldata) throw new Error('Not of type ChannelData');
		return new Uint8Array(this.buffer, this.byteOffset + 4, this.length);
	}
	set channeldata(data) {
		if (!this.is_channeldata) throw new Error('Not of type ChannelData');

		// Convert the data to a Uint8Array
		if (data instanceof ArrayBuffer) { data = new Uint8Array(data); }
		else { data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength); }

		this.length = data.byteLength;
		this.channel_data.set(data);
	}
	// Attributes for STUN messages
	get txid() {
		if (!this.is_stun) throw new Error('Not of type STUN');
		return new Uint8Array(this.buffer, this.byteOffset + 8, 12);
	}
	attrs() {
		if (!this.is_stun) throw new Error('Not of type STUN');

		const ret = new Map();

		let packet_length = Math.min(20 + this.length, this.byteLength);
		while (packet_length % 4) packet_length -= 1;

		let seen_integrity = false;
		for (let i = 20; i < packet_length;) {
			const attr_type = this.getUint16(i);
			const attr_len = this.getUint16(i + 2);
			i += 4;
			if (i + attr_len > packet_length) break;
			this.length = (i - 20 + attr_len);
			let value = new DataView(this.buffer, this.byteOffset + i, attr_len);
			
			if (attr_type == 0x8028 /* Fingerprint */) break;
			else if (seen_integrity) continue;
			else if (attr_type == 0x0008) seen_integrity = true;
			
			const known = known_attributes.get(attr_type);
			if (known?.decode) value = known.decode(value, this);
			if (value == INVALID) break;
			ret.set(known.name ?? attr_type, value);
			i += attr_len;
			while (i % 4) i += 1;
		}

		return ret;
	}
	async set_attrs(new_attrs) {
		if (!this.is_stun) throw new Error('Not of type STUN');

		this.length = 0;
		for (const [key, value] of new_attrs) {
			const known = known_attributes.get(key);
			if (known?.encode) known.encode.call(value, this);
		}
	}

	static async *parse(readable_stream, {maxByteLength = 4096} = {}) {
		const reader = readable_stream.getReader({mode: 'byob'});

		let buffer = new ArrayBuffer(100, maxByteLength);
		let available = 0;
		while (1) {
			const {value, done} = await reader.read(new Uint8Array(buffer, available));
			if (value) {
				buffer = value.buffer;
				available += value.byteLength;
				const turn = new this(buffer, 0, available);
				const framed = turn.framed_packet_length;
				if (available >= framed) {
					// Yield the turn message:
					yield turn;
					
					// Shift any unused data to the front of the buffer
					new Uint8Array(buffer).copyWithin(0, framed, available);
					available -= framed;
				}
				else if (framed > buffer.byteLength) {
					if (buffer.resizable && buffer.maxByteLength >= framed) buffer.resize(framed);
					else break;
				}
			}
			if (done) break;
		}
	}
}
