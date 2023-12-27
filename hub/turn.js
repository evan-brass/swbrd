import { parse_ipaddr } from "./ipaddr.mjs";

const MAGIC = 0x2112A442;

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

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class Turn extends DataView {
	#attrs;
	constructor(buffer, byteOffset, byteLength) {
		super(buffer ?? new ArrayBuffer(200, {maxByteLength: 4096}), byteOffset, byteLength);
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
	get packet() {
		return new Uint8Array(this.buffer, this.byteOffset, this.packet_length);
	}
	get framed_packet() {
		return new Uint8Array(this.buffer, this.byteOffset, this.framed_packet_length);
	}
	// deno-lint-ignore adjacent-overload-signatures
	set length(new_length) {
		// For STUN messages we must pad out the length to a 4 byte boundary
		while (this.is_stun && new_length % 4) new_length += 1;

		const size = new_length + (this.is_stun ? 20 : 4);
		
		// Resize the buffer if it's too small
		if (size > this.byteLength && this.buffer.resizable) this.buffer.resize(this.byteOffset + size);
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
	set_stun_type(clas, method) {
		this.type =
			((method << 0) & 0b00_00000_0_000_0_1111) |
			((clas   << 4) & 0b00_00000_0_000_1_0000) |
			((method << 1) & 0b00_00000_0_111_0_0000) |
			((clas   << 7) & 0b00_00000_1_000_0_0000) |
			((method << 2) & 0b00_11111_0_000_0_0000);
	}
	get class() {
		const typ = this.type;
		return (
			((typ & 0b00_00000_0_000_1_0000) >> 4) |
			((typ & 0b00_00000_1_000_0_0000) >> 7)
		);
	}
	set class(clas) {
		this.set_stun_type(clas, this.method);
	}
	get method() {
		const typ = this.type;
		return (
			((typ & 0b00_00000_0_000_0_1111) >> 0) |
			((typ & 0b00_00000_0_111_0_0000) >> 1) |
			((typ & 0b00_11111_0_000_0_0000) >> 2)
		);
	}
	set method(method) {
		this.set_stun_type(this.class, method);
	}
	get txid() {
		if (!this.is_stun) throw new Error('Not of type STUN');
		return new Uint8Array(this.buffer, this.byteOffset + 8, 12);
	}
	get attrs() {
		if (this.#attrs) return this.#attrs;
		if (!this.is_stun) throw new Error('Not of type STUN');

		this.#attrs = new Map();

		let packet_length = Math.min(20 + this.length, this.byteLength);
		while (packet_length % 4) packet_length -= 1;

		for (let i = 20; i < packet_length;) {
			const attr_type = this.getUint16(i);
			const attr_len = this.getUint16(i + 2);
			i += 4;
			if (i + attr_len > packet_length) break;
			this.length = (i - 20 + attr_len);

			const value = new DataView(this.buffer, this.byteOffset + i, attr_len);
			i += attr_len;
			while (i % 4) i += 1;
			
			if (!this.#attrs.has(attr_type)) {
				this.#attrs.set(attr_type, value);
			}
			if (attr_type == 0x0008 || attr_type == 0x8028) break;
		}

		return this.#attrs;
	}
	add_attribute(type, length) {
		if (!this.is_stun) throw new Error("Type is not STUN");

		const i = this.packet_length;
		this.length += 4 + length;
		this.setUint16(i, type);
		this.setUint16(i + 2, length);

		return new DataView(this.buffer, i + 4, length);
	}
	get_buffer_attr(type) {
		const view = this.attrs.get(type);
		if (view) return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
	}
	set_buffer_attr(type, value) {
		const view = this.add_attribute(type, value.byteLength);
		if (value instanceof ArrayBuffer) value = new Uint8Array(value);
		new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
			.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
	}
	get_text_attr(type) {
		const view = this.attrs.get(type);
		if (view) return decoder.decode(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
	}
	set_text_attr(type, value) {
		this.set_buffer_attr(type, encoder.encode(String(value)));
	}
	get_addr_attr(type, { transport = 'udp', xor = true } = {}) {
		const view = this.attrs.get(type);
		if (view?.byteLength < 8) return;
		const family = view.getUint8(1);
		let port = view.getUint16(2);
		let addr_bytes = new Uint8Array(view.buffer, view.byteOffset + 4, view.byteLength - 4);
		if (xor) {
			port = port ^ 0x2112;
			addr_bytes = addr_bytes.map((v, i) => v ^ this.getUint8(4 + i));
		}
		let hostname = '';
		if (family == 0x01) {
			if (addr_bytes.byteLength != 4) return;
			hostname = addr_bytes.join('.');
		} else if (family == 0x02) {
			if (addr_bytes.byteLength != 16) return;
			const view = new DataView(addr_bytes.buffer, addr_bytes.byteOffset, addr_bytes.byteLength);
			for (let i = 4; i < 20; i += 2) {
				if (!hostname) hostname += ':';
				hostname += view.getUint16(i).toString(16);
			}
		} else {
			return;
		}
		return { hostname, port, transport };
	}
	set_addr_attr(type, value, { xor = true } = {}) {
		let { hostname, port = 80 } = value;
		let ip_bytes = parse_ipaddr(hostname);

		if (xor) {
			port = port ^ 0x2112;
			ip_bytes = ip_bytes.map((v, i) => v ^ this.getUint8(4 + i));
		}
		const family = (ip_bytes.byteLength == 4) ? 0x01 : 0x02;
		const view = this.add_attribute(type, 4 + ip_bytes.byteLength);
		view.setUint8(0, 0);
		view.setUint8(1, family);
		view.setUint16(2, port);
		new Uint8Array(view.buffer, view.byteOffset + 4).set(ip_bytes);
	}

	// STUN Auth
	async check_auth(cmOrKey) {
		const key = (cmOrKey instanceof CryptoKey) ? cmOrKey : await cmOrKey.credential(this.username, this.realm);
		if (!key) return false;

		const mac = this.integrity;
		if (!mac) return false;

	}
	async add_auth(cmOrKey) {

	}
	
	// STUN Attribute getters/setters
	// Attributes: (TODO: DRY)
	get username() {
		return this.get_text_attr(0x0006);
	}
	set username(value) {
		this.set_text_attr(0x0006, value);
	}
	get realm() {
		return this.get_text_attr(0x0014);
	}
	set realm(value) {
		this.set_text_attr(0x0014, value);
	}
	get nonce() {
		return this.get_text_attr(0x0015);
	}
	set nonce(value) {
		this.set_text_attr(0x0015, value);
	}
	get error() {
		const view = this.attr.get(0x0009);
		if (view?.byteLength < 4) return undefined;
		const code = view.getUint8(2) * 100 + view.getUint8(3);
		const reason = decoder.decode(new Uint8Array(view.buffer, view.byteOffset + 4, view.byteLength - 4));
		return { code, reason };
	}
	set error(error) {
		let { code = 404, reason = '' } = error;
		reason = encoder.encode(reason);
		const view = this.add_attribute(0x0009, 4 + reason.byteLength);
		view.setUint16(0, 0);
		view.setUint8(2, Math.trunc(code / 100));
		view.setUint8(3, code % 100);
		new Uint8Array(view.buffer, view.byteOffset + 4, reason.byteLength).set(reason);
	}
	get data() {
		return this.get_buffer_attr(0x0013);
	}
	set data(value) {
		this.set_buffer_attr(0x0013, value);
	}
	get integrity() {
		return this.get_buffer_attr(0x0008);
	}
	get mapped() {
		return this.get_addr_attr(0x0001, {xor: false});
	}
	set mapped(value) {
		this.set_addr_attr(0x0001, value, {xor: false});
	}
	get xmapped() {
		return this.get_addr_attr(0x0020);
	}
	set xmapped(value) {
		this.set_addr_attr(0x0020, value);
	}
	get xpeer() {
		return this.get_addr_attr(0x0012);
	}
	set xpeer(value) {
		this.set_addr_attr(0x0012, value);
	}
	get xrelay() {
		return this.get_addr_attr(0x0016);
	}
	set xrelay(value) {
		this.set_addr_attr(0x0016, value);
	}
	get lifetime() {
		const view = this.attrs.get(0x000d);
		if (view?.byteLength != 4) return undefined;
		return view.getUint32(0);
	}
	set lifetime(value) {
		const view = this.add_attribute(0x000d, 4);
		view.setUint32(0, value);
	}

	static async *parse(readable_stream, {maxByteLength = 4096} = {}) {
		const reader = readable_stream.getReader({mode: 'byob'});

		let buffer = new ArrayBuffer(100, {maxByteLength});
		let available = 0;
		let ended = false;
		while (1) {
			const turn = new this(buffer, 0, available);
			const framed = turn.framed_packet_length;
			if (available >= framed) {
				// Yield the turn message:
				yield turn;

				// Shift any unused data to the front of the buffer
				new Uint8Array(buffer).copyWithin(0, framed, available);
				available -= framed;

				// Continue yielding TURN messages until we've used up everything available
				continue;
			}
			else if (framed > buffer.byteLength) {
				if (buffer.resizable && buffer.maxByteLength >= framed) buffer.resize(framed);
				else break;
			}
			
			if (ended) break;
			const {value, done} = await reader.read(new Uint8Array(buffer, available));
			if (value) {
				buffer = value.buffer;
				available += value.byteLength;
			}
			ended = done;
		}
	}
}
