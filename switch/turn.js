import { parse_ipaddr } from "./ipaddr.js";
import { Stun, Class, Method } from './stun.js';
import { long_term, realm } from "./auth.js";
import { Protocol } from "./proto.js";

export const allocations = new Map();
const fake_ip = new Uint8Array([169, 254, 255, 255]);
function is_fake(ip) {
	return (ip instanceof fake_ip.constructor) && fake_ip.length == ip.length && fake_ip.every(
		(v, i) => v == ip[i]
	);
}
const min_port = 49152, max_port = 65535;
const max_allocations = max_port - min_port;
let port = min_port;
function allocate() {
	if (allocations.size >= max_allocations) return;
	while (allocations.has(port)) {
		port += 1;
		if (port > max_port) port = min_port;
	}
	return port;
}

const maxByteLength = 2**13;

// This common indication buffer is shared by all of the TurnConns to relay data
const indication = new Stun(new ArrayBuffer(40, {maxByteLength}));
indication.class = Class.indication; indication.method = Method.data;

export class TurnConn extends Protocol {
	#xmapped;
	#xrelayed;
	#long_key;
	#channels = new Map();
	#recv;
	#available = 0;
	#send;
	constructor(inner) {
		super(inner, {mode: 'byob'});
		this.#xmapped = { ip: parse_ipaddr(inner.remoteAddr.hostname), port: inner.remoteAddr.port };
		this.#recv = new ArrayBuffer(40, {maxByteLength});
		this.#send = new ArrayBuffer(40, {maxByteLength});
	}
	get remoteAddr() {
		return { ip: fake_ip, port: this.#xrelayed };
	}
	async pull(controller) {
		for (;;) {
			let frame;
			try {
				const {value, done} = await super.read(new Uint8Array(this.#recv, this.#available));
				if (done) { controller.close(); break; }
				this.#available += value.byteLength; this.#recv = value.buffer;
	
				const res = parse(new Uint8Array(this.#recv, 0, this.#available));
				if (typeof res == 'number') {
					// Try to resize recv to accomodate the required size:
					if (res > this.#recv.maxByteLength) controller.error(new Error("Frame would be too big to fit into our recv buffer."));
					this.#recv.resize(res);
					continue;
				}
				frame = res;
			} catch { controller.close(); break; }

			try {
				// Handle the TURN frame
				if (frame instanceof Stun && frame.class == Class.request) {
					const response = new Stun(this.#send);
					response.method = frame.method;
					response.length = 0;
					response.txid.set(frame.txid);
		
					if (frame.method == Method.binding) {
						response.class = Class.success;
						response.xmapped = this.#xmapped;
					}
					else if (!frame.username || frame.nonce != 'none' || frame.realm != realm) {
						response.class = Class.error; response.errcode = 401;
						response.nonce = 'none'; response.realm = 'none';
					}
					else if (frame.method == Method.allocate) {
						this.#long_key ??= await long_term(frame.username);
						if (await frame.verify(this.#long_key)) {
							this.#xrelayed ??= allocate(this);
							if (!this.#xrelayed) {
								response.class = Class.error; response.errcode = 508;
							}
							else {
								allocations.set(this.#xrelayed, this);
								response.class = Class.success;
								response.xmapped = this.#xmapped;
								response.xrelayed = { ip: fake_ip, port: this.#xrelayed };
								response.lifetime = frame.lifetime || 3600;
							}
						} else {
							response.class = Class.error; response.errcode = 403;
						}
					}
					else if (!this.#long_key) {
						response.class = Class.error; response.errcode = 403;
					}
					else if (frame.method == Method.createPermission) {
						response.class = Class.success;
					}
					else if (frame.method == Method.channelBind) {
						if (frame.xpeer?.ip instanceof fake_ip.constructor && !fake_ip.every((v, i) => v == frame.xpeer.ip[i])) {
							response.class = Class.error; response.errcode = 403;
						}
						else if (this.#channels.szie >= 5) {
							response.class = Class.error; response.errcode = 508;
						}
						else {
							this.#channels.set(frame.channel, frame.xpeer.port);
							response.class = Class.success;
						}
					}
					else if (frame.method == Method.refresh) {
						response.class = Class.success;
					}
					else {
						response.class = Class.error; response.errcode = 404;
					}
		
					if (this.#long_key) await response.sign(this.#long_key);
					if (frame.fingerprint) response.fingerprint = true;
		
					await this.write(response);
				}
				else if (
					this.#xrelayed && (
						frame instanceof ChannelData &&
						this.#channels.has(frame.channel)
					) || (
						frame instanceof Stun &&
						frame.class == Class.indication && frame.method == Method.send &&
						is_fake(frame.xpeer?.ip)
					)
				) {
					const port = frame instanceof ChannelData ? this.#channels.get(frame.channel) : frame.xpeer.port;
					const data = frame.data;
					const uni = allocations.get(port);
					if (uni) {
						// Relay the packet:
						await uni.write(data, {xpeer: {ip: fake_ip, port: this.#xrelayed}});
					} else {
						// Pass the data up to the parent
						if (controller.byobRequest) {
							new Uint8Array(
								controller.byobRequest.view.buffer,
								controller.byobRequest.view.byteOffset,
								controller.byobRequest.view.byteLength
							).set(data);
							controller.byobRequest.respond(Math.min(controller.byobRequest.view.byteLength, data.byteLength));
						} else {
							controller.enqueue(data.slice());
						}
						return;
					}
				}
			} finally {
				// Shift unused data to the front of the buffer
				this.#available -= frame.needed;
				new Uint8Array(this.#recv, 0).set(new Uint8Array(this.#recv, frame.needed));
			}
		}
	}

	// WritableStream
	async write(chunk, {xpeer = {ip: fake_ip, port: 4666}} = {}) {
		// TODO: Limit the # of bytes sent to not exceed the # of bytes received
		// TODO: Cap bandwidth

		await super.write(chunk, { map(chunk) {
			if (!(chunk instanceof Stun || chunk instanceof ChannelData)) {
				indication.length = 0;
				crypto.getRandomValues(indication.txid); indication.magic = true;
				indication.xpeer = xpeer;
				indication.data = chunk;
				return indication.frame;
			} else {
				return chunk.frame;
			}
		}});
	}
}

export class ChannelData extends DataView {
	get channel() {
		return this.getUint16(0);
	}
	set channel(value) {
		this.setUint16(0, value);
	}
	get length() {
		return this.getUint16(2);
	}
	set length(len) {
		let packet_len = 4 + len;
		while (packet_len % 4 != 0) packet_len += 1;
		if (packet_len > this.byteLength) this.buffer.resize(this.byteOffset + packet_len);
		this.setUint16(2, len);
	}
	get needed() {
		if (this.byteLength < 4) return 4;
		if (this.channel < 0x4000) return Infinity;
		if (this.channel < 0x8000) {
			let ret = 4 + this.length;
			while (ret % 4 != 0) ret += 1;
			return ret;
		}
		return Infinity;
	}
	get frame() {
		return new Uint8Array(this.buffer, this.byteOffset, this.needed);
	}
	get data() {
		return new Uint8Array(this.buffer, this.byteOffset + 4, this.length);
	}
}

export function parse(data) {
	const stun = new Stun(data.buffer, data.byteOffset, data.byteLength);
	const channel = new ChannelData(data.buffer, data.byteOffset, data.byteLength);
	const needed = Math.min(stun.needed, channel.needed);
	if (data.byteLength < needed) {
		return needed;
	}
	else if (stun.needed < Infinity) {
		return stun;
	}
	else if (channel.needed < Infinity) {
		return channel;
	}
}
