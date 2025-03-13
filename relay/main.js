import { Ip6, parse_ipaddr } from '../src/ipaddr.js';
import { Stun, Class, Method, Attr, AttrType } from '../src/stun.js';
import { write } from '../src/util.js';

if (!import.meta.main) throw new Error("swbrd library code is in src");

const key_params = [
	{
		name: 'HMAC',
		hash: 'SHA-1',
	},
	true,
	['sign', 'verify'],
];
const turnKey = await crypto.subtle.importKey(
	'raw',
	new Uint8Array(
		// MD5(guest:none:password)
		[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173],
	),
	...key_params,
);
const default_lifetime = 6000;
const broadcast = new Ip6(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff);

const all = new Map();

function make_key(ip, port) {
	return `[${ip}]:${port}`;
}

class Turn {
	ip;
	port;
	writer;
	mappings;
	constructor(conn) {
		conn.setNoDelay(true);
		this.writer = conn.writable.getWriter();
		this.ip = parse_ipaddr(conn.remoteAddr.hostname);
		this.port = conn.remoteAddr.port;

		const key = make_key(this.ip, this.port);
		all.set(key, this);
		this.#handle(conn.readable).finally(() => all.delete(key));
	}
	async #handle_msg(msg) {
		const ret = new Stun(new ArrayBuffer(100)); // All fixed-length responses have a maximum length of 100 bytes
		ret.class = Class.Suc;
		ret.method = msg.method;
		ret.length = 0;
		ret.cookie = msg.cookie;
		ret.txid = msg.txid;

		// Parse STUN Attributes
		const [
			[
				// Allocate / Refresh / CreatePermission / ChannelBind
				username, realm, nonce,
				// Allocate
				requestedTransport,
				// Allocate / Refresh
				lifetime,
				// Send / CreatePermission / ChannelBind
				peer,
				// Send
				data,
				// ChannelBind
				_channel,
			],
			[_integrity],
			[fingerprint],
			unknown
		] = msg.parse(
			[
				[AttrType.Username, 'text'],
				[AttrType.Realm, 'text'],
				[AttrType.Nonce, 'text'],
				[AttrType.RequestedTransport, 'fucky_u8'],
				[AttrType.Lifetime, 'u32'],
				[AttrType.Peer, 'addr'],
				[AttrType.Data],
				[AttrType.ChannelNumber, 4],
			],
			[[AttrType.Integrity, 20]],
			[[AttrType.Fingerprint, 'u32']],
		);

		// Drop anything with unknown comprehension required attributes
		if (unknown.length) return;

		// Send Indications
		else if (msg.class == Class.Ind && msg.method == Method.Send) {
			if (!(peer?.ip instanceof Ip6) || !data?.byteLength) return;
			const is_broadcast = peer.ip.every((v, i) => broadcast[i] == v);

			// Send indications get modified in place and then relayed
			msg.method = Method.Data;
			const offset = Stun.minByteLength + Attr.minByteLength + 20 +
				Attr.minByteLength;
			const length = data.byteLength;

			// TODO: I honestly have no clue why the following line works...  Surely it's missing a msg.byteOffset somewhere, and why the hell is length in the ending index position?
			new Uint8Array(msg.buffer).copyWithin(offset, data.byteOffset, length);
			// const moved_data = new Uint8Array(msg.buffer, offset, length);

			const relay = async turn => {
				let peer;
				if (Array.isArray(turn.mappings)) {
					let self_port = 1 + turn.mappings.indexOf(this);
					if (self_port == 0) {
						if (turn.mappings.length >= 2000) return;
						turn.mappings.push(this);
						self_port = turn.mappings.length;
					}
					peer = { ip: broadcast, port: self_port };
				}
				else {
					peer = { ip: this.ip, port: this.port };
				}
				msg.length = 0;
				msg.append(AttrType.Peer, 'addr', peer);
				msg.append(AttrType.Data, length);
				await write(turn.writer, new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength));
			};

			// Broadcast
			if (is_broadcast && peer.port == 65535) {
				/**
				 * HACK: Needed because Firefox enforces TURN permissions locally.
				 * This means that it cannot receive packets from ips which it has not
				 * granted permission too.  It can however receive from unexpected ports
				 * so we map all peer ip+ports to an assigned port at a known ip.
				 * This is unneccessary state and we only have 2000 slots available, so
				 * we only perform this mapping for Firefox and not for Chrome.
				 *
				 * Also, once the connection opens and you trickle true ICE candidates,
				 * those will have proper permissions, and thus will not hit this mapping.
				 *
				 * ISSUE: https://bugzilla.mozilla.org/show_bug.cgi?id=1952664
				 */
				if (fingerprint) this.mappings ??= [];

				for (const turn of all.values()) {
					if (turn == this) continue;
					await relay(turn);
				}
			}

			// Unicast Mapped
			else if (is_broadcast) {
				const turn = this.mappings[peer.port - 1];
				if (!turn) return;
				await relay(turn);
			}

			// Unicast Transparent
			else {
				const key = make_key(peer.ip, peer.port);
				const turn = all.get(key);
				if (!turn) return;
				await relay(turn);
			}

			// We just performed a relay, so don't respond with anything.
			return;
		}

		// Drop all other non-requests
		else if (msg.class != Class.Req) return;

		// Binding Requests
		else if (msg.method == Method.Binding) {
			ret.append(AttrType.Mapped, 'addr', {ip: this.ip.canonical(), port: this.port});
		}

		// Check username, realm, and nonce
		else if (username != 'guest' || realm != 'none' || nonce != 'none') {
			ret.class = Class.Err;
			ret.append(AttrType.Error, 4, [0, 0, 4, 1]);
			ret.append(AttrType.Realm, 'text', 'none');
			ret.append(AttrType.Nonce, 'text', 'none');
		}

		// All other requests require valid integrity
		else if (!await msg.verify(turnKey)) {
			ret.class = Class.Err;
			ret.append(AttrType.Error, 4, [0, 0, 4, 3]);
		}

		// Allocate
		else if (msg.method == Method.Allocate) {
			if (requestedTransport != 17 /* UDP */) return;
			ret.append(AttrType.Mapped, 'addr', {ip: this.ip.canonical(), port: this.port});
			ret.append(AttrType.Relayed, 'addr', {ip: this.ip, port: this.port});
			ret.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime)
			await ret.sign(turnKey);
		}

		// Refresh
		else if (msg.method == Method.Refresh) {
			if (lifetime == 0) return; // Close notification -> don't respond
			ret.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime);
			await ret.sign(turnKey);
		}

		// Create Permission
		else if (msg.method == Method.CreatePermission) {
			await ret.sign(turnKey);
		}

		// Channel Bind
		else if (msg.method == Method.ChannelBind) {
			ret.class = Class.Err;
			ret.append(AttrType.Error, 4, [0, 0, 4, 38]);
			await ret.sign(turnKey)
		}

		// Drop all other requests
		else return;

		// Send the response
		await write(this.writer, new Uint8Array(ret.buffer, ret.byteOffset, ret.byteLength));
	}
	async #handle(readable) {
		const maxByteLength = 4096;
		// FUCK: Deno's Conn is taking my resiziable buffer and returning a non-resiziable one... So we need to resize the buffer manually
		let buffer = new ArrayBuffer(40);
		const reader = readable.getReader({ mode: 'byob' });

		let available = 0;
		for (;;) {
			try {
				const {value, done} = await reader.read(new Uint8Array(buffer, available));
				if (value) {
					buffer = value.buffer; // The stream apis detach buffers alot (so that they can be in different workers)
					available += value.byteLength;

					const msg = new Stun(buffer);
					const msg_byteLength = msg.byteLength;
					// Check if the message exceeds our max buffer size:
					if (msg_byteLength > maxByteLength) break;

					// Resize the buffer if needed:
					else if (msg_byteLength > buffer.byteLength) {
						// Transfer to a larger buffer
						buffer = buffer.transfer(msg_byteLength);
					}

					// If we have enough data available for this message, then consume it:
					else if (msg_byteLength <= available) {
						await this.#handle_msg(msg);

						// Shift the data in the buffer:
						new Uint8Array(buffer).copyWithin(0, msg_byteLength, available);
						available -= msg_byteLength;
					}
				}
				if (done) break;
			} catch (e) {
				console.warn(e);
				break;
			}
		}
	}
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	console.log('new', conn.remoteAddr.hostname, conn.remoteAddr.port, 'existing', all.size);
	new Turn(conn);
}
