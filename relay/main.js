import { Ip6, parse_ipaddr } from '../src/ipaddr.js';
import { Attr, AttrType, Class, MAGIC_COOKIE, Method, Stun } from '../src/stun.js';

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

const sock = Deno.listenDatagram({
	port: 3478,
	hostname: '::',
	transport: 'udp',
});
const buffer = new Uint8Array(2048);
packet_loop: for (; ;) {
	const [{ byteLength }, { hostname, port }] = await sock.receive(buffer);
	const msg = new Stun(buffer);
	if (msg.byteLength != byteLength) continue;
	const sender = parse_ipaddr(hostname);
	const canonical = sender.canonical();
	let receiver = { hostname, port };

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
		[_fingerprint],
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

	// Anything with unknown attributes
	if (unknown.length) {
		console.warn('dropping', unknown);
		continue packet_loop;
	}
	// Send Indications
	else if (msg.class == Class.Ind && msg.method == Method.Send) {
		if (!(peer?.ip instanceof Ip6) || !data?.byteLength) continue packet_loop;
		msg.method = Method.Data;
		const is_broadcast = peer.ip.every((v, i) => broadcast[i] == v);

		// Shift the data attribute to where it needs to be
		msg.length = 0;
		const offset = Stun.minByteLength + Attr.minByteLength + 20 +
			Attr.minByteLength;
		const length = data.byteLength;
		buffer.copyWithin(offset, data.byteOffset, length);
		const moved_data = new Uint8Array(buffer.buffer, offset, length);

		// Append the peer attribute and update the receiver
		msg.append(AttrType.Peer, 'addr', { ip: sender, port });
		receiver = { hostname: String(peer.ip), port: peer.port };

		// Peek inside the packet:
		hosted: if (is_broadcast) {
			// Check if this is an ICE connection test
			const inner = new Stun(moved_data);
			if (inner.byteLength != length) break hosted;
			if (inner.class != Class.Req) break hosted;
			if (inner.method != Method.Binding) break hosted;
			if (inner.cookie != MAGIC_COOKIE) break hosted;

			const [
				[
					username,
					priority,
					iceControlled,
					iceControlling,
					_useCandidate,
				],
				[integrity],
				[fingerprint],
				unknown,
			] = inner.parse(
				[
					[AttrType.Username, 'text'],
					[AttrType.Priority, 'u32'],
					[AttrType.IceControlled, 'u64'],
					[AttrType.IceControlling, 'u64'],
					[AttrType.UseCandidate, 'bool'],
				],
				[[AttrType.Integrity, 20]],
				[[AttrType.Fingerprint, 'u32']],
			);
			if (
				unknown.length ||
				!username || !priority || !integrity || !fingerprint ||
				(typeof iceControlled == typeof iceControlling) ||
				(typeof iceControlled != 'bigint' && typeof iceControlling != 'bigint')
			) {
				break hosted;
			}

			// Truncate the ICE connection test to the integrity attr
			inner.length = (integrity.byteOffset - inner.byteOffset) - Stun.minByteLength + 20;
			inner.append(AttrType.Peer, 'addr', {ip: sender, port});

			// TODO: ipc this to a webrtc implementation
			const _test = buffer.subarray(inner.byteOffset, inner.byteOffset + inner.byteLength);
		}
		// NOTE: Currently packets sent to ::ffff:255.255.255.255 will try to be sent, and then immediately dropped by the OS.  I'm leaving this in because I think it might be a useful method of ipc instead of using a named pipe or something.  I'm still not sure if having a process boundary is the right way to go.  It would be nice to be able to restart hosted peers without restarting the relay server.

		// Append the data attribute (We only need to assign the length, because the data is already in position.)
		msg.append(AttrType.Data, length);
	} // Drop all other Indications or Responses
	else if (msg.class != Class.Req) {
		continue packet_loop;
	} // Binding Requests
	else if (msg.method == Method.Binding) {
		msg.length = 0;
		msg.class = Class.Suc;
		msg.append(AttrType.Mapped, 'addr', { ip: canonical, port });
	} // Check the username, realm, and nonce
	else if (username != 'guest' || realm != 'none' || nonce != 'none') {
		msg.class = Class.Err;
		msg.length = 0;
		msg.append(AttrType.Error, 4, [0, 0, 4, 1]);
		msg.append(AttrType.Realm, 'text', 'none');
		msg.append(AttrType.Nonce, 'text', 'none');
	} // All other requests require Authentication
	else if (!await msg.verify(turnKey)) {
		msg.class = Class.Err;
		msg.length = 0;
		msg.append(AttrType.Error, 4, [0, 0, 4, 3]);
	} // Allocate Requests
	else if (msg.method == Method.Allocate) {
		if (requestedTransport != 17 /* UDP */) {
			continue packet_loop;
		}
		msg.class = Class.Suc;
		msg.length = 0;

		msg.append(AttrType.Mapped, 'addr', { ip: canonical, port });
		msg.append(AttrType.Relayed, 'addr', { ip: sender, port });
		msg.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime);
		await msg.sign(turnKey);
		console.assert(await msg.verify(turnKey), 'signature error');
	} // Refresh Request
	else if (msg.method == Method.Refresh) {
		if (lifetime === 0) continue packet_loop; // Close notification -> don't respond
		msg.class = Class.Suc;
		msg.length = 0;
		msg.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime);
		await msg.sign(turnKey);
	} // Create Permission Request
	else if (msg.method == Method.CreatePermission) {
		msg.class = Class.Suc;
		msg.length = 0;
		await msg.sign(turnKey);
	} // Channel Bind Request
	else if (msg.method == Method.ChannelBind) {
		msg.class = Class.Err;
		msg.length = 0;
		msg.append(AttrType.Error, 4, [0, 0, 4, 38]);
		await msg.sign(turnKey);
	} // Drop all other requests
	else continue packet_loop;

	try {
		await sock.send(buffer.subarray(0, msg.byteLength), receiver);
	} catch (e) {
		console.warn(e);
	}
}
