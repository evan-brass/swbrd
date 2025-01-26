import { Ip6, parse_ipaddr } from "./ipaddr.js";
import { decoder_lossy, encoder } from "./util.js";
import { Stun, Class, Method, Attr, AttrType, MAGIC_COOKIE } from "./stun.js";

if (import.meta.main) {
	const none = encoder.encode('none');
	const [turnKey, iceKey] = await Promise.all([
		[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173],
		[116, 104, 101, 47, 105, 99, 101, 47, 112, 97, 115, 115, 119, 111, 114, 100, 47, 99, 111, 110, 115, 116, 97, 110, 116]
	].map(v => crypto.subtle.importKey('raw', new Uint8Array(v), {
		name: 'HMAC', hash: 'SHA-1'
	}, true, ['sign', 'verify'])));
	const default_lifetime = 6000;

	const sock = Deno.listenDatagram({ port: 3478, hostname: '::', transport: 'udp' });
	const buffer = new Uint8Array(2048);
	packet_loop: for (; ;) {
		const [{ byteLength }, { hostname, port }] = await sock.receive(buffer);
		const msg = new Stun(buffer);
		if (msg.byteLength != byteLength) continue;
		const sender = parse_ipaddr(hostname);
		const canonical = sender.canonical();
		let receiver = { hostname, port };

		const [
			[username, realm, nonce],
			[], [],
		] = msg.parse([
			[AttrType.Username, 'text'],
			[AttrType.Realm, 'text'],
			[AttrType.Nonce, 'text'],
		], [AttrType.Integrity], [AttrType.Fingerprint]);

		// Send Indications
		if (msg.class == Class.Ind && msg.method == Method.Send) {
			let [[
				data,
				peer
			],
				unknown
			] = msg.parse([
				[AttrType.Data],
				[AttrType.Peer, 'addr']
			]);
			if (unknown.length) { debugger; continue packet_loop; }
			if (!(peer?.ip instanceof Ip6) || !data?.byteLength) { debugger; continue packet_loop; }

			msg.method = Method.Data;
			const broadcast = new Ip6(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff);

			// Shift the data Attribute to the beginning of the message:
			msg.length = 0;
			buffer.copyWithin(Stun.minByteLength + Attr.minByteLength + 20 + Attr.minByteLength, data.byteOffset, data.byteLength);

			// Swap the sender and peer, unless hosted:
			if (peer.ip.every((v, i) => broadcast[i] == v)) {
				msg.append(AttrType.Peer, 'addr', { ip: broadcast, port: peer.port });
			} else {
				msg.append(AttrType.Peer, 'addr', { ip: sender, port });
				receiver = { hostname: String(peer.ip), port: peer.port };
			}

			// Append the data attribute (We only need to assign the length, because the data is already in place.)
			msg.append(AttrType.Data, data.byteLength);

			// Peek inside the packet:
			// hosted: {
			// 	if (data[0] < 20) /* STUN */ {
			// 		const inner = new Stun(data);

			// 		// Only support ICE:
			// 		if (inner.method != Method.Binding) { debugger; continue packet_loop; }
			// 		if (inner.cookie != MAGIC_COOKIE) { debugger; continue packet_loop; }

			// 		// Connection Test requests:
			// 		if (inner.class == Class.Req) {
			// 			const [[
			// 				username,
			// 				priority,
			// 				iceControlled,
			// 				iceControlling,
			// 				useCandidate,
			// 			], [integrity], [fingerprint], unknown] = inner.parse([
			// 				[AttrType.Username, 'text'],
			// 				[AttrType.Priority, 'u32'],
			// 				[AttrType.IceControlled, 'u64'],
			// 				[AttrType.IceControlling, 'u64'],
			// 				[AttrType.UseCandidate, 'bool'],
			// 			], [[AttrType.Integrity]], [[AttrType.Fingerprint]]);

			// 			if (!username || !priority || integrity?.length == 20 || fingerprint?.length == 4 || (!iceControlled && !iceControlling) || (iceControlled && iceControlling)) {
			// 				debugger; continue packet_loop;
			// 			}

			// 			console.log('ice', username, priority, useCandidate ? true : false);
			// 		}

			// 		// Connection Test responses
			// 		else if (inner.class != Class.Ind) {
			// 			const [[
			// 				mapped,
			// 				error,
			// 			], [integrity], [fingerprint], unknown] = inner.parse([
			// 				[AttrType.Mapped, 'addr'],
			// 				[AttrType.Error],
			// 			], [[AttrType.Integrity]], [[AttrType.Fingerprint]]);
			// 			if (unknown.length) { debugger; continue packet_loop; }
			// 		}

			// 		// Connection Test Indications??
			// 		else { continue packet_loop; }
			// 	}
			// 	else if (data[0] < 64) /* DTLS */ {
			// 		console.log('dtls', data);
			// 		break hosted;
			// 	}
			// 	else /* SRTP, Etc. */ {
			// 		break hosted;
			// 	}
			// }
		}

		// Drop all other Indications or Responses
		else if (msg.class != Class.Req) {
			continue packet_loop;
		}

		// Binding Requests
		else if (msg.method == Method.Binding) {
			msg.length = 0;
			msg.class = Class.Suc;
			msg.append(AttrType.Mapped, 'addr', { ip: canonical, port });
		}

		// All other requests require Authentication
		else if (username != 'guest' || realm != 'none' || nonce != 'none' || !await msg.verify(turnKey)) {
			msg.class = Class.Err;
			msg.length = 0;
			msg.append(AttrType.Error, 4, [0, 0, 4, 1]);
			msg.append(AttrType.Realm, 'text', 'none');
			msg.append(AttrType.Nonce, 'text', 'none');
		}

		// Allocate Requests
		else if (msg.method == Method.Allocate) {
			const [[
				lifetime,
				requestedTransport,
			], [],
				unknown
			] = msg.parse([
				[AttrType.Lifetime, 'u32'],
				[AttrType.RequestedTransport, 'fucky_u8'],
				[AttrType.Username], [AttrType.Nonce], [AttrType.Realm],
			], [[AttrType.Integrity]]);
			if (unknown.length) { debugger; continue packet_loop; }
			if (requestedTransport != 17 /* UDP */) { debugger; continue packet_loop; }
			msg.class = Class.Suc;
			msg.length = 0;

			msg.append(AttrType.Mapped, 'addr', { ip: canonical, port });
			msg.append(AttrType.Relayed, 'addr', { ip: sender, port });
			msg.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime);
			await msg.sign(turnKey);
			console.assert(await msg.verify(turnKey), 'signature error');
		}

		// Refresh Request
		else if (msg.method == Method.Refresh) {
			const [[
				lifetime,
			], [],
				unknown
			] = msg.parse([
				[AttrType.Lifetime, 'u32'],
				[AttrType.Username], [AttrType.Nonce], [AttrType.Realm],
			], [[AttrType.Integrity]]);
			if (unknown.length) { debugger; continue packet_loop; }
			if (lifetime === 0) continue packet_loop; // Close notification, don't respond
			msg.class = Class.Suc;
			msg.length = 0;
			msg.append(AttrType.Lifetime, 'u32', lifetime || default_lifetime);
			await msg.sign(turnKey);
		}

		// Create Permission Request
		else if (msg.method == Method.CreatePermission) {
			msg.class = Class.Suc;
			msg.length = 0;
			await msg.sign(turnKey);
		}

		// Channel Bind Request
		else if (msg.method == Method.ChannelBind) {
			msg.class = Class.Err;
			msg.length = 0;
			msg.append(AttrType.Error, 4, [0, 0, 4, 38]);
			await msg.sign(turnKey);
		}

		// Drop all other requests
		else { continue packet_loop; }

		try {
			await sock.send(buffer.subarray(0, msg.byteLength), receiver);
		} catch (e) { console.warn(e); }
	}
}
