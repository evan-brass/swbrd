import { Dtls, Handshake } from "./dtls.js";
import { Ip6, parse_ipaddr } from "./ipaddr.js";
import { Stun, Class, Method, Attr, AttrType, MAGIC_COOKIE } from "./stun.js";

if (import.meta.main) {
	const key_params = [
		{
			name: 'HMAC', hash: 'SHA-1'
		},
		true,
		['sign', 'verify']
	];
	const turnKey = await crypto.subtle.importKey('raw', new Uint8Array(
		[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173]
	), ...key_params);
	const default_lifetime = 6000;

	// ufrag -> ice key or dtls session
	const peers = new Map();
	peers.set(
		'ucCm6JK3s22XuCRiTZVFpWajUq0tIpB7lDn1Sv8dRv3',
		await crypto.subtle.importKey('raw', new Uint8Array(
			[116, 104, 101, 47, 105, 99, 101, 47, 112, 97, 115, 115, 119, 111, 114, 100, 47, 99, 111, 110, 115, 116, 97, 110, 116]
		), ...key_params)
	);

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
		], [[AttrType.Integrity, 20]], [[AttrType.Fingerprint, 4]]);

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
			const is_broadcast = peer.ip.every((v, i) => broadcast[i] == v);

			// Shift the data Attribute to the beginning of the message:
			msg.length = 0;
			const offset = Stun.minByteLength + Attr.minByteLength + 20 + Attr.minByteLength;
			let length = data.byteLength;
			buffer.copyWithin(offset, data.byteOffset, length);
			data = new Uint8Array(buffer.buffer, offset, length);

			// Swap the sender and peer, unless hosted:
			if (is_broadcast) {
				msg.append(AttrType.Peer, 'addr', { ip: broadcast, port: peer.port });
			} else {
				msg.append(AttrType.Peer, 'addr', { ip: sender, port });
				receiver = { hostname: String(peer.ip), port: peer.port };
			}

			// Peek inside the packet:
			hosted: {
				if (data[0] < 20) /* STUN */ {
					const inner = new Stun(data);
					if (inner.byteLength != length) { debugger; continue packet_loop; };

					// Only relay ICE packets:
					if (inner.method != Method.Binding) { debugger; continue packet_loop; }
					if (inner.cookie != MAGIC_COOKIE) { debugger; continue packet_loop; }

					// Connection Test requests:
					if (inner.class == Class.Req) {
						const [[
							username,
							priority,
							iceControlled,
							iceControlling,
							useCandidate,
						], [integrity], [fingerprint], unknown] = inner.parse([
							[AttrType.Username, 'text'],
							[AttrType.Priority, 'u32'],
							[AttrType.IceControlled, 'u64'],
							[AttrType.IceControlling, 'u64'],
							[AttrType.UseCandidate, 'bool'],
						], [[AttrType.Integrity, 20]], [[AttrType.Fingerprint, 4]]);

						if (!username || !priority || !integrity || !fingerprint || (!iceControlled && !iceControlling) || (iceControlled && iceControlling)) {
							debugger; continue packet_loop;
						}

						const [dst_ufrag, src_ufrag] = username.split(':');
						if (!dst_ufrag || !src_ufrag) { debugger; continue packet_loop; }

						//
						if (is_broadcast) {
							const entry = peers.get(dst_ufrag);

							if (entry instanceof CryptoKey) {
								if (!is_broadcast) { debugger; continue packet_loop; }

								// Wrong ICE password
								if (!await inner.verify(entry)) {
									inner.length = 0;
									inner.class = Class.Err;
									inner.append(AttrType.Error, 4, [0, 0, 4, 3]);
								}

								// Wrong ICE role (clients must be controlling)
								else if (iceControlled) {
									inner.length = 0;
									inner.class = Class.Err;
									inner.append(AttrType.Error, 4, [0, 0, 4, 87]);
									await inner.sign(entry);
								}

								// Success
								else {
									inner.length = 0;
									inner.class = Class.Suc;
									inner.append(AttrType.Mapped, 'addr', { ip: sender, port });
									await inner.sign(entry);
								}
								inner.fingerprint();
								length = inner.byteLength;
							}
							else if (entry) {
								// Truncate everything following the integrity (Should just be the mandatory fingerprint)
								inner.msg.length = -Stun.minByteLength + integrity.byteOffset - inner.byteOffset + integrity.byteLength;
								if (inner.byteOffset + inner.byteLength + (24 /* Peer */ + 28 /* SCTP overhead */ + 60 /* TODO DTLS overhead */) > buffer.byteLength) {
									continue packet_loop;
								}
								inner.append(AttrType.Peer, 'addr', { ip: sender, port });

								// TODO: Shift inner into position for DTLS + SCTP and then forward to the owner of the dst_ufrag
								continue packet_loop;
							}
							else { debugger; continue packet_loop; }
						}

						console.log('ice-req', username, priority, useCandidate ? true : false);
					}

					// Connection Test responses
					else if (inner.class == Class.Suc && !is_broadcast) {
						const [[
							mapped,
						], [integrity], [fingerprint], unknown] = inner.parse([
							[AttrType.Mapped, 'addr'],
						], [[AttrType.Integrity, 20]], [[AttrType.Fingerprint, 4]]);
						if (!mapped || !integrity || !fingerprint || unknown.length) { debugger; continue packet_loop; }
					}
					else if (inner.class == Class.Err && !is_broadcast) {
						const [[
							_mapped,
							error
						], [integrity], [fingerprint], unknown] = inner.parse([
							[AttrType.Mapped, 'addr'],
							[AttrType.Error],
						], [[AttrType.Integrity, 20]], [[AttrType.Fingerprint, 4]]);
						if (!error || !integrity || !fingerprint || unknown.length) { debugger; continue packet_loop; }
					}

					// Connection Test Indications?? or non-requests to broadcast
					else { continue packet_loop; }
				}
				else if (data[0] < 64) /* DTLS */ {
					console.log('dtls', data);
					debugger;
					for (let offset = 0; (offset + Dtls.minByteLength) < data.byteLength;) {
						const dtls = new Dtls(data.buffer, { byteOffset: data.byteOffset + offset });
						offset += dtls.byteLength;
						if (offset > data.byteLength) break;
						if (dtls.type == 22) {
							for (let offset = Dtls.minByteLength; (offset + Handshake.minByteLength) < dtls.byteLength;) {
								const handshake = new Handshake(dtls.buffer, { byteOffset: dtls.byteOffset + offset });
								offset += handshake.byteLength;
								if (offset > dtls.byteLength) break;

								// Drop any DTLS packets that use fragmentation:
								if (handshake.total != handshake.length || handshake.offset) continue packet_loop;
							}
						}
						console.log(dtls);
					}
					// TODO: Handle DTLS handshaking
					if (is_broadcast) continue packet_loop;
					break hosted;
				}
				else /* SRTP, Etc. */ {
					// MAYBE: Add support for SRTP?
					if (is_broadcast) continue packet_loop;
					break hosted;
				}
			}

			// Append the data attribute (We only need to assign the length, because the data is already in position.)
			msg.append(AttrType.Data, length);
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

		// Check the username, realm, and nonce
		else if (username != 'guest' || realm != 'none' || nonce != 'none') {
			msg.class = Class.Err;
			msg.length = 0;
			msg.append(AttrType.Error, 4, [0, 0, 4, 1]);
			msg.append(AttrType.Realm, 'text', 'none');
			msg.append(AttrType.Nonce, 'text', 'none');
		}

		// All other requests require Authentication
		else if (!await msg.verify(turnKey)) {
			msg.class = Class.Err;
			msg.length = 0;
			msg.append(AttrType.Error, 4, [0, 0, 4, 3]);
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
			if (lifetime === 0) continue packet_loop; // Close notification -> don't respond
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
