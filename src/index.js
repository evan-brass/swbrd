import { Ip6, parse_ipaddr } from "./ipaddr.js";
import { decoder_lossy, encoder } from "./util.js";
import { Stun, Class, Method, Addr, Attr, AttrType } from "./stun.js";

if (import.meta.main) {
	const none = encoder.encode('none');
	const [turnKey, iceKey] = await Promise.all([
		[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173],
		[116, 104, 101, 47, 105, 99, 101, 47, 112, 97, 115, 115, 119, 111, 114, 100, 47, 99, 111, 110, 115, 116, 97, 110, 116]
	].map(v => crypto.subtle.importKey('raw', new Uint8Array(v), {
		name: 'HMAC', hash: 'SHA-1'
	}, true, ['sign', 'verify'])));

	const sock = Deno.listenDatagram({ port: 3478, hostname: '::', transport: 'udp'});
	const buffer = new Uint8Array(2048);
	packet_loop: for (;;) {
		const [{ byteLength }, {hostname, port}] = await sock.receive(buffer);
		const msg = new Stun(buffer);
		if (msg.byteLength != byteLength) continue;
		const sender = parse_ipaddr(hostname);
		const canonical = sender.canonical();
		let receiver = {hostname, port};

		// Send Indications
		if (msg.class == Class.Ind && msg.method == Method.Send) {
			msg.method = Method.Data;
			const peer = msg[Symbol.iterator]().find(a => a.type == AttrType.Peer);
			if (peer.byteOffset < Addr.minByteLength) continue packet_loop;
			const { ip: peerIp, port: peerPort } = new Addr(peer, {parent: msg});
			if (!(peerIp instanceof Ip6)) continue packet_loop;
			receiver = {hostname: String(peerIp), port: peerPort};
			const data = msg[Symbol.iterator]().find(a => a.type == AttrType.Data);
			if (!data) continue packet_loop;

			// Shift the data Attribute to the beginning of the message:
			const {byteOffset: offset, byteLength: len} = data;
			buffer.copyWithin(Stun.minByteLength, offset, offset + len);
			msg.length = len;

			// Append the sender's address as the new peer address
			msg.append({type: AttrType.Peer, port, ip: sender}, Addr); // NOTE: sender not canonical.
		}

		// Drop all other Indications or Responses
		else if (msg.class != Class.Req) {
			continue packet_loop;
		}

		// Binding Requests
		else if (msg.method == Method.Binding) {
			msg.length = 0;
			msg.class = Class.Suc;
			msg.append({ type: AttrType.Mapped, ip: canonical, port }, Addr);
		}

		// All other requests require Authentication
		else if (!await msg.verify(turnKey)) {
			msg.class = Class.Err;
			msg.length = 0;
			msg.append({type: AttrType.Error, length: 4, value: [0, 0, 4, 1]});
			msg.append({type: AttrType.Realm, length: 4, value: none});
			msg.append({type: AttrType.Nonce, length: 4, value: none});
		}

		// Allocate Requests
		else if (msg.method == Method.Allocate) {
			let lifetime = msg[Symbol.iterator]().find(a => a.type == AttrType.Lifetime && a.length == 4);
			lifetime = lifetime ? lifetime.getUint32(4) : 6000;
			msg.class = Class.Suc;
			msg.length = 0;
			msg.append({type: AttrType.Mapped, ip: canonical, port}, Addr);
			msg.append({type: AttrType.Relayed, ip: sender, port}, Addr);
			msg.append({type: AttrType.Lifetime, length: 4})
				.setUint32(Attr.minByteLength, lifetime);
			await msg.sign(turnKey);
			console.assert(await msg.verify(turnKey), 'wat');
		}

		// Refresh Request
		else if (msg.method == Method.Refresh) {
			let lifetime = msg[Symbol.iterator]().find(a => a.type == AttrType.Lifetime && a.length == 4);
			lifetime = lifetime ? lifetime.getUint32(4) : 6000;
			if (lifetime == 0) continue packet_loop; // Close association, don't respond
			msg.class = Class.Suc;
			msg.length = 0;
			msg.append({type: AttrType.Lifetime, length: 4})
				.setUint32(4, lifetime);
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
			msg.append({type: AttrType.Error, length: 4, value: [0, 0, 4, 38]});
			await msg.sign(turnKey);
		}

		// Drop all other requests
		else { continue packet_loop; }

		try {
			await sock.send(buffer.subarray(0, msg.byteLength), receiver);
		} catch {/* */}
	}
}
