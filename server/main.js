import { parse_ipaddr } from "../switch/ipaddr.js";
import { md5 } from "../switch/md5.js";
import { Stun, Class, Method } from "../switch/stun.js";
import { ChannelData } from "../switch/turn.js";
import { parse } from "../switch/turn.js";
import { encoder } from "../switch/util.js";

// Server 
const realm = 'none';
const nonce = 'none';
const long_cred = await crypto.subtle.importKey('raw', md5('guest:none:password'), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);
const short_cred = await crypto.subtle.importKey('raw', encoder.encode('the/ice/password/constant'), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

const sock = Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 });

const send = new ArrayBuffer(40, {maxByteLength: 2048});

function mapped(ip) {
	return ip instanceof Uint8Array ? new Uint16Array([
		0, 0, 0, 0, 0, 0xffff, (ip[0] << 8) + ip[1], (ip[2] << 8) + ip[3]
	]) : ip;
}

const hosted_send = new ArrayBuffer(40, {maxByteLength: 1200})
async function hosted(datagram, sender) {
	if (datagram.byteLength < 1) return;
	const fb = datagram[0];

	const ip = parse_ipaddr(sender.hostname);
	const mip = mapped(ip);

	// STUN
	if (fb <= 3) {
		const msg = parse(datagram);

		// Connection Test:
		if (msg instanceof Stun && msg.class == Class.request && msg.method == Method.binding) {
			const ind = new Stun(send);
			crypto.getRandomValues(ind.txid);
			ind.magic = true;
			ind.class = Class.indication;
			ind.method = Method.data;
			ind.length = 0;
			ind.xpeer = { ip, port: 4666 };
			
			const resp = new Stun(hosted_send);
			resp.magic = true;
			resp.method = Method.binding;
			resp.txid.set(msg.txid);
			resp.length = 0;
			// Wrong ICE pwd
			if (!await msg.verify(short_cred)) {
				resp.class = Class.error;
				resp.errcode = 441;
			}
			// We are pseudo-ice-lite so require peer to be controlling
			else if (msg.controlled) {
				resp.class = Class.error;
				resp.errcode = 487;
				await resp.sign(short_cred);
			}
			// Bind
			else {
				resp.class = Class.success;
				resp.xmapped = { ip, port: sender.port };
				await resp.sign(short_cred);
			}

			resp.fingerprint = true;
			ind.data = resp.frame;

			await sock.send(ind.frame, sender);
		}
		// Drop any other STUN / TURN
		else { return }
	}
	// DTLS
	else if (20 <= fb && fb < 64) {
		console.log('dtls', datagram);
	}
}
for await (const [datagram, sender] of sock) {
	// Drop ~50% of packets to reduce potential amplification attacks
	if (Math.random() < 0.5) continue;

	const ip = parse_ipaddr(sender.hostname);
	const mip = mapped(ip);

	// Handle TURN
	const msg = parse(datagram);
	if (msg instanceof ChannelData) {
		await hosted(msg.data, sender);
	}
	else if (msg instanceof Stun) {
		let receiver = sender;
		const resp = new Stun(send);
		resp.method = msg.method;
		resp.magic = true; // TODO: mirror the cookie from the request
		resp.length = 0;
		resp.txid.set(msg.txid);

		const xpeer = msg.xpeer;
		const data = msg.data;
		// Stateless Relay
		if (
			msg.class == Class.indication && msg.method == Method.send &&
			xpeer && data
		) {
			const peer_mip = mapped(xpeer.ip);

			// Handle hosted:
			if (mip.every((v, i) => v == peer_mip[i]) && xpeer.port == 4666) {
				await hosted(data, sender);
				continue;
			}

			// Forward everything else:
			else {
				resp.class = Class.indication;
				resp.method = Method.data;
				resp.xpeer = { ip, port: sender.port };
				resp.data = data;

				// Pick a sampling of the packets that we would have forwarded and encapsulate them into a WebRTC DataChannel message and then send that to a random person
				if (data[0] < 2 && Math.random() < 0.3) {
					console.log('encapsulate', Array.from(resp.frame));
					continue;
				}

				// Forward as normal
				else {
					receiver = {
						transport: 'udp',
						hostname: Array.from(peer_mip, n => n.toString(16)).join(':'),
						port: xpeer.port
					};
				}
			}
		}

		// Ignore anything that isn't a request
		else if (msg.class != Class.request) { continue; }

		// Binding
		else if (msg.method == Method.binding) {
			resp.class = Class.success;
			resp.xmapped = { ip, port: sender.port };
		}

		// 401: require authentication
		else if (msg.realm != realm || msg.nonce != nonce) {
			resp.class = Class.error;
			resp.errcode = 401;
			resp.realm = realm;
			resp.nonce = nonce;
		}

		// Everything else requires authentication:
		else if (!await msg.verify(long_cred)) {
			resp.class = Class.error;
			resp.errcode = 403;
		}

		// Allocate
		else if (msg.method == Method.allocate) {
			resp.class = Class.success;
			resp.xmapped = { ip, port: sender.port };
			resp.xrelayed = { ip, port: sender.port };
			resp.lifetime = msg.lifetime || 3600;
			await resp.sign(long_cred);
		}

		// CreatePermission
		else if (msg.method == Method.createPermission) {
			resp.class = Class.success;
			await resp.sign(long_cred);
		}

		// Refresh
		else if (msg.method == Method.refresh) {
			if (msg.lifetime == 0) continue;

			resp.class = Class.success;
			resp.lifetime = msg.lifetime || 3600;
			await resp.sign(long_cred);
		}

		// ChannelBind
		else if (msg.method == Method.channelBind) {
			const channel = msg.channel, xpeer = msg.xpeer;
			if (xpeer && 0x4000 <= channel && channel < 0x5000 && xpeer.port == 4666 && xpeer.ip.every) {
				resp.class = Class.success;
				await resp.sign(long_cred);
			}
			else { continue }
		}

		// 404: Not Yet implemented
		else {
			resp.class = Class.error;
			resp.errcode = 404;
			await resp.sign(long_cred);
		}

		if (msg.fingerprint) resp.fingerprint = true;

		try {
			await sock.send(resp.frame, receiver);
		} catch (e) {
			console.warn(e);
		}
	}
}
