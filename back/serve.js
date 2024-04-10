import { Stun, Class, Method } from '../src/stun.js';
import { ChannelData, parse } from '../src/turn.js';
import { md5 } from "../src/md5.js";

// const short_key = await crypto.subtle.importKey('raw', encoder.encode("the/ice/password/constant"), {
// 	name: 'HMAC',
// 	hash: 'SHA-1'
// }, true, ['sign', 'verify']);
const long_key = await crypto.subtle.importKey('raw', md5('guest:none:the/guest/turn/credential/constant'), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

const maxByteLength = 2**13;
const fake = {
	hostname: '255.255.255.255', port: 4666
};

const all_conns = new Set();
const routing_table = new Map(); // Map<username: string, Set<writer>>

async function handle(conn) {
	let recv = new ArrayBuffer(40, {maxByteLength});
	const send = new ArrayBuffer(40, {maxByteLength});

	const writer = conn.writable.getWriter(); all_conns.add(writer);
	let available = 0;
	const reader = conn.readable.getReader({ mode: 'byob' });

	let username;
	try {
		while (true) {
			const {value, done} = await reader.read(new Uint8Array(recv, available));
			if (done) break;
			available += value.byteLength; recv = value.buffer;
	
			const res = parse(new Uint8Array(recv, 0, available));
			if (typeof res == 'number') {
				// Try to resize recv to accomodate the required size:
				if (res > recv.maxByteLength) break;
				recv.resize(res);
				continue;
			}
			
			const frame = res;
			if (frame instanceof Stun && frame.class == Class.request) {
				const response = new Stun(send);
				response.method = frame.method;
				response.length = 0;
				response.txid.set(frame.txid);
				console.log('request', conn.remoteAddr.hostname, conn.remoteAddr.port, frame.method);

				if (frame.method == Method.binding) {
					response.class = Class.success;
					response.xmapped = conn.remoteAddr;
				}
				else if (frame.method == Method.allocate) {
					if (frame.nonce != 'none' || frame.realm != 'none') {
						response.class = Class.error; response.errcode = 401;
						response.nonce = 'none'; response.realm = 'none';
					} else {
						response.class = Class.success;
						response.xmapped = conn.remoteAddr;
						response.xrelayed = fake;
						response.lifetime = frame.lifetime || 3600;
						await response.sign(long_key);
					}
				}
				else if (frame.method == Method.createPermission) {
					response.class = Class.success;
					await response.sign(long_key);
				}
				else {
					response.class = Class.error; response.errcode = 404;
				}

				if (frame.fingerprint) response.fingerprint = true;

				console.log('response', response.class, response.method);

				while (writer.desiredLength < 1) await writer.ready;
				await writer.write(response.frame);
			}
			else if (frame instanceof ChannelData || (frame instanceof Stun && frame.class == Class.indication && frame.method == Method.send)) {
				// Prepare a data indication for this packet
				const indication = new Stun(send);
				indication.method = Method.data;
				indication.class = Class.indication;
				indication.length = 0;
				if (frame.txid) {
					indication.txid.set(frame.txid);
				} else {
					crypto.getRandomValues(indication.txid);
					indication.magic = true;
				}
				indication.xpeer = fake;
				indication.data = frame.data;
				const inner = parse(indication.data);

				// Update the routing table
				if (!username && inner instanceof Stun && inner.method == Method.binding && inner.username) {
					username = inner.username;
					const listen_username = username.split(':').reverse().join(':');
					// Get or set the set of conns for a given listen_username
					const siblings = routing_table.get(listen_username) ?? new Set();
					routing_table.set(listen_username, siblings);
					siblings.add(writer);
				}

				// Route the packet:
				if (username) {
					const destinations = routing_table.get(username) ?? new Set();
					console.log('routing', username, destinations.size);
					for (const w of destinations) {
						if (w == writer) continue;
						while (w.desiredLength < 1) await w.ready;
						await w.write(indication.frame);
					}
				}
			}
	
			// Shift unused data to the front of the buffer
			available -= res.needed;
			new Uint8Array(recv, 0).set(new Uint8Array(recv, res.needed));
		}
	} catch (e) {
		console.warn(e);
		// Do Nothing
	} finally {
		all_conns.delete(writer);
	}
	// Cleanup the connection?
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	handle(conn);
}
