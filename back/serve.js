import { serveDir } from '@std/http/file_server.ts';
import { Stun, Class, Method } from '../src/stun.js';
import { ChannelData, parse } from '../src/turn.js';
import { encoder } from "../src/stun.js";
import { md5 } from "../src/md5.js";

// Deno.serve(req => serveDir(req, {
// 	fsRoot: './',
// 	showIndex: true,
// 	showDirListing: true
// }));

const short_key = await crypto.subtle.importKey('raw', encoder.encode("the/ice/password/constant"), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);
const long_key = await crypto.subtle.importKey('raw', md5('guest:realm:the/guest/turn/credential/constant'), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

// const resp = new Stun(new ArrayBuffer(20, { maxByteLength: 4096 }));
// async function handle_turn(message, sender, { res_buffer = new ArrayBuffer(20, { maxByteLength: 4096 })}) {
// 	else if (message.method == Method.send) {
// 		if (message.class != Class.indication) return {response: null, forward: null};
// 		resp.class = Class.indication;
// 		resp.method = Method.data;
// 		resp.xpeer = sender;
// 		resp.data = message.data;
// 		return {response: null, forward: {
// 			address: message.xpeer,
// 			message: resp
// 		}};
// 	}
// 	else {
// 		return {response: null, forward: null}
// 	}
// 	if (message.fingerprint) resp.fingerprint = true;

// 	return { response: resp, forward: null };
// }

// const sock = Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 });
// for await (const [packet, sender] of sock) {
// 	if (packet.byteLength < 20) continue;
// 	// const msg = new Stun(packet.buffer, packet.byteOffset, packet.byteLength);
// 	const msg = parse(packet);
// 	if (!msg) continue;
	
// 	const {response, forward} = await handle_turn(msg, sender);

// 	if (response) {

// 	}

// 	const buff = new Uint8Array(resp.buffer, resp.byteOffset, resp.needed);
// 	await sock.send(buff, target);
// }

const maxByteLength = 2**13;

const writers = new Set();

async function handle(conn) {
	let recv = new ArrayBuffer(40, {maxByteLength});
	const send = new ArrayBuffer(40, {maxByteLength});

	// Allocate a link-local ip address for this peer
	const writer = conn.writable.getWriter();
	writers.add(writer);

	let available = 0;
	const reader = conn.readable.getReader({ mode: 'byob' });
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
	
			// Handle the frame
			const frame = res;
			if (frame instanceof Stun) {
				// TODO: Handle send indications
				const resp = new Stun(send);
				resp.method = frame.method;
				resp.class = Class.success;
				resp.txid.set(frame.txid);
				resp.length = 0;
				// resp.software = 'None';
	
				if (frame.method == Method.binding) {
					if (frame.class != Class.request) continue
	
					resp.mapped = conn.remoteAddr;
					resp.xmapped = conn.remoteAddr;
				}
				else if (frame.method == Method.allocate) {
					if (frame.class != Class.request) continue;
					if (!frame.nonce || !frame.realm) {
						resp.class = Class.error;
						resp.errcode = 401;
						resp.nonce = 'nonce';
						resp.realm = 'realm';
					}
					else if (!await frame.verify(long_key)) {
						resp.class = Class.error;
						resp.errcode = 403;
					}
					else {
						resp.xrelayed = {
							hostname: '169.254.0.1',
							port: conn.remoteAddr.port
						};
						resp.lifetime = frame.lifetime || 3600;
						resp.xmapped = conn.remoteAddr;
						await resp.sign(long_key);
					}
				}
				else if (frame.method == Method.createPermission) {
					if (frame.class != Class.request) continue;
					await resp.sign(long_key);
				}
				else if (frame.method == Method.refresh) {
					if (frame.class != Class.request) continue;
					resp.lifetime = frame.lifetime;
					await resp.sign(long_key);
				}
				else if (frame.method == Method.send) {
					if (frame.class != Class.indication) continue;
					resp.class = Class.indication;
					resp.method = Method.data;
					// const inner = parse(frame.data);
					resp.xpeer = {
						hostname: '169.254.0.1',
						port: conn.remoteAddr.port
					};
					// if (inner instanceof Stun && (inner.class == Class.error || inner.class == Class.success)) {
					// 	// Fudge the source for STUN responses because I think Firefox won't accept the response unless it comes from the same ip that we sent it too
					// } else {
					// 	resp.xpeer = conn.remoteAddr;
					// }
					resp.data = frame.data;
					console.log('send', frame.xpeer, frame.data.byteLength);
					
					for (const other of writers) {
						if (other == writer) continue;
						while (other.desiredSize < 1) await other.ready;
						await other.write(resp.frame);
					}
					// if (frame.xpeer.hostname.endsWith('.255.255')) {
					// 	console.log('multicast', conn.remoteAddr, frame.xpeer);
					// 	// Multicast
					// } else {
					// 	// Unicast
					// 	const other = writers.get(frame.xpeer.hostname);
					// 	if (!other) continue;
					// 	console.log('unicast', conn.remoteAddr, frame.xpeer);
					// 	while (other.desiredSize < 1) await other.ready;
					// 	await other.write(resp.frame);
					// }
				}

				// Send the response frame
				while (writer.desiredSize < 1) await writer.ready;
				await writer.write(resp.frame);
			}
			else if (frame instanceof ChannelData) {
				// TODO: 
			}
	
			// Shift unused data to the front of the buffer
			available -= frame.needed;
			new Uint8Array(recv, 0).set(new Uint8Array(recv, frame.needed));
		}
	} catch {
		// Do Nothing
	} finally {
		writers.delete(writer);
	}
	// Cleanup the connection?
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	handle(conn);
}
