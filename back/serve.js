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

const writers = new Map();

const hostname = '::ffff:169.254.255.255';

async function write(writer, frame) {
	console.log('write', writer, frame.byteLength);
	while (writer.desiredSize < 0) await writer.ready;
	if (writer.desiredSize == null || writer.desiredSize == 0) return;
	await writer.write(frame);
}

async function handle(conn) {
	let recv = new ArrayBuffer(40, {maxByteLength});
	const send = new ArrayBuffer(40, {maxByteLength});

	const writer = conn.writable.getWriter();
	let available = 0;
	const reader = conn.readable.getReader({ mode: 'byob' });

	// Allocate a port for the peer
	let port;
	while (!port || writers.has(port)) {
		port = crypto.getRandomValues(new Uint16Array(1))[0]
	}
	writers.set(port, writer);
	const xrelayed = {hostname, port};

	const channels = new Map();
	try {
		while (true) {
			try {
				const {value, done} = await reader.read(new Uint8Array(recv, available));
				if (done) break;
				available += value.byteLength; recv = value.buffer;
			} catch { break; }
	
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
						response.xrelayed = xrelayed;
						response.lifetime = frame.lifetime || 3600;
						await response.sign(long_key);
					}
				}
				else if (frame.method == Method.createPermission) {
					response.class = Class.success;
					await response.sign(long_key);
				}
				else if (frame.method == Method.channelBind) {
					if (channels.size < 5 && frame.xpeer) {
						channels.set(frame.channel, frame.xpeer);
						response.class = Class.success;
					} else {
						response.class = Class.error;
						response.errcode = 508;
					}
					await response.sign(long_key);
				}
				else {
					response.class = Class.error; response.errcode = 404;
				}

				if (frame.fingerprint) response.fingerprint = true;

				await write(writer, response.frame);
			}
			else if (frame instanceof ChannelData || (frame instanceof Stun && frame.class == Class.indication && frame.method == Method.send)) {
				const xpeer = frame.xpeer ?? channels.get(frame.channel);
				if (xpeer && frame.data) {
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
					indication.xpeer = xrelayed;
					indication.data = frame.data;
					const inner = parse(frame.data);

					// Try to unicast the packet
					const uni = xpeer.hostname == hostname && writers.get(xpeer.port);
					if (uni && uni !== writer) {
						await write(uni, indication.frame);
					}
					// Otherwise broadcast the packet (So long as it's a connection test)
					else if (inner instanceof Stun && inner.method == Method.binding && inner.class == Class.request) {
						console.log('broadcast', inner.username, inner.controlled, inner.controlling, inner.usecandidate);
						for (const broad of writers.values()) {
							if (broad == writer) continue;
							await write(broad, indication.frame);
						}
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
		writers.delete(xrelayed.hostname);
	}
	// Cleanup the connection?
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	handle(conn);
}
