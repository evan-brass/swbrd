import { Stun, Class, Method } from './stun.js';
import { ChannelData, parse } from './turn.js';
import { write } from "./util.js";
import { realm, users, long_term } from "./auth.js";
import { allocations, allocate, hostname } from "./allocate.js";

await long_term('guest', 'the/guest/turn/credential/constant');

const maxByteLength = 2**13;

async function handle(conn) {
	let recv = new ArrayBuffer(40, {maxByteLength});
	const send = new ArrayBuffer(40, {maxByteLength});

	const writer = conn.writable.getWriter();
	let available = 0;
	const reader = conn.readable.getReader({ mode: 'byob' });

	let xrelayed;
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

				const key = users.get(frame.username);

				if (!frame.username || frame.nonce != 'none' || frame.realm != realm) {
					response.class = Class.error; response.errcode = 401;
					response.nonce = 'none'; response.realm = 'none';
				}
				else if (frame.method == Method.binding) {
					response.class = Class.success;
					response.xmapped = conn.remoteAddr;
				}
				else if (!key) {
					response.class = Class.error; response.errcode = 403;
				}
				else if (frame.method == Method.allocate) {
					xrelayed ??= allocate(writer);
					if (!xrelayed) {
						response.class = Class.error; response.errcode = 508;
					}
					else {
						response.class = Class.success;
						response.xmapped = conn.remoteAddr;
						response.xrelayed = xrelayed;
						response.lifetime = frame.lifetime || 3600;
					}
				}
				else if (frame.method == Method.createPermission) {
					response.class = Class.success;
				}
				else if (frame.method == Method.channelBind) {
					if (channels.size < 5 && frame.xpeer) {
						channels.set(frame.channel, frame.xpeer);
						response.class = Class.success;
					} else {
						response.class = Class.error;
						response.errcode = 508;
					}
				}
				else if (frame.method == Method.refresh) {
					response.class = Class.success;
				}
				else {
					response.class = Class.error; response.errcode = 404;
				}

				if (key) await response.sign(key);
				if (frame.fingerprint) response.fingerprint = true;

				await write(writer, response.frame);
			}
			else if (xrelayed && frame instanceof ChannelData || (frame instanceof Stun && frame.class == Class.indication && frame.method == Method.send)) {
				// TODO: Limit bandwidth
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
					const uni = xpeer.hostname == hostname && allocations.get(xpeer.port);
					if (uni && uni !== writer) {
						await write(uni, indication.frame);
					}
					// Otherwise broadcast the packet (So long as it's a connection test)
					else if (inner instanceof Stun && inner.method == Method.binding && inner.class == Class.request) {
						console.log('broadcast', inner.username, inner.controlled, inner.controlling, inner.usecandidate);
						for (const broad of allocations.values()) {
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
		if (xrelayed) allocations.delete(xrelayed.port);
	}
	// Cleanup the connection / reader / writer?
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	handle(conn);
}
