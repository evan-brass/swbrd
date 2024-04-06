import { Stun, Class, Method } from '../src/stun.js';
import { ChannelData, parse } from '../src/turn.js';
import { md5 } from "../src/md5.js";

// const short_key = await crypto.subtle.importKey('raw', encoder.encode("the/ice/password/constant"), {
// 	name: 'HMAC',
// 	hash: 'SHA-1'
// }, true, ['sign', 'verify']);
const long_key = await crypto.subtle.importKey('raw', md5('guest:realm:the/guest/turn/credential/constant'), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

const maxByteLength = 2**13;
const fake_addr = Object.assign(Object.create(null), {
	hostname: '169.254.255.255', port: 4666
});

const writers = new Set();

async function serve(frame, addr, {send}) {
	const response = new Stun(send);
	response.length = 0;

	if (frame instanceof Stun) {
		response.method = frame.method;
		response.txid.set(frame.txid);

		if (frame.method == Method.binding && frame.class == Class.request) {
			response.class = Class.success;
			response.mapped = addr;
			response.xmapped = addr;
		}
		else if (frame.method == Method.allocate && frame.class == Class.request) {
			if (!frame.nonce || !frame.realm) {
				response.class = Class.error;
				response.errcode = 401;
				response.nonce = 'nonce';
				response.realm = 'realm';
			}
			else if (!await frame.verify(long_key)) {
				response.class = Class.error;
				response.errcode = 403;
			}
			else {
				response.class = Class.success;
				response.xmapped = addr;
				response.xrelayed = fake_addr;
				response.lifetime = frame.lifetime || 3600;
				await response.sign(long_key);
			}
		}
		else if (frame.method == Method.createPermission && frame.class == Class.request) {
			response.class = Class.success;
			await response.sign(long_key);
		}
		else if (frame.method == Method.refresh && frame.class == Class.request) {
			response.class = Class.success;
			response.lifetime = frame.lifetime;
			await response.sign(long_key);
		}
		else if (frame.method == Method.channelBind && frame.class == Class.request) {
			response.class = Class.success;
			await response.sign(long_key);
		}
		else if (frame.method == Method.send && frame.class == Class.indication) {
			response.class = Class.indication;
			response.method = Method.data;
			response.xpeer = fake_addr;
			response.data = frame.data;

			return { forward: response };
		}
		else {
			return {};
		}

		return { response };
	}
	else if (frame instanceof ChannelData) {
		crypto.getRandomValues(response.txid);
		response.class = Class.indication;
		response.method = Method.data;
		response.xpeer = fake_addr;
		response.data = frame.data;

		return { forward: response };
	}

	return {};
}

async function handle(conn) {
	let recv = new ArrayBuffer(40, {maxByteLength});
	const send = new ArrayBuffer(40, {maxByteLength});

	const writer = conn.writable.getWriter(); writers.add(writer);
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
			console.log('request', res.frame);
			const { response, forward } = await serve(res, conn.remoteAddr, { send });

			if (forward) {
				console.log('forward', forward.frame);
				for (const other of writers.values()) {
					if (other === writer) continue;
					while (other.desiredSize < 1) await other.ready;
					await other.write(forward.frame);
				}
			}
			if (response) {
				console.log('response', response.frame);
				while (writer.desiredSize < 1) await writer.ready;
				await writer.write(response.frame);
			}
	
			// Shift unused data to the front of the buffer
			available -= res.needed;
			new Uint8Array(recv, 0).set(new Uint8Array(recv, res.needed));
		}
	} catch (e) {
		console.warn(e);
		// Do Nothing
	} finally {
		writers.delete(writer);
	}
	// Cleanup the connection?
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	handle(conn);
}
