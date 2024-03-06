import { serveDir } from '@std/http/file_server.ts';
import { Stun, Class, Method } from '../src/stun.js';
import { encoder } from "../src/stun.js";
import { md5 } from "../src/md5.js";

Deno.serve(req => serveDir(req, {
	fsRoot: './',
	showIndex: true,
	showDirListing: true
}));

const short_key = await crypto.subtle.importKey('raw', encoder.encode("the/ice/password/constant"), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);
const long_key = await crypto.subtle.importKey('raw', md5("guest:realm:the/guest/password"), {
	name: 'HMAC',
	hash: 'SHA-1'
}, true, ['sign', 'verify']);

const resp = new Stun(new ArrayBuffer(20, { maxByteLength: 4096 }));

const sock = Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 });
for await (const [packet, sender] of sock) {
	if (packet.byteLength < 20) continue;
	const msg = new Stun(packet.buffer, packet.byteOffset, packet.byteLength);

	resp.method = msg.method;
	resp.class = Class.success;
	resp.txid.set(msg.txid);
	resp.length = 0;
	let target = sender;

	if (msg.method == Method.binding) {
		if (msg.class != Class.request) continue;

		resp.mapped = sender;
		resp.xmapped = sender;
	}
	else if (msg.method == Method.allocate) {
		if (msg.class != Class.request) continue;
		if (!msg.nonce) {
			resp.class = Class.error;
			resp.errcode = 401;
			resp.nonce = 'nonce';
			resp.realm = 'realm';
		}
		else { continue; }
	}

	console.log(sender, msg.class, msg.method, msg.username);

	const buff = new Uint8Array(resp.buffer, resp.byteOffset, resp.needed);
	await sock.send(buff, target);
}
