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

const resp = new Stun(new ArrayBuffer(20, { maxByteLength: 4096 }))
for await (const [packet, addr] of Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 })) {
	if (packet.byteLength < 20) continue;
	const msg = new Stun(packet.buffer, packet.byteOffset, packet.byteLength);

	resp.method = msg.method;
	resp.txid.set(msg.txid);
	resp.length = 0;
	
	console.log(addr, msg.class, msg.method, msg.username);
	// for (const attr of msg) {
	// 	console.log('-', attr);
	// }
}
