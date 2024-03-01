import { serveDir } from '@std/http/file_server.ts';
import { Stun, Class, Method } from '../src/stun.js';
import { parse_ipaddr } from "../src/ipaddr.js";

Deno.serve(req => serveDir(req, {
	fsRoot: './',
	showIndex: true,
	showDirListing: true
}));

for await (const [packet, addr] of Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 })) {
	const ip = parse_ipaddr(addr.hostname);
	if (packet.byteLength < 20) continue;
	const msg = new Stun(packet.buffer, packet.byteOffset, packet.byteLength);
	
	if (msg.method == Method.binding) {
		if (msg.class !== Class.request) continue;


	}
	console.log(addr, msg.class, msg.method);
	console.log(ip);
	console.log(msg.attrs);
}
