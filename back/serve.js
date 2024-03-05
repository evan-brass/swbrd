import { serveDir } from '@std/http/file_server.ts';
import { Stun, Class, Method } from '../src/stun.js';

Deno.serve(req => serveDir(req, {
	fsRoot: './',
	showIndex: true,
	showDirListing: true
}));

for await (const [packet, addr] of Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 })) {
	if (packet.byteLength < 20) continue;

	const msg = new Stun(packet.buffer, packet.byteOffset, packet.byteLength);

	if (msg.method == Method.binding) {
		if (msg.class != Class.request) continue;

		// Having a fingerprint probably means that this is ICE
		if (msg.fingerprint) {
			continue;
		}
		// Send back a normal binding response
		else {
			
		}
	}
	
	console.log(addr, msg.class, msg.method, msg.fingerprint);
	// for (const {type, value} of msg) {
	// 	console.log('-', type, value);
	// }
}
