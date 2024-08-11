// import { Stun, Class, Method, encoder } from './stun.js';
// import { ChannelData, TurnConn, parse, parse_readable } from './turn.js';
// import { write } from "./util.js";
// import { realm, long_term, short_term } from "./auth.js";
// import { allocations, allocate, ip } from "./allocate.js";
// import { from_string } from "../src/id.js";
// import { parse_ipaddr } from "./ipaddr.js";
import { TurnConn } from "./turn.js";
// import { Hosted } from "./hosted.js";
import { Dtls } from "./dtls.js";
import { SctpConn } from "./sctp.js";

async function handle(conn) {
	console.log('conn', conn);
	const relay = new TurnConn(conn);
	const decrypt = new Dtls(relay);
	await decrypt.readable.pipeThrough(new TransformStream(new SctpConn())).pipeTo(decrypt.writable);
}

for await (const conn of Deno.listen({ hostname: '::', port: 3478 })) {
	handle(conn);
}
