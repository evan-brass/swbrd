#!/usr/bin/env -S deno run --allow-read --allow-write --unstable-net
// A switchboard extension in ~20 lines: echo every message back to the peer.
//
//   deno run --allow-read --allow-write extensions/echo.js /run/swbrd/ext/echo.sock
//
// The daemon dials this socket once per datachannel whose DCEP protocol the
// directory maps here, so each connection is one channel.

import { Channel } from '../src/chan.js';

const path = Deno.args[0] ?? '/run/swbrd/ext/echo.sock';
try {
	Deno.removeSync(path);
} catch {
	// Nothing there to clean up.
}

const listener = Deno.listen({ path, transport: 'unix' });
console.log(`echo extension listening on ${path}`);

for await (const conn of listener) {
	serve(conn).catch((e) => console.error('channel failed:', e));
}

async function serve(conn) {
	const chan = await Channel.accept(conn);
	const { id, label, protocol } = chan.open;
	console.log(
		`open peer=${id} label=${JSON.stringify(label)} protocol=${protocol}`,
	);

	await chan.send(`echo ready for ${id}`);
	for await (const msg of chan) {
		console.log(`recv ${msg.text ?? `${msg.data.length} bytes`}`);
		await chan.send(msg.text ?? msg.data, { ppid: msg.ppid });
	}
	console.log(`close peer=${id}`);
	chan.close();
}
