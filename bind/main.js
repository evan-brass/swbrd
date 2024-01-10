import { Turn } from './turn.js';

Deno.serve(async req => {
	let host = new URL(req.url).searchParams.get('host');
	if (!URL.canParse(host)) throw new Error("Couldn't parse host search parameter");
	host = new URL(host);

	if (!/^turns?:/i.test(host.protocol) || host.search != '?transport=tcp') throw new Error("Host url wasn't turn(s) or wasn't transport=tcp")

	let [hostname, port] = host.pathname.split(':');
	port = parseInt(port);

	const conn = (host.protocol == 'turns:') ? await Deno.connectTls({hostname, port}) : await Deno.connect({hostname, port});
	const {socket, response} = Deno.upgradeWebSocket(req);

	handle(socket, conn);

	return response;
});

async function handle(socket, conn) {
	const turn_msgs = Turn.parse(conn.readable);

	// Close the tcp socket when the websocket closes:
	socket.addEventListener('close', () => turn_msgs.return());

	try {
		// Handle TURN messages on the tcp/tls conn
		for await (const msg of turn_msgs) {
			// We only care about data indications
			if (msg.class != 0b01) continue;
			if (msg.method != 0x007) continue;
			// We only want ICE connection tests (STUN Bind with username)
			if (msg.data?.byteLength < 20) continue;
			const inner = new Turn(msg.data.buffer, msg.data.byteOffset, msg.data.byteLength);
			if (inner.class != 0b00) continue;
			if (inner.method != 0x001) continue;
			const username = inner.username;
			const peer = msg.xpeer;
			if (!username || !peer) continue;
	
			const [dest, src] = username.split(':');
			console.log(dest, '<-', src);

			if (socket.readyState < 1) continue;
			if (socket.readyState > 1) break;
			socket.send(JSON.stringify({
				dest, src, address: peer
			}));
		}
	} finally {
		await conn.readable.cancel('WebSocket closed');
		await conn.writable.close();
	}
}
