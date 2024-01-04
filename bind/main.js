// The bind api: Give a websocket endpoint to receive broadcasts from the fake TURN server (hub)
import { Turn } from "./turn.js";

const websockets = new Set();
Deno.serve(req => {
	console.log(req);
	const {socket, response} = Deno.upgradeWebSocket(req);
	console.log(response);
	websockets.add(socket);
	socket.addEventListener('close', () => websockets.delete(socket));

	return response
});

// Broadcast the TURN messages to the WebSockets
const hub = await Deno.connect({ hostname: 'hub', port: 3478 });
for await (const msg of Turn.parse(hub.readable)) {
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
	for (const ws of websockets) {
		if (ws.readyState != 1) continue;
		ws.send(JSON.stringify({username, peer}));
	}
}
