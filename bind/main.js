// The bind api: Give a websocket endpoint to receive broadcasts from the fake TURN server (hub)
import { Turn } from "./turn.js";

const websockets = new Set();
Deno.serve(req => {
	const {socket, response} = Deno.upgradeWebSocket(req);
	websockets.add(socket);
	socket.addEventListener('close', () => websockets.delete(socket));

	return response
});

// Broadcast the TURN messages to the WebSockets
const hub = await Deno.connect({ hostname: 'hub', port: 3478 });
for await (const msg of Turn.parse(hub.readable)) {
	for (const ws of websockets) {
		ws.send(msg);
	}
}
