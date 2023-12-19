import { Turn } from "./turn_old.mjs";

function default_listeners() {
	const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));

	const alpnProtocols = ['http/1.1', 'h2', 'stun.turn'];
	const hostname = '::';

	return [
		Deno.listenDatagram({ hostname, transport: 'udp', port: 80 }),
		Deno.listenTls({ hostname, port: 443, cert, key, alpnProtocols }),
		Deno.listenDatagram({ hostname, transport: 'udp', port: 3478 }),
		Deno.listen({ hostname, transport: 'tcp', port: 3478 }),
		Deno.listenTls({ hostname, port: 5349, cert, key, alpnProtocols })
	];
}

export default function listen({
	handle_turn = (_turn, _endpoint, _addr) => {},
	handle_http = _req => new Response('Not Found', {status: 404}),
	listeners = default_listeners()
} = {}) {
	for (let i = 0; i < listeners.length; ++i) {
		// Spawn a task to handle messages on this listener
		(async () => {
			const listener = listeners[i];
			for await (const item of listener) {
				if (Array.isArray(item)) {
					const [buff, addr] = item;
					const turn = await Turn.parse_packet(buff);
					if (turn) handle_turn(i, addr, turn);
				} else {
					const conn = item;
					// Spawn a task to handle the connection:
					(async () => {
						const proto = (conn.handshake && (await conn.handshake()).alpnProtocol) ?? 'stun.turn';
						if (proto == 'stun.turn') {
							// Deframe and serve TURN over the conn:
							for await (const turn of Turn.parse_readable(conn.readable)) {
								handle_turn(i, conn.remoteAddr, turn);
							}
						} else {
							// Serve HTTP over the conn:
							for await (const e of Deno.serveHttp(conn)) {
								e.respondWith(handle_http(e.request));
							}
						}
					})();
				}
			}
		})();
	}
}
