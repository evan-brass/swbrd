// import { parse_ipaddr } from "./ipaddr.mjs";
import { serveDir } from "std/http/file_server.ts";
import { Turn } from "./turn.js";

class TurnListener {
	#inner;
	#waiters = [];
	constructor(inner) {
		this.#inner = inner;
	}
	get remoteAddr() { return this.#inner.remoteAddr; }
	async send(data) {
		// Wait until we can aquire a lock on the writable stream
		while (this.#inner.writable.locked) await new Promise(res => this.#waiters.push(res));
		const writer = this.#inner.writable.getWriter();
		try {
			await writer.ready;
			await writer.write(data);
			writer.releaseLock();
		} finally {
			const waiter = this.#waiters.shift();
			if (waiter) waiter();
		}
	}
	// Technically, this is yielding TURN message, but what I actually want it to yield are packets to relay and for it to handle all the TURN internally
	async *[Symbol.asyncIterator]() {
		const res = new Turn();
		for await(const msg of Turn.parse(this.#inner.readable)) {
			if (!msg.is_stun) continue;

			// Prepare the response
			res.length = 0;
			res.method = msg.method;
			res.class = 0b10;
			res.txid.set(msg.txid);

			// STUN Indication
			if (msg.class == 0b01) {
				// Send indication
				if (msg.method == 0x006) {
					yield [msg.xpeer, msg.data];
				} else {/* */}
			}
			// STUN Responses (Success or Error)
			else if (msg.class == 0b10 || msg.class == 0b11) {/* */}
			// TURN Allocate
			else if (msg.method == 0x003) {
				res.xmapped = this.remoteAddr;
				res.xrelay = this.remoteAddr;
				res.lifetime = 3600;
				await this.send(res.framed_packet);
			}
			// TURN Permission
			else if (msg.method == 0x008) {
				await this.send(res.framed_packet);
			}
			// Unknown message
			else {/* */}
		}
	}
}

const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const alpnProtocols = ['stun.turn', 'h2', 'http/1.1'];
const hostname = '::';

const listeners = new Set();
const sockets = new Set();

function handle_http(request) {
	if (new URLPattern({ pathname: '/broadcast' }).test(request.url)) {
		const {socket, response} = Deno.upgradeWebSocket(request);
		sockets.add(socket);
		return response;
	} else {
		return serveDir(request, {fsRoot: 'frontend'});
	}
}

// for await (const stream of Deno.listen({ hostname, port: 3478, cert, key })) {
// for await (const stream of Deno.listenTls({ hostname, port: 5349, cert, key })) {
for await (const stream of Deno.listenTls({ hostname, port: 443, cert, key, alpnProtocols })) {
	const { alpnProtocol } = await stream.handshake();

	// Spawn a task for the stream
	(async () => {
		// handle TURN:
		if (alpnProtocols.indexOf(alpnProtocol) < 1) {
			const listener = new TurnListener(stream);
			try {
				listeners.add(listener);
				const data = new Turn();
				data.class = 0x01;
				data.method = 0x007;
				for await (const [dest, packet] of listener) {
					const broadcast = dest.hostname == '255.255.255.255';

					// Broadcast the message to every association at this TURN server
					crypto.getRandomValues(data.txid);
					data.length = 0;
					data.xpeer = stream.remoteAddr;
					data.data = packet;
					for (const l of listeners) {
						if (l == listener) continue;
						if (broadcast || l.remoteAddr.hostname.endsWith(dest.hostname)) {
							await l.send(data.framed_packet);
						}
					}

					// Send some information to all the websockets if it's a broadcast
					if (broadcast) {
						const inner = new Turn(packet.buffer, packet.byteOffset, packet.byteLength);
						if (inner.byteLength < 4) break;
						if (!inner.is_stun) break;
						const ice_username = inner.username;
						if (!ice_username) break;
						for (const s of sockets) {
							if (s.readyState > 1) { sockets.delete(s); continue }
							if (s.readyState < 1) continue;
							const data = JSON.stringify({ ice_username, addr: listener.remoteAddr });
							s.send(data);
						}
					}
				}
			} finally {
				listeners.delete(listener);
			}
		}
		// handle HTTP
		else {
			for await (const e of Deno.serveHttp(stream)) {
				e.respondWith(handle_http(e.request));
			}
		}
	})();
}
