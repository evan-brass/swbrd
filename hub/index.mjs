import { serveDir } from "https://deno.land/std@0.201.0/http/file_server.ts";
// import { parse_ipaddr } from "./ipaddr.mjs";

import listen from "./listen.mjs";

const sockets = new Set();

listen({
	handle_turn(msg, _conn, addr) {
		console.log(addr, msg);
	},
	handle_http(req) {
		if (new URLPattern({ pathname: '/assoc_stream' }).test(req.url)) {
			const {socket, response} = Deno.upgradeWebSocket(req);
			sockets.add(socket);
			return response;
		} else {
			return serveDir(req, { fsRoot: new URL('frontend', import.meta.url).pathname });
		}
	}
});
