import { serveDir } from "std/http/file_server.ts";

const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const alpnProtocols = ['http/1.1', 'h2', 'stun.turn'];
const hostname = '::';

for await (const stream of Deno.listenTls({ hostname, port: 443, cert, key, alpnProtocols })) {
	(async () => {
		for await (const e of Deno.serveHttp(stream)) {
			e.respondWith(serveDir(e.request, {fsRoot: "frontend"}));
		}
	})();
}
