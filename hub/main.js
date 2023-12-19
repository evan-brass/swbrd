import { Turn } from "./turn.mjs";

const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const alpnProtocols = ['http/1.1', 'h2', 'stun.turn'];
const hostname = '::';

for await (const stream of Deno.listenTls({ hostname, port: 5349, cert, key, alpnProtocols })) {
	(async () => {
		for await (const msg of Turn.decode_stream(stream)) {
			console.log()
		}
	})();
}
