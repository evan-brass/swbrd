// import { parse_ipaddr } from "./ipaddr.mjs";
import { Turn } from "./turn_old.mjs";

const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const alpnProtocols = ['http/1.1', 'h2', 'stun.turn'];
const hostname = '::';

for await (const stream of Deno.listenTls({ hostname, port: 5349, cert, key, alpnProtocols })) {
	(async () => {
		for await (const msg of Turn.parse_readable(stream.readable)) {
			console.log(stream.remoteAddr, msg);
			// if (msg.type == req(0x003/* Allocate */)) {
				// const parsed_ip = parse_ipaddr(stream.remoteAddr.hostname);
				// console.log(parsed_ip);
			// }
		}
	})();
}
