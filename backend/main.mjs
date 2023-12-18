const [cert, key] = ['cert.pem', 'key.pem'].map(f => Deno.readTextFileSync(f));
const alpnProtocols = ['http/1.1', 'h2', 'stun.turn'];
const hostname = '::';

for await (const stream of Deno.listenTls({ hostname, port: 443, cert, key, alpnProtocols })) {
	(async () => {
		const proto = (await stream.handshake())?.alpnProtocol ?? 'stun.turn';

		console.log(proto);

		const reader = stream.readable.getReader();
		while (1) {
			const {done, value} = await reader.read();
			if (done) break;

			console.log(value);
		}
	})();
}
