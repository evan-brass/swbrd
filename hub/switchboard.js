


// const alpnProtocols = ['http/1.1', 'h2', 'stun.turn'];
const hostname = '::';

export default new class Switchboard extends EventTarget {
	constructor() {
		super();
		this.run();
	}
	async run() {
		for await (const stream of Deno.listenTls({ hostname, port: 5349, cert, key })) {
			
		}
	}
}
