import { Protocol } from "./proto.js";

const encoder = new TextEncoder();
// const decoder = new TextDecoder();

const sessions = new Map();
const delays = new Map();

const { module: _module, instance } = await WebAssembly.instantiateStreaming(fetch(new URL('./dist/dtls.wasm', import.meta.url)), {
	env: {
		log() {
			debugger;
		},
		random(_ctx, offset, length) {
			crypto.getRandomValues(mem8(offset, length));
			return length;
		},
		verify(ptr, fingerprint) {
			const session = sessions.get(ptr);
			if (!session) return 0;

			const actual = BigInt(mem8(fingerprint, 32).reduce((a, v) => a + v.toString(16).padStart(2, '0'), '0x'));
			return Number(session.pid == actual);
		},
		set_timer(ctx, int_delay, fin_delay) {
			if (fin_delay == 0) {
				delays.delete(ctx);
			} else {
				const now = performance.now();
				int_delay += now;
				fin_delay += now;
				delays.set(ctx, { int_delay, fin_delay });
			}
		},
		get_timer(ctx) {
			const pair = delays.get(ctx);
			if (!pair) return -1;
			const { int_delay, fin_delay } = pair;
			const now = performance.now();
			if (fin_delay < now) return 2;
			else if (int_delay < now) return 1;
			else return 0;
		},
		send(ptr, offset, len) {
			const session = sessions.get(ptr);
			if (!session) return -1;
			const buff = mem8(offset, len);
			return session.send(buff);
		},
		recv(ptr, offset, len) {
			const session = sessions.get(ptr);
			if (!session) return -1;
			const buff = mem8(offset, len);
			return session.recv(buff);
		},
	}
});
const dtls = instance.exports;

function mem8(offset, length) {
	return new Uint8Array(dtls.memory.buffer, offset, length);
}
// function memdv(offset, length) {
// 	return new DataView(dtls.memory.buffer, offset, length);
// }

let ssl_config, id; {
	let txt = Deno.env.get('CERT') ?? Deno.readTextFileSync('./cert.pem');
	if (!txt.endsWith('\0')) txt += '\0';

	const encoded = encoder.encode(txt);
	const pem_ptr = dtls.malloc(encoded.byteLength);
	if (!pem_ptr) throw new Error("Couldn't allocate for the CERT's PEM data");
	mem8(pem_ptr, encoded.byteLength).set(encoded);

	ssl_config = dtls.setup(pem_ptr, encoded.byteLength);
	if (!ssl_config) throw new Error("Failed to create the ssl_config");

	id = BigInt(mem8(dtls.fingerprint(ssl_config), 32).reduce((a, v) => a + v.toString(16).padStart(2, '0'), '0x'))
}

export { id };

const MBEDTLS_ERR_SSL_WANT_READ  = -0x6900;
const MBEDTLS_ERR_SSL_WANT_WRITE = -0x6880;

export class Dtls extends Protocol {
	#ptr;
	constructor() {
		super(...arguments);
	}
	async start() {
		await super.start(...arguments);
		this.#ptr = dtls.session(ssl_config, true);
		if (!this.#ptr) throw new Error("Failed to create an ssl session");
		sessions.set(this.#ptr, this);
	}
	async pull(controller) {
		
	}
	async write(chunk) {

	}
}
