import { Protocol } from "./proto.js";

const debug = false;

const encoder = new TextEncoder();
// const decoder = new TextDecoder();

const sessions = new Map();
const delays = new Map();

const { module: _module, instance } = await WebAssembly.instantiateStreaming(fetch(new URL('./dist/dtls.wasm', import.meta.url)), {
	env: {
		log() {
			debug && console.log('mbedtls log', ...arguments);
			throw new Error();
		},
		random(_ctx, offset, length) {
			debug && console.log('random', ...arguments);
			crypto.getRandomValues(mem8(offset, length));
			return 0;
		},
		verify(ptr, fingerprint) {
			const session = sessions.get(ptr);
			if (!session) throw new Error();

			const actual = BigInt(mem8(fingerprint, 32).reduce((a, v) => a + v.toString(16).padStart(2, '0'), '0x'));
			const ret = Number(session.pid == actual);
			// console.log('verify', ...arguments, '->', ret);
			return ret;
		},
		set_timer(ctx, int_delay, fin_delay) {
			debug && console.log('set_timer', ...arguments);
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
			let ret;
			if (!pair) ret = -1;
			else {
				const { int_delay, fin_delay } = pair;
				const now = performance.now();
				if (fin_delay < now) ret = 2;
				else if (int_delay < now) ret = 1;
				else ret = 0;
			}
			debug && console.log('get_timer', ...arguments, '->', ret);
			return ret;
		},
		send(ptr, offset, len) {
			const session = sessions.get(ptr);
			if (!session) throw new Error();
			const buff = mem8(offset, len);
			const ret =  session.send(buff);
			debug && console.log('send', ...arguments, '->', ret);
			return ret;
		},
		recv(ptr, offset, len) {
			const session = sessions.get(ptr);
			if (!session) throw new Error();
			const buff = mem8(offset, len);
			const ret = session.recv(buff);
			debug && console.log('recv', ...arguments, '->', ret);
			return ret;
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
const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880;

const byteLength = 1650;

export class Dtls extends Protocol {
	#ptr;
	#recv;
	#send;
	#wbuff;
	#rbuff;
	constructor() {
		super(...arguments);
	}
	async start() {
		await super.start(...arguments);
		this.#ptr = dtls.session(ssl_config, true);
		this.#wbuff = dtls.malloc(byteLength);
		this.#rbuff = dtls.malloc(byteLength);
		if (!this.#ptr || !this.#wbuff || !this.#rbuff) throw new Error();
		sessions.set(this.#ptr, this);
	}
	recv(buff) {
		debug && console.log('this.#recv', this.#recv);
		if (!this.#recv || typeof this.#recv.then == 'function') {
			this.#recv ??= super.read().then(v => this.#recv = v, err => this.#recv = {err});
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
		const { value, done, err } = this.#recv;
		if (err) {
			return -666;
		}
		else if (value) {
			// console.log(value);
			buff.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
			this.#recv.value = false;
			if (!done) this.#recv = null;

			return value.byteLength;
		}
		return 0;
	}
	send(buff) {
		if (this.#send === true) {
			this.#send = null;
			return buff.byteLength;
		}
		else if (this.#send === false) {
			return -1;
		}
		this.#send ??= super.write(buff.slice()).then(() => this.#send = true, () => this.#send = false);
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	async pull(controller) {
		for (;;) {
			const res = dtls.read(this.#ptr, this.#rbuff, byteLength);
			debug && console.log('pl', res);
			if (res == MBEDTLS_ERR_SSL_WANT_READ) { await this.#recv; continue; }
			else if (res == MBEDTLS_ERR_SSL_WANT_WRITE) { await this.#send; continue; }
			else if (res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) controller.close();
			
			else if (res == 0) controller.close();
			else if (res < 0) controller.error(`pull err: ${res}`);
			else controller.enqueue(mem8(this.#rbuff, res).slice());
			
			if (dtls.pending(this.#ptr)) break; // Continue reading so long as data is pending

			break;
		}
	}
	close() {
		debug && console.log(":::close called:::");
		dtls.close(this.#ptr);
		return super.close();
	}
	async write(chunk, controller) {
		mem8(this.#wbuff, byteLength).set(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
		for (;;) {
			const res = dtls.write(this.#ptr, this.#wbuff, chunk.byteLength);
			debug && console.log('wl', res);
			if (res == MBEDTLS_ERR_SSL_WANT_READ) { await this.#recv; continue; }
			else if (res == MBEDTLS_ERR_SSL_WANT_WRITE) { await this.#send; continue; }

			else if (res == 0) continue;
			else if (res < 0) controller.error(`write err: ${res}`);
			else return;
		}
	}
}
