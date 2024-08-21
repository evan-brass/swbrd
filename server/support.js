import { Stun, Class, Method } from "../switch/stun.js";
import { encoder, decoder } from "../src/util.js";
import { from_bytes } from '../src/id.js';
import { sock, send } from "./sock.js";
import { parse_ipaddr } from "../src/ipaddr.js";

function unimplemented() { throw new Error("Not Implemented."); }

const { instance } = await WebAssembly.instantiateStreaming(fetch(new URL('./dist/dtls.wasm', import.meta.url)), {
	wasi_snapshot_preview1: {
		fd_close: unimplemented,
		fd_fdstat_get: unimplemented,
		fd_seek: unimplemented,
		fd_write: unimplemented,
	},
	env: {
		send(ctx, offset, len) {
			const key = decoder.decode(mem8(ctx, 48));
			const { 1: hostname, 2: port } = /\[([0-9a-f:]+)\]:([0-9]+)/i.exec(key);

			const ind = new Stun(send);
			ind.class = Class.indication;
			ind.method = Method.data;
			ind.length = 0;
			crypto.getRandomValues(ind.txid);
			ind.magic = true;
			ind.xpeer = {
				ip: parse_ipaddr(hostname),
				port: 4666
			};
			if (ind.frame.byteLength + 4 + len > send.maxByteLength) {
				console.warn('Unable to encapsulate DTLS data into DataIndication - too big', len);
				return len;
			}

			const inner = mem8(offset, len);
			ind.data = inner;

			sock.send(ind.frame, {
				transport: 'udp',
				hostname,
				port: parseInt(port)
			}).catch(console.warn);

			return len;
		},
		cert_pem(offset, len) {
			let pem = Deno.readTextFileSync('./cert.pem');
			if (!pem.endsWith('\0')) pem += '\0';

			const { read, written } = encoder.encodeInto(pem, mem8(offset, len));
			if (read < pem.length) throw new Error("PEM buffer too small");

			return written;
		},
		exit(code) {
			throw new Error(`Support exit: ${code}`);
		},
		log(_ctx, _dbg_lvl, file, line, msg) {
			file = decoder.decode(mem8(file, instance.exports.strlen(file)));
			msg = decoder.decode(mem8(msg, Math.max(0, instance.exports.strlen(msg) - 1)));
			console.log(`${file}:${line}`, msg);
		},
		random(_ctx, offset, length) {
			crypto.getRandomValues(mem8(offset, length));
			return 0;
		},
		now() { return performance.now(); }
	}
});

function mem8(offset, length) {
	return new Uint8Array(instance.exports.memory.buffer, offset, length);
}

instance.exports._start();

export const id = from_bytes(mem8(instance.exports.fingerprint(), 32));

export function new_session(key) {
	const ret = instance.exports.create_session();
	if (ret) encoder.encodeInto(key, mem8(ret, 48));

	return ret;
}

const recv_len = 2048;
const recv_buffer = instance.exports.malloc(recv_len);
if (!recv_buffer) throw new Error("OOM");

const send_len = 600;
const send_buffer = instance.exports.malloc(send_len);

export function send_buff() { return mem8(send_buffer, send_len); }

export function write(ptr, len) {
	return instance.exports.write(ptr, send_buffer, len);
}

export function push(ptr, datagram) {
	const offset = instance.exports.push(ptr, datagram.byteLength);
	if (offset) mem8(offset, datagram.byteLength).set(datagram);
}

export function pull(ptr) {
	const ret = instance.exports.pull(ptr, recv_buffer, recv_len);
	if (ret > 0) return mem8(recv_buffer, ret);
	return ret;
}

export function peer_id(ptr) {
	const offset = instance.exports.peer_fingerprint(ptr);
	const fingerprint = mem8(offset, 32);
	return from_bytes(fingerprint);
}
