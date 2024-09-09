// import { Protocol } from "./proto.js";

import { from_bytes } from '../src/id.js';
import { decoder_lossy } from '../src/util.js';

const libpath = (Deno.build.os == 'darwin') ? '/usr/local/lib/libssl.3.dylib' : '/usr/lib/libssl.so.3';

const {symbols: openssl} = Deno.dlopen(libpath, {
	OPENSSL_version_major: { parameters: [], result: 'u32' },
	OPENSSL_version_minor: { parameters: [], result: 'u32' },
	OPENSSL_version_patch: { parameters: [], result: 'u32' },

	DTLS_method: { parameters: [], result: 'pointer' },
	DTLS_server_method: { parameters: [], result: 'pointer' },
	DTLS_client_method: { parameters: [], result: 'pointer' },

	EVP_sha256: { parameters: [], result: 'pointer' },

	SSL_CTX_new: { parameters: ['pointer' /* method */], result: 'pointer' },
	SSL_CTX_free: { parameters: ['pointer' /* ctx */], result: 'void' },
	SSL_CTX_use_certificate: { parameters: ['pointer' /* ctx */, 'pointer' /* X509 */], result: 'i32' },
	SSL_CTX_use_PrivateKey: { parameters: ['pointer' /* ctx */, 'pointer' /* EVP_PKEY */], result: 'i32' },
	SSL_CTX_check_private_key: { parameters: ['pointer' /* ctx */], result: 'i32' },

	SSL_new: { parameters: ['pointer'/* ctx */], result: 'pointer' },
	SSL_set_ssl_method: { parameters: ['pointer', 'pointer'], result: 'i32' },
	SSL_handle_events: { parameters: ['pointer'], result: 'i32' },
	SSL_get_rbio: { parameters: ['pointer'], result: 'pointer' },
	SSL_get_wbio: { parameters: ['pointer'], result: 'pointer' },
	SSL_set_bio: { parameters: ['pointer', 'pointer', 'pointer'], result: 'void' },
	SSL_set_accept_state: { parameters: ['pointer'], result: 'void' },
	SSL_accept: { parameters: ['pointer'], result: 'i32' },
	SSL_connect: { parameters: ['pointer'], result: 'i32' },
	SSL_get_error: { parameters: ['pointer', 'i32'], result: 'i32' },
	SSL_do_handshake: { parameters: ['pointer'], result: 'i32' },
	SSL_write: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
	SSL_read: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
	SSL_want: { parameters: ['pointer'], result: 'i32' },
	SSL_is_init_finished: { parameters: ['pointer'], result: 'i32' },
	// SSL_want_read: { parameters: ['pointer'], result: 'i32' },
	// SSL_want_write: { parameters: ['pointer'], result: 'i32' },

	ERR_get_error: { parameters: [], result: 'u32' },
	// TODO: load error strings?
	ERR_error_string_n: { parameters: ['u32', 'buffer', 'isize'], result: 'void' },

	// BIO_get_new_index: { parameters: [], result: 'i32' },
	BIO_meth_new: { parameters: ['i32', 'buffer'], result: 'pointer' },
	BIO_meth_set_read_ex: { parameters: ['pointer', 'function'], result: 'i32' },
	BIO_meth_set_write_ex: { parameters: ['pointer', 'function'], result: 'i32' },

	BIO_new: { parameters: ['pointer'], result: 'pointer' },
	BIO_new_mem_buf: { parameters: ['buffer', 'i32'], result: 'pointer' },
	BIO_s_mem: { parameters: [], result: 'pointer' },
	BIO_s_dgram_mem: { parameters: [], result: 'pointer' },
	BIO_free: { parameters: ['pointer'], result: 'void' },
	BIO_read: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
	BIO_write: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
	BIO_ctrl: { parameters: ['pointer', 'i32', 'i64', 'pointer'], result: 'i64' },
	// TODO: Why is make_bio_pair not defined?
	// BIO_make_bio_pair: { parameters: ['pointer', 'pointer'], result: 'i32' },
	BIO_new_bio_pair: { parameters: ['pointer', 'isize', 'pointer', 'isize'], result: 'pointer' },

	PEM_read_bio_PrivateKey: { parameters: [
		'pointer', // BIO
		'pointer', // reuse EV_PKEY (leave void)
		'pointer', // pem_pass (leave void)
		'pointer', // pem_pass_ctx (leave void)
	], result: 'pointer' },

	PEM_read_bio_X509: { parameters: [
		'pointer', // BIO
		'pointer', // reuse (leave void)
		'pointer', // pem_pass (leave void)
		'pointer', // pem_pass_ctx (leave void)
	], result: 'pointer' },
	X509_free: { parameters: ['pointer'], result: 'void' },
	X509_digest: { parameters: [
		'pointer', // X509*
		'pointer', // EVP_MD*
		'buffer', // char* (Assumed that this will be big enough to store the digest)
		'pointer', // int* length (output: the length of the digest will be written here)
	], result: 'i32' },
});
const BIO_CTRL_PENDING = 10;
const SSL_NOTHING = 1;
const SSL_READING = 3;

console.log('openssl', openssl.OPENSSL_version_major(), openssl.OPENSSL_version_minor(), openssl.OPENSSL_version_patch());


function check_err(result) {
	if (typeof result == 'object' && result !== null) return result;
	else if (result > 0) return result;

	const buffer = new Uint8Array(1000);
	const code = openssl.ERR_get_error();
	openssl.ERR_error_string_n(code, buffer, buffer.byteLength);
	const reason = decoder_lossy.decode(buffer).replace(/\0.*/, '');
	throw new Error(`OpenSSL Error (${result}:${code}): ${reason}`);
}

// Load the certificate and private key
let pkey, cert, id; {
	const pem = Deno.readFileSync('./cert.pem');
	const bio = check_err(openssl.BIO_new_mem_buf(pem, pem.byteLength));
	pkey = check_err(openssl.PEM_read_bio_PrivateKey(bio, null, null, null));
	cert = check_err(openssl.PEM_read_bio_X509(bio, null, null, null));
	openssl.BIO_free(bio);
	
	const fingerprint = new Uint8Array(32);
	const evp_sha256 = check_err(openssl.EVP_sha256());
	check_err(openssl.X509_digest(cert, evp_sha256, fingerprint, null));

	id = from_bytes(fingerprint);
}
export { id };

// Create an SSL context
let ctx; {
	const method = openssl.DTLS_server_method();
	ctx = openssl.SSL_CTX_new(method);
	if (ctx == null) throw new Error("Failed to create the SSL ctx");

	check_err(openssl.SSL_CTX_use_certificate(ctx, cert));
	check_err(openssl.SSL_CTX_use_PrivateKey(ctx, pkey));
	check_err(openssl.SSL_CTX_check_private_key(ctx));
}

export class Dtls {
	#in;
	#out;
	#ssl;
	constructor() {
		this.#in = openssl.BIO_new(openssl.BIO_s_mem());
		this.#out = openssl.BIO_new(openssl.BIO_s_mem());
		this.#ssl = openssl.SSL_new(ctx);
		if (!(this.#in && this.#out && this.#ssl)) throw new Error("");
		openssl.SSL_set_accept_state(this.#ssl);
		openssl.SSL_set_bio(this.#ssl, this.#in, this.#out);
	}
	*push(buffer) {
		check_err(openssl.BIO_write(this.#in, buffer, buffer.byteLength));
		const buff = new Uint8Array(1200);
		while (1) {
			let result;
			if (!openssl.SSL_is_init_finished(this.#ssl)) {
				result = openssl.SSL_accept(this.#ssl);
				if (result > 0) continue;
				result = openssl.SSL_get_error(this.#ssl, result);
			}
			else {
				result = openssl.SSL_read(this.#ssl, buff, buff.byteLength);
				if (result > 0) yield { read: buff.subarray(0, result), write: null };
			}

			while (openssl.BIO_ctrl(this.#out, BIO_CTRL_PENDING, 0, null) > 0) {
				const n = openssl.BIO_read(this.#out, buff, buff.byteLength);
				if (n <= 0) throw new Error("");
				yield { read: null, write: buff.subarray(0, n) };
			}
			const want = openssl.SSL_want(this.#ssl);
			if (want == SSL_READING || want == SSL_NOTHING) break;
			console.log('SSL_want', want);
			check_err(openssl.SSL_get_error(this.#ssl, result));
			return;
		}
	}
	write(buffer) {
		check_err(openssl.SSL_write(this.#ssl, buffer, buffer.byteLength));
	}
}

// Create BIO methods that wrap ReadableStreamDefaultReader and WritableStreamDefaultWriter
// const writers = new Map(), readers = new Map();
// let meth, meth_name; {
// 	meth_name = encoder.encode('swbrd');
// 	const BIO_TYPE_SOURCE_SINK = 0x0400;
// 	meth = check_err(openssl.BIO_meth_new(BIO_TYPE_SOURCE_SINK, meth_name));

// 	const SSL_ERROR_WANT_READ = 2;
// 	const SSL_ERROR_WANT_WRITE = 3;
// 	const read_ex = new Deno.UnsafeCallback({ parameters: ['pointer', 'buffer', 'isize', 'pointer'], result: 'i32' }, function read_ex() {
// 		console.log('read_ex', ...arguments);
// 		return SSL_ERROR_WANT_READ;
// 	});
// 	const write_ex = new Deno.UnsafeCallback({ parameters: ['pointer', 'buffer', 'isize', 'pointer'], result: 'i32' }, function write_ex() {
// 		console.log('write_ex', ...arguments);
// 		return SSL_ERROR_WANT_WRITE;
// 	});

// 	check_err(openssl.BIO_meth_set_read_ex(meth, read_ex.pointer));
// 	check_err(openssl.BIO_meth_set_write_ex(meth, write_ex.pointer));
// }

// Create and wrap the SSLs
// export class Dtls extends Protocol {
// 	#ssl;
// 	// #polite;
// 	#bio;
// 	constructor(inner, { pid } = {}) {
// 		super(...arguments);

// 		// const polite = id < pid;

// 		this.#bio = check_err(openssl.BIO_new(meth));
// 		// check_err(openssl.BIO_make_bio_pair(this.#rbio, this.#wbio));

// 		this.#ssl = check_err(openssl.SSL_new(ctx));
// 		// check_err(openssl.SSL_set_ssl_method(
// 		// 	this.#ssl,
// 		// 	polite ? openssl.DTLS_server_method() : openssl.DTLS_client_method()
// 		// ));
// 		openssl.SSL_set_bio(this.#ssl, this.#bio, this.#bio);
// 		check_err(openssl.SSL_accept(this.#ssl));

// 		// check_err(polite ? openssl.SSL_accept(this.#ssl) : openssl.SSL_connect(this.#ssl));
// 		// check_err(openssl.SSL_do_handshake(this.#ssl));
// 	}
// 	async pull(controller) {
// 		const chunk = new Uint8Array(1650);
// 		const res = check_err(openssl.SSL_read(this.#ssl, chunk, chunk.byteLength));
// 		console.log('read', res);
// 		if (res > 0) {
// 			controller.enqueue(chunk.subarray(0, res));
// 		}
// 	}
// 	async write(chunk) {
// 		const res = check_err(openssl.SSL_write(this.#ssl, chunk, chunk.byteLength));
// 		console.log('write', res);
// 	}
// }
