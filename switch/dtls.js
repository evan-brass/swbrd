import { Protocol } from "./proto.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// const libpath = (Deno.build.os == 'darwin') ? '/opt/homebrew/opt/openssl@3.3/lib/libssl.3.dylib' : '/usr/lib/libssl.so.3';
const libpath = '/opt/homebrew/opt/openssl@3.3/lib/libssl.3.dylib';

const openssl = Deno.dlopen(libpath, {
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
	SSL_accept: { parameters: ['pointer'], result: 'i32' },
	SSL_connect: { parameters: ['pointer'], result: 'i32' },
	SSL_get_error: { parameters: ['pointer', 'i32'], result: 'i32' },
	SSL_do_handshake: { parameters: ['pointer'], result: 'i32' },
	SSL_write: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
	SSL_read: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
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
	BIO_s_dgram_mem: { parameters: [], result: 'pointer' },
	BIO_free: { parameters: ['pointer'], result: 'void' },
	BIO_read: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
	BIO_write: { parameters: ['pointer', 'buffer', 'i32'], result: 'i32' },
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

console.log('openssl', openssl.symbols.OPENSSL_version_major(), openssl.symbols.OPENSSL_version_minor(), openssl.symbols.OPENSSL_version_patch());

function check_err(result) {
	if (typeof result == 'object' && result !== null) return result;
	else if (result > 0) return result;

	const buffer = new Uint8Array(1000);
	const code = openssl.symbols.ERR_get_error();
	openssl.symbols.ERR_error_string_n(code, buffer, buffer.byteLength);
	const reason = decoder.decode(buffer).replace(/\0.*/, '');
	throw new Error(`OpenSSL Error (${result}:${code}): ${reason}`);
}

// Load the certificate and private key
let pkey, cert, id; {
	const txt = Deno.env.get('CERT') ?? Deno.readTextFileSync('./cert.pem');
	const encoded = encoder.encode(txt);
	const bio = check_err(openssl.symbols.BIO_new_mem_buf(encoded, encoded.byteLength));
	pkey = check_err(openssl.symbols.PEM_read_bio_PrivateKey(bio, null, null, null));
	cert = check_err(openssl.symbols.PEM_read_bio_X509(bio, null, null, null));
	openssl.symbols.BIO_free(bio);
	
	const fingerprint = new Uint8Array(32);
	const evp_sha256 = check_err(openssl.symbols.EVP_sha256());
	check_err(openssl.symbols.X509_digest(cert, evp_sha256, fingerprint, null));

	id = BigInt('0x' + Array.from(fingerprint, b => b.toString(16).padStart(2, '0')).join(''));
}
export { id };

// Create an SSL context
let ctx; {
	// const method = openssl.symbols.DTLS_server_method();
	const method = openssl.symbols.DTLS_client_method();
	ctx = openssl.symbols.SSL_CTX_new(method);
	if (ctx == null) throw new Error("Failed to create the SSL ctx");

	check_err(openssl.symbols.SSL_CTX_use_certificate(ctx, cert));
	check_err(openssl.symbols.SSL_CTX_use_PrivateKey(ctx, pkey));
	check_err(openssl.symbols.SSL_CTX_check_private_key(ctx));
	openssl.symbols.SSL_CTX_set_verify(ctx, )
}

// Create BIO methods that wrap ReadableStreamDefaultReader and WritableStreamDefaultWriter
const writers = new Map(), readers = new Map();
let meth, meth_name; {
	meth_name = encoder.encode('swbrd');
	const BIO_TYPE_SOURCE_SINK = 0x0400;
	meth = check_err(openssl.symbols.BIO_meth_new(BIO_TYPE_SOURCE_SINK, meth_name));

	const SSL_ERROR_WANT_READ = 2;
	const SSL_ERROR_WANT_WRITE = 3;
	const read_ex = new Deno.UnsafeCallback({ parameters: ['pointer', 'buffer', 'isize', 'pointer'], result: 'i32' }, function read_ex() {
		console.log('read_ex', ...arguments);
		return SSL_ERROR_WANT_READ;
	});
	const write_ex = new Deno.UnsafeCallback({ parameters: ['pointer', 'buffer', 'isize', 'pointer'], result: 'i32' }, function write_ex() {
		console.log('write_ex', ...arguments);
		return SSL_ERROR_WANT_WRITE;
	});

	check_err(openssl.symbols.BIO_meth_set_read_ex(meth, read_ex.pointer));
	check_err(openssl.symbols.BIO_meth_set_write_ex(meth, write_ex.pointer));
}

// Create and wrap the SSLs
export class Dtls extends Protocol {
	#ssl;
	// #polite;
	#bio;
	constructor(inner, { pid } = {}) {
		super(...arguments);

		// const polite = id < pid;

		this.#bio = check_err(openssl.symbols.BIO_new(meth));
		// check_err(openssl.symbols.BIO_make_bio_pair(this.#rbio, this.#wbio));

		this.#ssl = check_err(openssl.symbols.SSL_new(ctx));
		// check_err(openssl.symbols.SSL_set_ssl_method(
		// 	this.#ssl,
		// 	polite ? openssl.symbols.DTLS_server_method() : openssl.symbols.DTLS_client_method()
		// ));
		openssl.symbols.SSL_set_bio(this.#ssl, this.#bio, this.#bio);
		check_err(openssl.symbols.SSL_accept(this.#ssl));

		// check_err(polite ? openssl.symbols.SSL_accept(this.#ssl) : openssl.symbols.SSL_connect(this.#ssl));
		// check_err(openssl.symbols.SSL_do_handshake(this.#ssl));
	}
	async pull(controller) {
		const chunk = new Uint8Array(1650);
		const res = check_err(openssl.symbols.SSL_read(this.#ssl, chunk, chunk.byteLength));
		console.log('read', res);
		if (res > 0) {
			controller.enqueue(chunk.subarray(0, res));
		}
	}
	async write(chunk) {
		const res = check_err(openssl.symbols.SSL_write(this.#ssl, chunk, chunk.byteLength));
		console.log('write', res);
	}
}
