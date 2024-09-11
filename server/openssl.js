import { decoder_lossy } from "../src/util.js";

const libpath = (Deno.build.os == 'darwin') ? '/usr/local/lib/libssl.3.dylib' : '/usr/lib/libssl.so.3';
export const {symbols: openssl} = Deno.dlopen(libpath, {
	OPENSSL_version_major: { parameters: [], result: 'u32' },
	OPENSSL_version_minor: { parameters: [], result: 'u32' },
	OPENSSL_version_patch: { parameters: [], result: 'u32' },

	DTLS_method: { parameters: [], result: 'pointer' },
	DTLS_server_method: { parameters: [], result: 'pointer' },
	DTLS_client_method: { parameters: [], result: 'pointer' },
	DTLS_set_timer_cb: { parameters: ['pointer', 'function'], result: 'pointer' },

	EVP_sha256: { parameters: [], result: 'pointer' },

	SSL_CTX_new: { parameters: ['pointer' /* method */], result: 'pointer' },
	SSL_CTX_free: { parameters: ['pointer' /* ctx */], result: 'void' },
	SSL_CTX_use_certificate: { parameters: ['pointer' /* ctx */, 'pointer' /* X509 */], result: 'i32' },
	SSL_CTX_use_PrivateKey: { parameters: ['pointer' /* ctx */, 'pointer' /* EVP_PKEY */], result: 'i32' },
	SSL_CTX_check_private_key: { parameters: ['pointer' /* ctx */], result: 'i32' },
	SSL_CTX_set_verify: { parameters: ['pointer' /* ctx */, 'i32' /* mode */, 'function' /* verify callback */], result: 'void' },
	SSL_CTX_set_verify_depth: { parameters: ['pointer' /* ctx */, 'i32' /* depth */], result: 'void' },

	SSL_new: { parameters: ['pointer'/* ctx */], result: 'pointer' },
	SSL_free: { parameters: ['pointer'/* ctx */], result: 'void' },
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
	SSL_get0_peer_certificate: { parameters: ['pointer'], result: 'pointer' },

	ERR_get_error: { parameters: [], result: 'u32' },
	ERR_error_string_n: { parameters: ['u32', 'buffer', 'isize'], result: 'void' },

	// BIO_meth_new: { parameters: ['i32', 'buffer'], result: 'pointer' },
	// BIO_meth_set_read_ex: { parameters: ['pointer', 'function'], result: 'i32' },
	// BIO_meth_set_write_ex: { parameters: ['pointer', 'function'], result: 'i32' },

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
	// BIO_new_bio_pair: { parameters: ['pointer', 'isize', 'pointer', 'isize'], result: 'pointer' },

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
export const BIO_CTRL_PENDING = 10;

export const SSL_NOTHING = 1;
export const SSL_READING = 3;

export const SSL_VERIFY_PEER = 0x01;
export const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;

console.log('openssl', openssl.OPENSSL_version_major(), openssl.OPENSSL_version_minor(), openssl.OPENSSL_version_patch());

export function check_err(result) {
	if (typeof result == 'object' && result !== null) return result;
	else if (result > 0) return result;

	const buffer = new Uint8Array(1000);
	const code = openssl.ERR_get_error();
	openssl.ERR_error_string_n(code, buffer, buffer.byteLength);
	const reason = decoder_lossy.decode(buffer).replace(/\0.*/, '');
	throw new Error(`OpenSSL Error (${result}:${code}): ${reason}`);
}
