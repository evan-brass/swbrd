import { from_bytes } from '../src/id.js';
import {
	openssl,
	check_err,
	SSL_NOTHING, SSL_READING,
	BIO_CTRL_PENDING
} from './openssl.js';

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
