#include <stdlib.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"

__attribute__((import_name("random"))) int js_random(void* ctx, unsigned char* offset, size_t length);
__attribute__((import_name("log"))) void js_log(void* ctx, int, const char*, int, const char *);
__attribute__((import_name("set_timer"))) void js_set_timer(void* ctx, unsigned int, unsigned int);
__attribute__((import_name("get_timer"))) int js_get_timer(void* ctx);
__attribute__((import_name("send"))) int js_send(void* ctx, const unsigned char *buf, size_t len);
__attribute__((import_name("recv"))) int js_recv(void* ctx, unsigned char *buf, size_t len);
__attribute__((import_name("verify"))) int js_verify(void* ctx, unsigned char* fingerprint, int preverify);
__attribute__((import_name("cert_pem"))) size_t cert_pem(unsigned char* buffer, size_t len);

static unsigned char fingerprint[32];
static mbedtls_ssl_config conf;
static mbedtls_pk_context pkey;
static mbedtls_x509_crt cert;
static mbedtls_ssl_cookie_ctx cookies;

int main() {
	unsigned char pem_buffer[2048];
	mbedtls_sha256_context hasher;

	size_t pem_len = cert_pem(pem_buffer, sizeof(pem_buffer));

	mbedtls_sha256_init(&hasher);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_conf_rng(&conf, js_random, NULL);
	mbedtls_pk_init(&pkey);
	mbedtls_x509_crt_init(&cert);
	mbedtls_ssl_cookie_init(&cookies);

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cert, NULL); // TODO: I only want to check the expiration, not the CA so... hmm

	if (mbedtls_ssl_config_defaults(
		&conf,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	) != 0) exit(-1);
	if (mbedtls_pk_parse_key(
		&pkey,
		pem_buffer, pem_len,
		NULL, 0,
		js_random, NULL
	) != 0) exit(-1);
	if (mbedtls_x509_crt_parse(
		&cert,
		pem_buffer, pem_len
	) != 0) exit(-1);

	if (mbedtls_ssl_conf_own_cert(
		&conf,
		&cert,
		&pkey
	) != 0) exit(-1);

	// Get the sha256 fingerprint of the cert
	if (mbedtls_sha256_starts(
		&hasher,
		0
	) != 0) exit(-1);
	if (mbedtls_sha256_update(
		&hasher,
		cert.raw.p,
		cert.raw.len
	) != 0) exit(-1);
	if (mbedtls_sha256_finish(
		&hasher,
		fingerprint
	) != 0) exit(-1);
}

typedef struct ssl_config {
	mbedtls_ssl_config server;
	mbedtls_ssl_config client;
	mbedtls_pk_context pkey;
	mbedtls_x509_crt cert;
	unsigned char fingerprint[32];
} ssl_config;

__attribute__((visibility("default"), export_name("fingerprint"))) unsigned char * get_fingerprint(ssl_config* conf) {
	return fingerprint;
}

int verify(void* ctx, mbedtls_x509_crt* cert, int preverify, uint32_t* flags) {
	mbedtls_sha256_context hasher;
	mbedtls_sha256_init(&hasher);

	unsigned char fingerprint[32];

	if (mbedtls_sha256_starts(
		&hasher,
		0
	) != 0) preverify = -1;
	if (mbedtls_sha256_update(
		&hasher,
		cert->raw.p,
		cert->raw.len
	) != 0) preverify = -1;
	if (mbedtls_sha256_finish(
		&hasher,
		fingerprint
	) != 0) preverify = -1;

	mbedtls_sha256_free(&hasher);

	*flags = 0;

	return js_verify(ctx, fingerprint, preverify);
}

__attribute__((visibility("default"))) ssl_config* setup(unsigned char* buffer, size_t length) {
	ssl_config* ret = (ssl_config*)malloc(sizeof(ssl_config));
	if (!ret) goto done;

	mbedtls_sha256_context hasher;
	mbedtls_sha256_init(&hasher);

	mbedtls_ssl_config_init(&ret->server);
	mbedtls_ssl_config_init(&ret->client);
	mbedtls_ssl_conf_rng(&ret->server, js_random, NULL);
	mbedtls_ssl_conf_rng(&ret->client, js_random, NULL);
	// mbedtls_ssl_conf_dbg(&ret->server, js_log, NULL);
	// mbedtls_ssl_conf_dbg(&ret->client, js_log, NULL);
	mbedtls_pk_init(&ret->pkey);
	mbedtls_x509_crt_init(&ret->cert);

	mbedtls_ssl_conf_authmode(&ret->server, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_authmode(&ret->client, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_ca_chain(&ret->server, &ret->cert, NULL);
	mbedtls_ssl_conf_ca_chain(&ret->client, &ret->cert, NULL);

	if (mbedtls_ssl_config_defaults(
		&ret->server,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	) != 0) goto abort;
	if (mbedtls_ssl_config_defaults(
		&ret->client,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	) != 0) goto abort;
	if (mbedtls_pk_parse_key(
		&ret->pkey,
		buffer, length,
		NULL, 0,
		js_random, NULL
	) != 0) goto abort;
	if (mbedtls_x509_crt_parse(
		&ret->cert,
		buffer, length
	) != 0) goto abort;

	if (mbedtls_ssl_conf_own_cert(
		&ret->server,
		&ret->cert,
		&ret->pkey
	) != 0) goto abort;
	if (mbedtls_ssl_conf_own_cert(
		&ret->client,
		&ret->cert,
		&ret->pkey
	) != 0) goto abort;

	// Get the sha256 fingerprint of the cert
	if (mbedtls_sha256_starts(
		&hasher,
		0
	) != 0) goto abort;
	if (mbedtls_sha256_update(
		&hasher,
		ret->cert.raw.p,
		ret->cert.raw.len
	) != 0) goto abort;
	if (mbedtls_sha256_finish(
		&hasher,
		ret->fingerprint
	) != 0) goto abort;

	
	// Success
	goto done;

	// Failure
	abort:
	mbedtls_ssl_config_free(&ret->server);
	mbedtls_ssl_config_free(&ret->client);
	mbedtls_pk_free(&ret->pkey);
	mbedtls_x509_crt_free(&ret->cert);
	free(ret);
	ret = NULL;

	done:
	mbedtls_sha256_free(&hasher);
	free(buffer);
	return ret;
}

__attribute__((visibility("default"))) mbedtls_ssl_context* session() {
	mbedtls_ssl_context* ret = (mbedtls_ssl_context*) malloc(sizeof(mbedtls_ssl_context));
	if (ret == NULL) goto abort;

	mbedtls_ssl_init(ret);
	mbedtls_ssl_set_mtu(ret, 1200);
	mbedtls_ssl_set_verify(ret, verify, ret);
	mbedtls_ssl_set_timer_cb(ret, ret, js_set_timer, js_get_timer);
	mbedtls_ssl_set_bio(ret, ret, js_send, js_recv, NULL);

	if (mbedtls_ssl_setup(
		ret,
		&conf
	) != 0) goto abort;

	goto done;

	abort:
	mbedtls_ssl_free(ret);
	free(ret);
	ret = NULL;

	done:
	return ret;
}

__attribute__((visibility("default"))) int write(mbedtls_ssl_context* ssl, const unsigned char* buff, size_t len) {
	return mbedtls_ssl_write(ssl, buff, len);
}
__attribute__((visibility("default"))) int read(mbedtls_ssl_context* ssl, unsigned char* buff, size_t len) {
	return mbedtls_ssl_read(ssl, buff, len);
}
__attribute__((visibility("default"))) int close(mbedtls_ssl_context* ssl) {
	return mbedtls_ssl_close_notify(ssl);
}
__attribute__((visibility("default"))) int pending(mbedtls_ssl_context* ssl) {
	return mbedtls_ssl_check_pending(ssl);
}
