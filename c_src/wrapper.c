#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/entropy.h"

static mbedtls_entropy_context entropy;
static mbedtls_sha256_context hasher;


__attribute__((constructor)) void init() {
	mbedtls_entropy_init(&entropy);
	mbedtls_sha256_init(&hasher);
}

typedef struct config {
	mbedtls_ssl_config config;
	mbedtls_pk_context pk;
	mbedtls_x509_crt cert;
	mbedtls_ssl_cookie_ctx cookies;
} config;

__attribute__((visibility("default"))) config* create_config(const unsigned char* pem, size_t pem_len, unsigned char fingerprint[32]) {
	config* ret = (config*) malloc(sizeof(config));
	if (!ret) exit(1);

	mbedtls_ssl_config_init(&ret->config);
	mbedtls_pk_init(&ret->pk);
	mbedtls_x509_crt_init(&ret->cert);
	mbedtls_ssl_cookie_init(&ret->cookies);

	mbedtls_ssl_conf_rng(&ret->config, mbedtls_entropy_func, &entropy);
	mbedtls_ssl_conf_read_timeout(&ret->config, 10000);
	mbedtls_ssl_conf_authmode(&ret->config, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&ret->config, &ret->cert, NULL);

	if (mbedtls_ssl_config_defaults(
		&ret->config,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	) != 0) exit(2);

	if (mbedtls_pk_parse_key(
		&ret->pk,
		pem, pem_len,
		NULL, 0,
		mbedtls_entropy_func, &entropy
	) != 0) exit(3);

	if (mbedtls_x509_crt_parse(
		&ret->cert,
		pem, pem_len
	) != 0) exit(4);

	if (mbedtls_ssl_conf_own_cert(
		&ret->config,
		&ret->cert,
		&ret->pk
	) != 0) exit(5);

	if (mbedtls_ssl_cookie_setup(
		&ret->cookies,
		mbedtls_entropy_func,
		&entropy
	) != 0) exit(6);

	mbedtls_ssl_conf_dtls_cookies(
		&ret->config,
		mbedtls_ssl_cookie_write,
		mbedtls_ssl_cookie_check,
		&ret->cookies
	);

	if (mbedtls_sha256_starts(
		&hasher,
		0
	) != 0) exit(7);

	if (mbedtls_sha256_update(
		&hasher,
		ret->cert.raw.p,
		ret->cert.raw.len
	) != 0) exit(8);

	if (mbedtls_sha256_finish(
		&hasher,
		fingerprint
	) != 0) exit(9);
	
	return ret;
}
