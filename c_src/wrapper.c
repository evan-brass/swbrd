#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/entropy.h"

static mbedtls_entropy_context entropy;


__attribute__((constructor)) void init() {
	mbedtls_entropy_init(&entropy);
}

typedef struct config {
	unsigned char fingerprint[32];
	mbedtls_ssl_config config;
	mbedtls_pk_context pk;
	mbedtls_x509_crt cert;
	mbedtls_ssl_cookie_ctx cookies;
} config;

__attribute__((visibility("default"))) config* create_config() {
	config* ret = (config*) malloc(sizeof(config));
	if (!ret) return NULL;
	memset(&ret->fingerprint, 0, sizeof(ret->fingerprint));

	return ret;
}
