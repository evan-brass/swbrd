#include <stdlib.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/sha256.h>

#define MAKE_CONSTRUCTOR(TYPE) TYPE * new_ ## TYPE() { \
	return (TYPE *) malloc(sizeof(TYPE)); \
}
MAKE_CONSTRUCTOR(mbedtls_hmac_drbg_context)
MAKE_CONSTRUCTOR(mbedtls_sha256_context)
MAKE_CONSTRUCTOR(mbedtls_x509_crt)
MAKE_CONSTRUCTOR(mbedtls_pk_context)
MAKE_CONSTRUCTOR(mbedtls_entropy_context)
MAKE_CONSTRUCTOR(mbedtls_ssl_config)
MAKE_CONSTRUCTOR(mbedtls_ssl_context)
