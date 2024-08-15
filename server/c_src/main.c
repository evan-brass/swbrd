#include <stdlib.h>
#include <string.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/sha256.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl_cookie.h"

__attribute__((import_name("random"))) int js_random(void* ctx, unsigned char* offset, size_t length);
__attribute__((import_name("log"))) void js_log(void* ctx, int, const char*, int, const char *);
__attribute__((import_name("exit"))) void js_exit(int code);
__attribute__((import_name("cert_pem"))) size_t js_cert_pem(unsigned char* buffer, size_t len);
__attribute__((import_name("now"))) double js_now();
__attribute__((import_name("send"))) int js_send(void* ctx, const unsigned char *buf, size_t len);

static mbedtls_sha256_context hasher;
static mbedtls_ssl_config conf;
static mbedtls_pk_context pkey;
static mbedtls_x509_crt cert;
static mbedtls_ssl_cookie_ctx cookies;

static unsigned char fingerprint[32];
__attribute__((visibility("default"), export_name("fingerprint"))) const unsigned char * get_fingerprint() { return fingerprint; }

typedef struct dtls {
	unsigned char addr[48];
	unsigned char fingerprint[32];
	double mid;
	double fin;
	mbedtls_ssl_context inner;
} dtls;


void set_timer(void* ctx, unsigned int mid, unsigned int fin) {
	dtls* sess = (dtls*) ctx;
	if (fin == 0.0) {
		sess->mid = 0.0;
		sess->fin = 0.0;
		return;
	}
	double now = js_now();
	sess->mid = now + (double) mid;
	sess->fin = now + (double) fin;
}
int get_timer(void* ctx) {
	dtls* sess = (dtls*) ctx;
	if (sess->fin == 0.0) return -1;
	double now = js_now();
	if (sess->fin < now) return 2;
	if (sess->mid < now) return 1;
	return 0;
}
int recv(void* ctx, unsigned char *buf, size_t len) { return MBEDTLS_ERR_SSL_WANT_READ; }

int verify(void* ctx, mbedtls_x509_crt* cert, int preverify, uint32_t* flags) {
	dtls* sess = (dtls*) ctx;
	if (mbedtls_sha256_starts(
		&hasher,
		0
	) != 0) js_exit(-9);
	if (mbedtls_sha256_update(
		&hasher,
		cert->raw.p,
		cert->raw.len
	) != 0) js_exit(-10);
	if (mbedtls_sha256_finish(
		&hasher,
		sess->fingerprint
	) != 0) js_exit(-11);

	*flags = 0;

	return 0;
}

__attribute__((visibility("default"))) unsigned char * push(dtls* sess, size_t wanted) {
	size_t free_space = sess->inner.in_buf_len - (size_t) (sess->inner.in_hdr - sess->inner.in_buf) - sess->inner.in_left;
	if (free_space < wanted) return NULL;
	sess->inner.in_left += wanted;
	return sess->inner.in_hdr;
}

__attribute__((visibility("default"))) int pull(dtls* sess, unsigned char* buffer, size_t len) {
	int ret = mbedtls_ssl_read(&sess->inner, buffer, len);
	if (ret > 0) return ret;
	if (ret == MBEDTLS_ERR_SSL_WANT_READ) return 0;
	
	mbedtls_ssl_free(&sess->inner);
	free(sess);

	return -1;
}

__attribute__((visibility("default"))) unsigned char * peer_fingerprint(dtls* sess) {
	return sess->fingerprint;
}

__attribute__((visibility("default"))) dtls* create_session() {
	dtls* ret = (dtls*) malloc(sizeof(dtls));
	memset(ret->addr, 0, 48);
	memset(ret->fingerprint, 0, 32);
	ret->mid = 0.0;
	ret->fin = 0.0;
	mbedtls_ssl_init(&ret->inner);
	mbedtls_ssl_set_mtu(&ret->inner, 1000);
	mbedtls_ssl_set_verify(&ret->inner, verify, ret);
	mbedtls_ssl_set_timer_cb(&ret->inner, ret, set_timer, get_timer);
	mbedtls_ssl_set_bio(&ret->inner, ret, js_send, recv, NULL);

	// This is a replacement for mbedtls_ssl_set_client_transport_id:
	// By the time this is read, it will have been filled with the ipv6 socket address of the peer.
	ret->inner.cli_id = ret->addr;
	ret->inner.cli_id_len = 48;

	if (mbedtls_ssl_setup(
		&ret->inner,
		&conf
	) != 0) {
		mbedtls_ssl_free(&ret->inner);
		free(ret);
		js_exit(-8);
		return NULL;
	}

	return ret;
}

int main() {
	unsigned char pem_buffer[2048];
	size_t pem_len = js_cert_pem(pem_buffer, sizeof(pem_buffer));

	mbedtls_sha256_init(&hasher);
	mbedtls_ssl_config_init(&conf);
	mbedtls_pk_init(&pkey);
	mbedtls_x509_crt_init(&cert);
	mbedtls_ssl_cookie_init(&cookies);

	mbedtls_ssl_conf_rng(&conf, js_random, NULL);
	mbedtls_ssl_conf_dbg(&conf, js_log, NULL);
	mbedtls_ssl_conf_read_timeout(&conf, 10000);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cert, NULL);
	mbedtls_debug_set_threshold(3);

	if (mbedtls_ssl_config_defaults(
		&conf,
		MBEDTLS_SSL_IS_SERVER,
		MBEDTLS_SSL_TRANSPORT_DATAGRAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	) != 0) js_exit(-1);

	if (mbedtls_pk_parse_key(
		&pkey,
		pem_buffer, pem_len,
		NULL, 0,
		js_random, NULL
	) != 0) js_exit(-2);
	if (mbedtls_x509_crt_parse(
		&cert,
		pem_buffer, pem_len
	) != 0) js_exit(-3);

	if (mbedtls_ssl_conf_own_cert(
		&conf,
		&cert,
		&pkey
	) != 0) js_exit(-4);

	if (mbedtls_ssl_cookie_setup(&cookies, js_random, NULL) != 0) js_exit(-12);
	mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cookies);

	// Get our local SHA-256 fingerprint
	if (mbedtls_sha256_starts(
		&hasher,
		0
	) != 0) js_exit(-5);
	if (mbedtls_sha256_update(
		&hasher,
		cert.raw.p,
		cert.raw.len
	) != 0) js_exit(-6);
	if (mbedtls_sha256_finish(
		&hasher,
		fingerprint
	) != 0) js_exit(-7);
}
