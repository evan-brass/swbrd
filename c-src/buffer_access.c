#include <stdlib.h>
#include <mbedtls/x509_crt.h>

size_t get_x509_crt_len(mbedtls_x509_crt* cert) {
	return cert->raw.len;
}
unsigned char* get_x509_crt_ptr(mbedtls_x509_crt* cert) {
	return cert->raw.p;
}
