
relay/mbedtls.wasm: vendor/mbedtls/library/* vendor/mbedtls/include/* c-src/*
	/opt/wasi-sdk/bin/wasm32-wasi-clang -O3 \
		-Ic-src -Ivendor/mbedtls/include \
		-DMBEDTLS_CONFIG_FILE=\"config.h\" \
		-fvisibility=default \
		-Wl,--export-dynamic,--export=malloc,--export=free,--export=strlen \
		-o $@ \
		$(filter %.c, $^)
