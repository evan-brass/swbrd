
dist/dtls.wasm: c_src/main.c mbedtls/library/*.c
	clang -O3 \
		-target wasm32-unknown-wasi \
		-Ic_src -Imbedtls/include \
		-DMBEDTLS_CONFIG_FILE=\"wasm_config.h\" \
		-Wl,--export-dynamic,--export=malloc,--export=free,--export=realloc,--export=strlen \
		-o $@ \
		$^
	cp mbedtls/LICENSE dist
	wasm2wat $@ | grep -E "import|export" > dist/syms.wat
