export function struct_buffer_to_js_buffer(res) {
	console.assert(res instanceof Uint8Array);
	console.assert(res.byteLength == 16);

}

const signatures = [
	'pointer new_x509_crt()',
	'void x509_crt_init(pointer)',
	'i32 x509_crt_parse(pointer,buffer,usize)',
	'usize get_x509_crt_len(pointer)',
	'pointer get_x509_crt_ptr(pointer)',

	'pointer new_pk_context()',
	'void pk_init(pointer)',
	'i32 pk_parse_key(pointer,buffer,usize,buffer,usize,pointer,pointer)',

	'pointer new_ssl_config()',
	'void ssl_config_init(pointer)',
	'i32 ssl_config_defaults(pointer,i32,i32,i32)',
	'i32 ssl_conf_own_cert(pointer,pointer,pointer)',

	'pointer new_ssl_context()',
	'void ssl_init(pointer)',
];
const symbols = {};
for (const sig of signatures) {
	const res = /^(pointer|i32|void|usize) ([a-z_0-9]+)\(((pointer|i32|usize|buffer)(,(pointer|i32|usize|buffer))*)?\)$/.exec(sig);
	const {1: result, 2: name, 3: parameters} = res;
	symbols[name] = {
		name: name.replace(/^(?!get_)(new_)?/, '$1mbedtls_'),
		result,
		parameters: parameters ? parameters.split(',') : []
	};
}
const lib = Deno.dlopen('mbedtls.so', symbols);
console.log(lib);
export default lib.symbols;
