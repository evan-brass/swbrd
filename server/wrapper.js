import { from_bytes } from "../src/id.js";
import { encoder } from '../src/util.js';

const res = Deno.dlopen(new URL('./wrapper', import.meta.url), {
	create_config: {parameters: ['buffer', 'isize', 'buffer'], result: 'pointer'},
});

let cert = Deno.readTextFileSync('./cert.pem');
if (!cert.endsWith('\0')) cert += '\0';
cert = encoder.encode(cert);

const fingerprint = new Uint8Array(32);
const config_ptr = res.symbols.create_config(cert, cert.byteLength, fingerprint);

export const id = from_bytes(fingerprint);

console.log(config_ptr, id);
