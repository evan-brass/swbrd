import { md5 } from "./md5.js";
import { encoder } from "./util.js";

export const users = new Map();

export const realm = Deno.env.get('REALM') ?? 'none';
export async function long_term(user, pass) {
	const key = await crypto.subtle.importKey('raw', md5(`${user}:${realm}:${pass}`), {
		name: 'HMAC',
		hash: 'SHA-1'
	}, true, ['sign', 'verify']);
	users.set(user, key);
}

export async function short_term(user, pass) {
	const key = await crypto.subtle.importKey('raw', encoder.encode(pass), {
		name: 'HMAC',
		hash: 'SHA-1'
	}, true, ['sign', 'verify']);
	users.set(user, key);
}
