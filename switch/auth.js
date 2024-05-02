import { md5 } from "./md5.js";
import { encoder } from "./util.js";

export const realm = Deno.env.get('REALM') ?? 'none';
const turn_pass = Deno.env.get('TURN_CREDENTIAL') ?? 'the/guest/turn/credential/constant';
const ice_pass = Deno.env.get('ICE_PWD') ?? 'the/ice/password/constant';

export async function long_term(user, pass = turn_pass) {
	return await crypto.subtle.importKey('raw', md5(`${user}:${realm}:${pass}`), {
		name: 'HMAC',
		hash: 'SHA-1'
	}, true, ['sign', 'verify']);
}

export async function short_term(pass = ice_pass) {
	return await crypto.subtle.importKey('raw', encoder.encode(pass), {
		name: 'HMAC',
		hash: 'SHA-1'
	}, true, ['sign', 'verify']);
}
