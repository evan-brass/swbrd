import { idf } from './cert.js';
import { Conn } from './conn.js';
import { query_txt } from './dns.js';
/**
 * Example Addr-esses:
 * const a = new Addr('udp:seed.evan-brass.net'); await a.resolve_id(); const conn = a.connect();
 * const conn = new Addr('udp:vMLqtj41eqxrH4ExSw893MLbgDm1JHWqkv9R9AMqhHDE@example.com').connect();
 * const conn = new Addr('turn:U5PYjsHYz77HroCoCTy7hM9YuZ9G6oFZ6z3mWrFCP8uF@127.0.0.1?turn_transport=tcp').connect();
 */
export class Addr extends URL {
	#id;
	async resolve_id() {
		const {username, hostname} = this.#authority();
		this.#id ??= idf.fromString(username);
		for await (const txt of query_txt(hostname, {prefix: `swbrd(${idf.algorithm})=`})) {
			this.#id ??= idf.fromString(txt);
		}
		return this.#id;
	}
	#authority() {
		// Use two URLS to unhide default ports: new URL('https://test.com:443').port == '' and new URL('http://test.com:80').port == ''
		const http = new URL(this.href.replace(/^[^:]+:/, 'http:'));
		const https = new URL(this.href.replace(/^[^:]+:/, 'https:'));
		const host = (http.host.length < https.host.length) ? https.host : http.host;
		const port = parseInt(http.port || https.port || 3478);
		return { username: http.username, password: http.password, hostname: http.hostname, host, port };
	}
	config() {
		if (/^turns?:/i.test(this.protocol)) {
			const {host} = this.#authority();
			let transport = this.searchParams.get('turn_transport') || 'tcp';
			transport = (transport == 'udp') ? '' : '?transport=' + transport;
			return {
				iceTransportPolicy: 'relay',
				iceServers: [{
					urls: `${this.protocol}${host}${transport}`,
					username: this.searchParams.get('turn_username') || 'guest',
					credential: this.searchParams.get('turn_credential') || 'the/guest/turn/credential/constant'
				}]
			};
		}
		return null;
	}
	connect(config = null) {
		const {hostname, port, username, password: ice_pwd} = this.#authority();
		this.#id ??= idf.fromString(username);
		if (!this.#id) return;
		let setup = this.searchParams.get('setup');
		let ice_lite = this.searchParams.get('ice_lite');

		// Configure connection parameters
		if (/^udp:/i.test(this.protocol)) {
			setup ??= 'passive';
			ice_lite ??= true;		}

		const ret = new Conn(this.#id, {
			setup,
			ice_lite,
			ice_pwd,
			...config,
			...this.config()
		});

		// Add ice candidates
		for (const candidate of this.searchParams.getAll('candidate').map(s => {
			s = decodeURIComponent(s);
			try { return JSON.parse(s); }
			catch { return s; }
		})) {
			ret.addIceCandidate(candidate);
		}
		if (/^udp:/i.test(this.protocol)) {
			ret.addIceCandidate({ candidate: `candidate:foundation 1 udp 42 ${hostname} ${port} typ host` });
		}

		return ret;
	}
}
