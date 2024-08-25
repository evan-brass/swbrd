import { algorithm, from_string } from "./id.js";
import { Conn } from './conn.js';
import { query_txt } from './dns.js';
import { default_turn_credential, default_turn_username } from "./const.js";
/**
 * Example Addr-esses:
 * const a = new Addr('udp:seed.evan-brass.net'); await a.resolve_id(); const conn = a.connect();
 * const conn = new Addr('udp:vMLqtj41eqxrH4ExSw893MLbgDm1JHWqkv9R9AMqhHDE@example.com').connect();
 * const conn = new Addr('turn+tcp:U5PYjsHYz77HroCoCTy7hM9YuZ9G6oFZ6z3mWrFCP8uF@127.0.0.1').connect();
 */
export class Addr extends URL {
	#id;
	get id() {
		if (!this.#id) {
			const { username } = this.authority;
			this.#id = from_string(username);
		}
		return this.#id;
	}

	async resolve_id() {
		if (this.id) return this.#id;
		const {hostname} = this.authority;
		for await (const txt of query_txt(hostname, {prefix: `swbrd(${algorithm})=`})) {
			this.#id ??= from_string(txt);
		}
		return this.#id;
	}
	#authority;
	get authority() {
		if (this.#authority?.href != this.href) {
			// Use two URLS to unhide default ports: new URL('https://test.com:443').port == '' and new URL('http://test.com:80').port == ''
			const http = new URL(this.href.replace(/^[^:]+:/, 'http:'));
			const https = new URL(this.href.replace(/^[^:]+:/, 'https:'));
			const host = (http.host.length < https.host.length) ? https.host : http.host;
			const port = parseInt(http.port || https.port || 3478);
			const address = http.hostname.replaceAll(/[\[\]]/g, '')
			this.#authority = { href: this.href, username: decodeURIComponent(http.username), password: decodeURIComponent(http.password), hostname: http.hostname, host, port, address };
		}
		return this.#authority;
	}
	temp_adjustment() {
		const turn_res = /^(turns?)(?:\+(tcp|udp))?:/i.exec(this.protocol);
		if (!turn_res) return null;
		const {1: proto, 2: transport} = turn_res;
		const { host } = this.authority;
		return {
			iceTransportPolicy: 'relay',
			iceServers: [{
				urls: `${proto}:${host}${transport ? '?transport=' + transport : ''}`,
				username: this.searchParams.get('turn_username') || default_turn_username,
				credential: this.searchParams.get('turn_credential') || default_turn_credential
			}]
		};
	}
	*candidates() {
		// Yield candidate search params
		for (let val of this.searchParams.getAll('candidate')) {
			val = decodeURIComponent(val);
			let json;
			// Try to parse the candidate as JSON
			try { json = JSON.parse(val); } catch {/* Do Nothing */}
			if (typeof json == 'object') { yield json; }
			
			// Yield the candidate as a string
			else { yield val; }
		}

		// Yield protocol specific candidate
		if (/^udp:/i.test(this.protocol)) {
			yield {address, port};
		}
		else if (/^(turns?)(?:\+(tcp|udp))?:/i.test(this.protocol)) {
			yield {};
		}
	}
	connect(config = null) {
		if (!this.id) return;

		// Adjust the config if needed
		const adjustment = this.temp_adjustment();

		const {password: ice_pwd} = this.authority;
		const setup = this.searchParams.get('setup') ?? 'passive';

		// Create the connection
		const ret = new Conn(this.id, {
			ice_pwd, setup,
			...config,
			...adjustment
		});

		// Spawn the task to signal the connection
		(async () => {
			for (const candidate of this.candidates()) {
				await ret.addIceCandidate(candidate);
			}

			// Undo the adjustement
			if (adjustment) {
				// Wait for the connection to succeed (or close)
				while (!['connected', 'closed'].includes(ret.connectionState)) await new Promise(
					res => ret.addEventListener('connectionstatechange', res, {once: true})
				);

				// If the connection is closed, then the config adjustment is irrelevant
				if (ret.connectionState == 'closed') return;
				
				// Remove the adjustment
				ret.setConfiguration(config);
				
				// Restart ICE so that the configuration can take effect
				ret.restartIce();
			}
		})();

		return ret;
	}
}
