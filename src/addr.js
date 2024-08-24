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
	// This constructor disables support for using Url(url, base)
	constructor(url, { id, base } = {}) {
		super(url, base);
		this.#id = id;
	}
	async resolve_id() {
		const {username, hostname} = this.#authority();
		this.#id ??= from_string(username);
		for await (const txt of query_txt(hostname, {prefix: `swbrd(${algorithm})=`})) {
			this.#id ??= from_string(txt);
		}
		return this.#id;
	}
	#authority() {
		// Use two URLS to unhide default ports: new URL('https://test.com:443').port == '' and new URL('http://test.com:80').port == ''
		const http = new URL(this.href.replace(/^[^:]+:/, 'http:'));
		const https = new URL(this.href.replace(/^[^:]+:/, 'https:'));
		const host = (http.host.length < https.host.length) ? https.host : http.host;
		const port = parseInt(http.port || https.port || 3478);
		const address = http.hostname.replaceAll(/[\[\]]/g, '')
		return { username: decodeURIComponent(http.username), password: decodeURIComponent(http.password), hostname: http.hostname, host, port, address };
	}
	temp_adjustment() {
		const turn_res = /^(turns?)(?:\+(tcp|udp))?:/i.exec(this.protocol);
		if (!turn_res) return null;
		const {1: proto, 2: transport} = turn_res;
		const { host } = this.#authority();
		return {
			iceTransportPolicy: 'relay',
			iceServers: [{
				urls: `${proto}:${host}${transport ? '?transport=' + transport : ''}`,
				username: this.searchParams.get('turn_username') || default_turn_username,
				credential: this.searchParams.get('turn_credential') || default_turn_credential
			}]
		};
	}
	connect(config = null) {
		const {address, port, username, password: ice_pwd} = this.#authority();
		this.#id ??= from_string(username);
		if (!this.#id) return;
		const setup = this.searchParams.get('setup') ?? 'passive';

		// Adjust the config if needed
		const adjustment = this.temp_adjustment();

		// Prepare the candidates 
		const candidates = Array.isArray(config?.candidates) ? config?.candidates : [];
		for (let val of this.searchParams.getAll('candidate')) {
			val = decodeURIComponent(val);
			try {
				// Try to parse as JSON and add an object candidate
				candidates.push(JSON.parse(val));
			} catch {
				// Otherwise leave the candidate as a string
				candidates.push(val);
			}
		}

		// If manual candidates aren't specified then use protocol specific default candidate
		if (candidates.length < 1) {
			if (/^udp:/i.test(this.protocol)) {
				candidates.push({address, port, transport: 'udp'});
			}
			else if (/^(turns?)(?:\+(tcp|udp))?:/i.test(this.protocol)) {
				candidates.push({});
			}
		}

		// Create the connection
		const ret = new Conn(this.#id, {
			setup,
			ice_pwd,
			...config,
			...adjustment
		});

		// Spawn the task to signal the connection
		(async () => {
			for (const candidate of candidates) {
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
				ret.setConfiguration({
					setup,
					ice_pwd,
					...config
				});
				
				// Restart ICE so that the configuration can take effect
				ret.restartIce();
			}
		})();

		return ret;
	}
}
