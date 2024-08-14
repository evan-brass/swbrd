import { algorithm, from_string } from "./id.js";
import { Conn } from './conn.js';
import { query_txt } from './dns.js';
/**
 * Example Addr-esses:
 * const a = new Addr('udp:seed.evan-brass.net'); await a.resolve_id(); const conn = a.connect();
 * const conn = new Addr('udp:vMLqtj41eqxrH4ExSw893MLbgDm1JHWqkv9R9AMqhHDE@example.com').connect();
 * const conn = new Addr('turn+tcp:U5PYjsHYz77HroCoCTy7hM9YuZ9G6oFZ6z3mWrFCP8uF@127.0.0.1').connect();
 */
export class Addr extends URL {
	#id;
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
	connect(config = null) {
		const {address, port, username, password: ice_pwd} = this.#authority();
		this.#id ??= from_string(username);
		if (!this.#id) return;
		const setup = this.searchParams.get('setup') ?? 'passive';
		let ice_lite = this.searchParams.get('ice_lite');

		// Configure connection parameters
		if (/^udp:/i.test(this.protocol)) {
			ice_lite ??= true;
		}

		// Adjust the config if needed
		let adjustment = null, turn_res;
		if ((turn_res = /^(turns?)(?:\+(tcp|udp))?:/i.exec(this.protocol))) {
			const {1: proto, 2: transport} = turn_res;
			const {host} = this.#authority();
			adjustment = {
				iceTransportPolicy: 'relay',
				iceServers: [{
					urls: `${proto}:${host}${transport ? '?transport=' + transport : ''}`,
					username: this.searchParams.get('turn_username') || 'guest',
					credential: this.searchParams.get('turn_credential') || 'password'
				}]
			};
		}

		// Prepare the candidates 
		const candidates = Array.from(this.searchParams.getAll('candidate'), s => {
			s = decodeURI(s);
			try { return JSON.parse(s); } catch { return s }
		});
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
			ice_lite,
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
					ice_lite,
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
