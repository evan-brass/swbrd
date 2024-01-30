import { Id } from './id.js';
import { Conn, Sig } from './conn.js';
import { query_txt } from './dns.js';
/**
 * Example Addr-esses:
 * const a = new Addr('udp:seed.evan-brass.net'); await a.resolve_id(); const conn = a.connect();
 * const conn = new Addr('udp:eSfQhc2igaaF_yILi4avPLmpeI6ffxOLB6jr-hvFTJs@example.com').connect();
 * const conn = new Addr('turn:bTKXMJ2yK94aKGWUsbQfNG2RzgG7S5vFgBd-FIzdYXQ@127.0.0.1?turn_transport=tcp').connect();
 */
export class Addr extends URL {
	#id;
	async resolve_id() {
		const {username} = this.#authority();
		this.#id ??= Id.from_str(username);
		for await (const txt of query_txt(this.#authority().hostname, {prefix: 'swbrd='})) {
			this.#id ??= Id.from_str(txt);
		}
		return this.#id;
	}
	#authority() {
		// Use two URLS to unhide default ports: new URL('https://test.com:443').port == '' and new URL('http://test.com:80').port == ''
		const http = new URL(this); http.protocol = 'http:';
		const https = new URL(this); https.protocol = 'https:';
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
	sig() {
		const {hostname, port, username, password: ice_pwd} = this.#authority();
		const id = this.#id ?? Id.from_str(username);
		const candidates = this.searchParams.getAll('candidate')
			.map(s => {try { return JSON.parse(s); } catch { return s; }});
		let setup = this.searchParams.get('setup');
		let ice_lite = this.searchParams.get('ice_lite');
		const ice_ufrag = this.searchParams.get('ice_ufrag');
		if (/^udp:/i.test(this.protocol)) {
			candidates.push({address: hostname, port, type: 'host'});
			setup ??= 'passive';
			ice_lite ??= true;
		}
		else if (/^turns?:/i.test(this.protocol)) {
			if (candidates.length < 1) candidates.push({address: '255.255.255.255', port: '3478', type: 'relay'});
		}
		return new Sig({
			id,
			candidates,
			ice_pwd,
			ice_ufrag,
			setup,
			ice_lite
		});
	}
	connect(config = null) {
		const adjustment = this.config();
		const ret = new Conn({...config, ...adjustment });
		
		// If we asjusted the config, then perform a fixup later.
		if (adjustment) ret.local.then(() => {
			ret.setConfiguration(config);
			ret.restartIce();
		});

		ret.remote = this.sig();

		return ret;
	}
}
