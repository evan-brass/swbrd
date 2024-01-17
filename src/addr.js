import { Sig, Conn } from "./conn.js";
import { Id } from "./id.js";
import { query_id } from "./dns.js";

const advanced_usage = {
	bindv1_service: 'wss://swbrd-bindv1.deno.dev?host='
};

// This is how I actually want to do listeners: with a WebRTC bind server, but I'm still too frustrated with server-side WebRTC
export class Listener {
	#conn;
	#base;
	#filter;
	#bind;
	#addr;
	get addr() { return this.#addr; }
	constructor(conn, { base, filter = () => true } = {}) {
		this.#conn = conn;
		this.#base = base;
		this.#filter = filter;
		this.#bind = conn.createDataChannel('bind');
		if (this.#base) {
			// When a base address is supplied, then we make our own address using it
			this.#addr = (async () => {
				const id = await conn.local_id;
				this.#addr = new Addr(this.#base);
				this.#addr.username = id;
			})();
		}
	}
	async *[Symbol.asyncIterator]() {
		while(1) {
			try {
				const data = await new Promise((res, rej) => {
					this.#bind.addEventListener('message', res, {once: true});
					this.#bind.addEventListener('close', rej, {once: true});
					this.#bind.addEventListener('error', rej, {once: true});
				});
				if (typeof data != 'string') continue;

				const { src, dst } = JSON.parse(data);

				
				if (!this.#filter(src)) continue;

				const config = this.#conn.getConfiguration();
				const ret = new Conn(this.#base ? this.#base.adjust_config(config) : config);

				if (this.#base) {
					this.#base.fixup(ret, config);
					sig.ice_pwd = this.#base.password;
				}

				ret.remote = sig;

				yield ret;
			}
			catch { break; }
		}
	}
}

export class Addr extends URL {
	get #authority() {
		// For some reason, the browser doesn't give us access to URI authority information unless the scheme is http: or https:
		// new URL('http://host.local:80').port == '' and new URL('https://host.local:443').port == '' so we parse the URL twice to get the actual port
		const http = new URL(this); http.protocol = 'http:';
		const https = new URL(this); https.protocol = 'https:';
		const host = (http.host.length < https.host.length) ? https.host : http.host;
		const port = parseInt(http.port || https.port || 0);
		return { username: http.username, password: http.password, host, hostname: http.hostname, port };
	}
	config() {
		if (/^udp:|tcp:/i.test(this.protocol)) return null;

		if (/^turns?:/i.test(this.protocol)) {
			const {host} = this.#authority;
			const username = this.searchParams.get('turn_username') || 'the/turn/username/constant';
			const credential = this.searchParams.get('turn_credential') || 'the/turn/credential/constant';
			const turn_transport = this.searchParams.get('turn_transport') || 'tcp';
			const search = (turn_transport == 'udp') ? '' : ('?transport=' + turn_transport)
			
			const urls = `${this.protocol}${host}${search}`;
			return {
				iceTransportPolicy: 'relay',
				iceServers: [{urls, username, credential}]
			};
		}
	}
	async sig() {
		const authority = this.#authority;
		
		const id = new Id(authority.username ? authority.username : await query_id(authority.hostname));
		
		const candidates = [];
		const ice_pwd = authority.password || 'the/ice/password/constant';
		let setup = this.searchParams.get('setup');
		let ice_lite = this.searchParams.get('ice_lite') == 'true';
		// TODO: Add ice_ufrag param?

		if (/^udp:|tcp:/i.test(this.protocol)) {
			const port = authority.port || 3478;
			candidates.push({ transport: this.protocol.replace(':', ''), address: authority.hostname, port, type: 'host' });
			setup ??= 'passive';
			ice_lite ??= true;
		}
		else if (/^turns?:/i.test(this.protocol)) {
			// For turn addresses we add the broadcast candidate
			candidates.push({ transport: 'udp', address: '255.255.255.255', port: 3478, typ: 'host' });
		}

		return new Sig({ id, candidates, setup, ice_lite, ice_pwd });
	}
	connect(config = null) {
		const adjustment = this.config();

		const ret = new Conn({ ...config, ...adjustment });

		// Spawn a task to signal the connection
		(async () => {
			const remote = await this.sig();
			if (!remote?.id) { ret.close(); return }

			ret.remote = remote;

			// If we adjusted the config, then fixup the config
			if (adjustment) {
				const _ = await ret.local;
				ret.setConfiguration(config);
				ret.restartIce();
			}
		})();

		return ret;
	}
}
