import { Sig, Conn } from "./conn.js";
import { Id } from "./id.js";
import { query_id } from "./dns.js";

const advanced_usage = {
	bindv1_service: 'wss://swbrd-bindv1.deno.dev?host='
};

// A Listener is just a subclassed Conn with a #bind
export class Listener extends Conn {
	#bind = this.createDataChannel('bind');
	#answer_addr;
	#filter;
	#answered = new Set();
	constructor(config, {filter = () => true, base_addr} = {}) {
		super(config);
		this.#answer_addr = class ListenAddr extends base_addr.constructor {
			#id;
			#candidates;
			async sig() {
				const ret = await super.sig();
				if (!ret) return ret;
				ret.candidates = this.#candidates;
				ret.id = this.#id;

				return ret;
			}
			constructor(id, candidates) {
				super(base_addr);
				this.#id = id;
				this.#candidates = candidates;
			}
			connect() { return super.connect(config); }
		};
		this.#filter = filter;
	}
	async *[Symbol.asyncIterator]() {
		try {
			while (this.#bind.readyState != 'closed') {
				const msg = await new Promise(res => {
					this.#bind.addEventListener('message', res, {once: true});
					this.#bind.addEventListener('close', () => res(), {once: true});
				});
				if (!msg) break;
				const {data} = msg;
				const {src: { ufrag, ip: address, port }, dst} = JSON.parse(String(data));

				// Checks
				if (dst != String(this.local_id)) continue;
				if (this.#answered.has(ufrag)) continue;
				const src = new Id(ufrag);
				if (!src) continue;
				if (!this.#filter(src)) continue;

				const conn = (new this.#answer_addr(src, [{ address, port }])).connect();

				// Update the answered set
				this.#answered.add(ufrag);
				conn.addEventListener('close', () => this.#answered.delete(ufrag));
				
				yield conn;
			}
		} catch (e) { console.warn(e); }
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
	bind(config = null, listen_opts = null) {
		// TODO: Factor out the common between this and connect
		if (config?.certificates?.length != 1) throw new Error("You must provide a single certificate that will be reused to answer incoming connections.");

		const adjustment = this.config();

		const ret = new Listener({ ...config, ...adjustment }, {base_addr: this, ...listen_opts});

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
