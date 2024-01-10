import { Sig, Conn, default_config } from "./conn.js";
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

				const sig = new Sig(JSON.parse(data));
				
				if (!this.#filter(sig)) continue;

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
	get id() {
		const http = new URL(this); http.protocol = 'http:';
		const username = http.username;
		if (username) return new Id(http.username);
		else return query_id(http.hostname).then(s => s && new Id(s));
	}
	get #port() {
		// new URL('http://host.local:80').port == '' and new URL('https://host.local:443').port == '' so we parse the URL twice to get the actual port
		const http = new URL(this); http.protocol = 'http:';
		const https = new URL(this); https.protocol = 'https:';
		return parseInt(http.port || https.port || 0);
	}
	get candidate() {
		if (/^udp:|tcp:/i.test(this.protocol)) {
			return { transport: this.protocol.replace(':', ''), address: http.hostname, port: this.#port || 3478, type: 'host' };
		}
		else if (/^turns?:/i.test(this.protocol)) {
			// For turn addresses we add the broadcast candidate
			return { transport: 'udp', address: '255.255.255.255', port: 3478, typ: 'host' };
		}
		else {
			// Unknown address type
			return;
		}
	}
	get setup() {
		if (/^udp:|tcp:/i.test(this.protocol)) return 'passive';
	}
	get ice_lite() {
		if (/^udp:|tcp:/i.test(this.protocol)) return true;
	}
	get ice_pwd() {
		const http = new URL(this); http.protocol = 'http:';
		return http.password || undefined;
	}
	get turn_url() {
		if (!/turns?:/i.test(this.protocol)) throw new Error("Not a turn address.");

		const http = new URL(this); http.protocol = 'http:';
		// Notice: this is backwards: 'turns:<id>@hostname' => '?transport=tcp' and 'turns:<id>@hostname?transport=udp' => '' because I want the default to be turns + tcp
		const query = this.searchParams.get('transport') == 'udp' ? '' : '?transport=tcp';
		// Notice: I've changed the default ports to: 'turns:' => 443, 'turn:' => 3478
		const port = this.#port || (this.protocol == 'turns:' ? 443 : 3478);

		return `${this.protocol}${http.hostname}:${port}${query}`;
	}
	adjust_config(config) {
		if (!/^turns?:/i.test(this.protocol)) return config;

		return {
			...config,
			iceTransportPolicy: 'relay',
			iceServers: [{ urls: this.turn_url, username: 'the/turn/username/constant', credential: 'the/turn/credential/constant' }]
		};
	}
	fixup(conn, config) {
		if (!/^turns?:/i.test(this.protocol)) return;

		// For turn addresses, we change the configuration back and trigger an iceRestart
		conn.setConfiguration(config);
		conn.restartIce();
	}
	connect(config = default_config, {overide_id} = {}) {
		const init = this.adjust_config(config);
		const ret = new Conn(init);

		// Spawn a task to signal the connection
		(async () => {
			const id = overide_id ?? await this.id;
			if (!id) ret.close();

			ret.remote = new Sig({ id, candidates: [this.candidate], setup: this.setup, ice_lite: this.ice_lite, ice_pwd: this.ice_pwd });

			// Call fixup after the local sig has been generated. (But renegotiation won't progress until the datachannel is open)
			const _ = await ret.local;
			this.fixup(ret, config);
		})();

		return ret;
	}
	async *bindv1(config = default_config, { filter = () => true } = {}) {
		if (!/^turns?:/i.test(this.protocol)) throw new Error('bindv1 only works with turn(s) addresses.');

		const local_ids = String(await this.id).split(',');

		const sock = new WebSocket(advanced_usage.bindv1_service + encodeURIComponent(this.turn_url));
		const next_msg = () => new Promise((res, rej) => {
			sock.addEventListener('message', res, {once: true});
			sock.addEventListener('close', () => rej, {once: true});
			sock.addEventListener('error', () => rej, {once: true});
		});

		const answered = new Set();

		while(1) {
			const {data} = await next_msg();
			const {dest, src, address} = JSON.parse(data);
			if (!local_ids.includes(dest)) continue; // Connection test was not destined for us
			
			const overide_id = new Id(src);
			if (!overide_id || answered.has(src) || !filter(overide_id, address)) continue; // Connection test filtered out

			const conn = this.connect(config, {overide_id});

			// Deduplicate incoming connections:
			answered.add(src);
			conn.addEventListener('connectionstatechange', () => {
				if (['closed', 'failed'].includes(conn.connectionState)) answered.delete(src);
			});

			yield conn;
		}
	}
}
