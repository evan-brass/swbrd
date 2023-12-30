import { Sig, Conn, default_config } from "./conn.mjs";
import { Id } from "./id.mjs";
import { query_id } from "./dns.mjs";


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

// Default port is 80, even for udp because Firewalls tend to be permissive to port 80.
export class Addr extends URL {
	protocol;
	id;
	constructor(init) {
		super(init);
		this.protocol = super.protocol.replaceAll(':', '');
		super.protocol = 'http';
		if (this.username) this.id = new Id(this.username);
		else this.id = query_id(this.hostname).then(s => this.id = new Id(s));
	}
	get port() { return parseInt(super.port || 80); }
	set port(v) { super.port = v; }
	adjust_config(config) {
		if (!this.protocol.startsWith('swbrd')) return config;

		// Calculate the TURN url
		let urls; {
			const protocol = this.searchParams.get('protocol') || 'turns';
			let transport = this.searchParams.get('transport') ?? 'tcp';
			if (transport.length) transport = '?transport=' + transport;
			urls = `${protocol}:${this.host}${transport}`;
		}

		return {
			...config,
			iceTransportPolicy: 'relay',
			iceServers: [
				{urls, username: 'the/turn/username/constant', credential: 'the/turn/credential/constant'}
			]
		};
	}
	// Apply a fixup step after the connection succeeds
	fixup(conn, config) {
		if (!this.protocol.startsWith('swbrd')) return;

		conn.connected.then(() => {
			ret.setConfiguration(config);
			ret.restartIce();
		});
	}
	connect(config = default_config) {
		const ret = new Conn(this.adjust_config(config));

		this.fixup(ret, config);

		// Spawn a task to signal this connection:
		(async () => {
			const id = await this.id;

			ret.remote = new Sig({
				id,
				ice_pwd: this.password,
				...(this.protocol.startsWith('swbrd') ? {
					candidates: [{
						// IP Broadcast
						address: "255.255.255.255",
						port: 3478,
					}]
				} : {
					ice_lite: true,
					setup: 'passive',
					candidates: [{
						transport: this.protocol,
						address: this.hostname,
						port: this.port
					}]
				})
			});
		})();

		return ret;
	}
	bind(config = default_config, options = {}) {
		const conn = this.connect(config);
		return new Listener(conn, { base: this, ...options});
	}
}
