import { Sig, Conn } from "./conn.js";
import { Id } from "./id.js";
import { query_id } from "./dns.js";

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
	async bind(config = null, {filter = () => true} = {}) {
		if (config?.certificates?.length != 1) throw new Error("In order to bind your config must include a single RTCCertificate.");

		const adjustment = this.config();
		const sig = await this.sig();
		if (!sig?.id) throw new Error("Can't connect to the bind server.");

		const conn = new Conn({ ...config, ...adjustment });
		conn.remote = sig;
		const bind = conn.createDataChannel('bind');
		const answered = new Set();

		const {id} = await conn.local; // TODO: I'm not sure if this await could be a problem.
		const {password, host} = this.#authority;
		// TODO: Constructing the address like this feels hacky
		const addr = new Addr(`${this.protocol}//${id}${password && ':'}${password}@${host}${this.search}`);

		return {
			addr,
			async *[Symbol.asyncIterator]() {
				try {
					while (bind.readyState != 'closed') {
						const e = await new Promise(res => {
							bind.addEventListener('message', res, {once: true});
							bind.addEventListener('error', () => res(), {once: true});
							bind.addEventListener('close', () => res(), {once: true});
						});
						if (!e) { continue; }
						const {src: {ufrag, ip, port}, dst} = JSON.parse(e.data);
						// TODO: Double check the dst?
						if (answered.has(ufrag)) continue;
						const src = new Id(ufrag);
						if (!src) continue;
						if (!filter(src)) continue;

						const answer = new Conn({ ...config, ...adjustment });
						answer.remote = new Sig(sig, {
							id: src,
							candidates: [{ address: ip, port }]
						});
						if (adjustment) answer.local.then(() => {
							// Fixup
							answer.setConfiguration(config);
							answer.restartIce();
						});

						answered.add(ufrag);
						answer.addEventListener('close', () => answered.delete(ufrag));

						yield answer;
					}
				} catch (e) {
					console.warn(e);
				}
			}
		};
	}
}
