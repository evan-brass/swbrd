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
	// WARNING: bind_forking only (kinda) works in Chrome
	async bind_forking(config = null, {
		filter = () => true,
		timeout = 1000,
		make_id = ufrag => Id.from_str(ufrag),
		expected_address,
		ice_pwd,
		assign_setup = true
	} = {}) {
		if (config?.certificates?.length != 1) throw new Error("You must provide exactly one rtc certificate.");

		console.warn("bind_forking only (kinda) works on Chrome.");

		const adjustment = this.config();

		// Create a connection 
		const fork = new Conn({...config, ...adjustment});
		const fork_sig = await fork.local;

		// Do our best to build an address
		const {host} = this.#authority();
		const addr = new Addr(`${this.protocol}//${fork_sig.id}:${fork_sig.ice_pwd}@${host}`);
		for (const {address, port, type} of fork_sig.candidates) {
			addr.searchParams.append('candidate', JSON.stringify({address, port, type}));
		}
		if (assign_setup) addr.searchParams.set('setup', 'active');

		// Assume that the remote peer will receive the same address as us and will thus only vary by port
		expected_address ??= fork_sig.candidates?.[0]?.address;
		expected_address ??= '255.255.255.255';
		// TODO: It would be nice if we could set a permission for the expected address, but we can't do that without setting the remote description of fork (which would cause other problems.)

		return {
			fork,
			get addr() {
				console.warn("This address is only a best guess.  You will likely need to modify this address to match your use case.");
				return addr;
			},
			answered: new Set(),
			async *[Symbol.asyncIterator]() {
				while (1) {
					const stats = await fork.getStats();
					for (const {type, address, port, usernameFragment} of stats.values()) {
						if (type != 'remote-candidate' || !usernameFragment) continue;
						if (this.answered.has(usernameFragment)) continue;
						if (!filter(usernameFragment)) continue;
						const id = make_id(usernameFragment);
						if (!id) continue;
		
						const answer = new Conn({...config, ...adjustment});
						
						// Mark the usernameFragment as answered
						this.answered.add(usernameFragment);
						answer.addEventListener('connectionstatechange', () => {
							if (answer.connectionState == 'closed') this.answered.delete(usernameFragment);
						});

						let setup;
						if (assign_setup) setup = 'passive';

						answer.remote = new Sig({
							id,
							ice_ufrag: usernameFragment,
							ice_pwd,
							candidates: [
								{ priority: 2^31, address: address || expected_address, port, type: 'host' } // TODO: Is this type right?
							],
							setup
						});
		
						yield answer;
					}
		
					await new Promise(res => setTimeout(res, timeout));
				}
			}
		};
	}
}
