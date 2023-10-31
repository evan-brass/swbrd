import { Sig, Conn } from "./conn.mjs";
import { Id } from "./id.mjs";
import { query_id } from "./dns.mjs";

const default_ports = {
	// I don't really know what these should be.  Is it more common to use the ports in the spec, or the ports with most compatibility?
	udp: 80,
	tcp: 3478,
	tls: 443
};

export class Addr {
	#http;
	#https;
	protocol;
	static parse(addr) {
		if (!URL.canParse(addr)) return;
		const ret = new this();
		ret.#http = new URL(addr);
		ret.protocol = ret.#http.protocol.replace(':', '');
		ret.#http.protocol = 'http';
		ret.#https = new URL(addr);
		ret.#https.protocol = 'https';
		return ret;
	}
	get hostname() {
		return this.#http.hostname;
	}
	get port() {
		return parseInt(this.#http.port || this.#https.port || default_ports[this.protocol] || 4666);
	}
	/**
	 * Get the Id for this Addr
	 * @returns {Id | undefined | Promise<Id | undefined>}
	 */
	id() {
		if (this.#http.username) {
			return Id.parse(this.#http.username);
		} else {
			return query_id(this.#http.hostname);
		}
	}
	/**
	 * Immediately returns a Conn that may or may not succeed in connecting to the address.
	 * @param {*} config 
	 * @returns {Conn | undefined}
	 */
	connect(config) {
		if (this.protocol == 'udp') {
			const ret = new Conn(config);

			// Spawn a task to signal the connection:
			(async () => {
				const remote = new Sig();
				remote.id = await this.id();
				remote.ice_ufrag = String(remote.id);
				remote.ice_pwd = this.#http.password || 'the/ice/password/constant';
				remote.setup = 'passive';
				remote.ice_lite = true;
				remote.candidates.push({
					transport: 'udp',
					address: this.hostname,
					port: this.port,
					typ: 'host'
				});
				if (remote.is_filled()) {
					ret.remote = remote;
				} else {
					ret.close();
				}
			})();

			return ret;
		}
		else if (this.protocol == 'swbrd') {
			// TODO: The Switchboard reverse proxy protocol
		}
		else {/* */}
	}
}
