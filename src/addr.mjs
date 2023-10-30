import { Sig, Conn } from "./conn.mjs";
import { Id } from "./id.mjs";
import { query_id } from "./dns.mjs";

const default_ports = {
	udp: 3478,
	tcp: 3478,
	tls: 5349
};

export class Addr {
	#http;
	#https;
	protocol;
	static parse(addr) {
		if (!URL.canParse(addr)) return;
		const ret = new this();
		ret.#http = new URL(addr);
		ret.protocol = ret.#http.protocol;
		ret.#http.protocol = 'http';
		ret.#https = new URL(addr);
		ret.#https.protocol = 'https';
		return ret;
	}
	get port() {
		return this.#http.port || this.#https.port || default_ports[this.protocol] || 4666;
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
	connect() {

	}
}
