import { Sig, Conn, default_config } from "./conn.mjs";
import { Id } from "./id.mjs";
import { query_id } from "./dns.mjs";
import { btoa_url, buftobinstr } from "swbrd/b64url.mjs";
import { reg_all } from "swbrd/util.mjs";

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
	get host() {
		return this.#http.port ? this.#http.host : this.#https.host;
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
	connect(config = default_config) {
		const ret = new Conn(this.protocol !== 'swbrd' ? config : Object.assign(Object.create(config), {
			iceTransportPolicy: 'relay',
			delay_signaling: true
		}));

		// Spawn a task to signal the connection:
		(async () => {
			const remote = new Sig();
			remote.id = await this.id();

			if (this.protocol == 'udp') {
				remote.ice_ufrag = String(remote.id);
				remote.ice_pwd = this.#http.password || 'the/ice/password/constant';
				remote.setup = 'passive';
				remote.ice_lite = true;
				remote.candidates.push({
					address: this.hostname,
					port: this.port,
					typ: 'host'
				});
			}
			else if (this.protocol == 'swbrd') {
				// swbrd delays the default signaling task until after we have the local ID, because we need to do a preliminary ICERestart.
				await RTCPeerConnection.prototype.setLocalDescription.call(ret);

				// Setup our TURN parameters:
				const local_id = new Id();
				for (const {1: alg, 2: value} of reg_all(/a=fingerprint:([^ ]+) (.+)/g, ret.localDescription.sdp)) {
					local_id.add_fingerprint(alg, value);
				}
				const token = this.password || btoa_url(buftobinstr(crypto.getRandomValues(new Uint8Array(16))));
				const username = `${remote.id}.${local_id}.${token}`;
				const temp_config = Object.assign(Object.create(config), {
					iceTransportPolicy: 'relay',
					iceServers: [
						{ urls: `turns:${this.host}?transport=tcp`, username, credential: 'the/turn/password/constant' }
					]
				});

				// Apply the TURN server, restart ICE, and then run normal signaling:
				ret.setConfiguration(temp_config);
				ret.restartIce()
				ret._signal_task();

				const local = await ret.local;

				remote.ice_ufrag = local.ice_pwd;
				remote.ice_pwd = 'the/ice/password/constant';
				remote.candidates.push({
					// Use US Department of Defence IP space for our fake candidate.  The TURN server redirects the packets anyway, so I don't think it really matters and because DoD IP space shouldn't be advertised on the public Internet any packets should get dropped.
					address: crypto.getRandomValues(new Uint8Array(3)).reduce((a, v) => a + '.' + v, '30'),
					port: crypto.getRandomValues(new Uint16Array(1))[0],
					typ: 'host'
				});
			}
			else {/* */}

			if (remote.is_filled()) {
				ret.remote = remote;
			} else {
				ret.close();
			}
		})();
		
		return ret;
	}
}
