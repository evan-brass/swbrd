import { Sig, Conn, default_config } from "./conn.mjs";
import { Id } from "./id.mjs";
import { query_id } from "./dns.mjs";
import { btoa_url, buftobinstr, from_url } from "./b64url.mjs";
import { reg_all } from "./util.mjs";

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
				remote.ice_ufrag = from_url(String(remote.id), false);
				remote.ice_pwd = this.password || 'the/ice/password/constant';
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
