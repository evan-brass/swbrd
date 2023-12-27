import { Sig, Conn, default_config } from "./conn.mjs";
import { Id } from "./id.mjs";
import { query_id } from "./dns.mjs";

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
		// Modify the config, if we're using switchboard
		const init_config = (this.protocol != 'swbrd') ? config : {
			...config,
			iceTransportPolicy: 'relay',
			iceServers: [
				{urls: `turns:${this.hostname}?transport=tcp`, username: 'the/turn/username/constant', credential: 'the/turn/credential/constant'}
			]
		};
		const ret = new Conn(init_config);

		// Spawn a task to signal this connection:
		(async () => {
			const id = await this.id;
			let init;
			if (this.protocol == 'udp' || this.protocol == 'tcp') {
				init = {
					id,
					ice_pwd: this.password,
					ice_lite: true,
					setup: 'passive',
					candidates: [{
						transport: this.protocol,
						address: this.hostname,
						port: this.port
					}]
				};
			}
			else if (this.protocol == 'swbrd') {
				init = {
					id,
					ice_pwd: this.password,
					candidates: [{
						// IP Broadcast
						address: "255.255.255.255",
						port: 3478,
					}]
				};
			}
			else { throw new Error("Unknown Protocol"); }

			ret.remote = new Sig(init);

			await ret.connected;

			// Once we're connected, set the configuration back:
			if (this.protocol == 'swbrd') {
				ret.setConfiguration(config);
			}
		})();

		return ret;
	}
}
