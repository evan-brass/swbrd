import { Id } from "./id.mjs";

export class Sig {
	// Required fields:
	id;
	ice_ufrag;
	ice_pwd;
	candidates = [];
	// Optional Fields:
	setup;
	ice_lite = false;
	constructor() { Object.assign(this, ...arguments); }
	is_filled() {
		return (this.id instanceof Id) &&
			typeof this.ice_ufrag == 'string' &&
			typeof this.ice_pwd == 'string' &&
			this.candidates.length > 0;
	}
	sdp(other_id) {
		return [
			...this.id.sdp(),
			...(this.ice_lite ? ['a=ice-lite'] : []),
			`a=ice-ufrag:${this.ice_ufrag}`,
			`a=ice-pwd:${this.ice_pwd}`,
			...this.candidates.map((c, i) => `a=candidate:foundation 1 udp ${i + 1} ${c.address} ${c.port} typ ${c.typ}`),
			`a=setup:${this.setup ?? (this.id < other_id) ? 'passive' : 'active'}`,
		];
	}
}

export const default_config = {
	iceServers: [
		{ urls: 'stun:global.stun.twilio.com:3478' },
		{ urls: 'stun:stun.l.google.com:19302' }
	]
};

function reg_all(reg, s) {
	const ret = [];
	let t;
	while ((t = reg.exec(s))) ret.push(t);
	return ret;
}

export class Conn extends RTCPeerConnection {
	// The zero datachannel (used for connection renegotiation)
	#dc;

	// Local signaling message
	#local_res;
	#local_prom = new Promise(res => this.#local_res = res);
	#local = new Sig(); // In-Progress local signaling message
	get local() { return this.#local_prom; } // Retrieve complete / ready-to-send signaling message
	_local() { return this.#local; } // Retrieve incomplete / not-yet-ready-to-send signaling message (used by address connections)

	// Remote signaling message
	#remote_res;
	#remote = new Promise(res => this.#remote_res = res);
	set remote(sig) { this.#remote_res(sig); }
	get remote() { return this.#remote; }

	constructor(config = default_config) {
		super(config);
		this.#local.id = config.id;

		this.#dc = this.createDataChannel('', {negotiated: true, id: 0});
		this.#signal_task();
	}
	async #signal_task() {
		// 1. Set the local description
		await super.setLocalDescription();

		// 2. Get most of the parameters for the local Sig:
		this.#local.ice_ufrag = /a=ice-ufrag:(.+)/.exec(this.localDescription.sdp)[1];
		this.#local.ice_pwd = /a=ice-pwd:(.+)/.exec(this.localDescription.sdp)[1];
		this.#local.id ??= new Id();
		for (const {1: alg, 2: value} of reg_all(/a=fingerprint:([^ ]+) (.+)/g, this.localDescription.sdp)) {
			this.#local.id.add_fingerprint(alg, value);
		}

		// 3. Handle making the local Sig (signaling message) once we've aquired our local candidates.
		const try_make_local = () => {
			if (this.iceGatheringState != 'complete') {
				this.addEventListener('icegatheringstatechange', try_make_local, {once: true});
				return;
			}
			this.#local.candidates = reg_all(/a=candidate:[^ ]+ [0-9]+ udp ([0-9]+) ([^ ]+) ([0-9]+) typ (host|srflx)/g, this.localDescription.sdp)
				.map(({1: priority, 2: address, 3: port, 4: typ}) => {
				return {priority: Number.parseInt(priority), address, port: Number.parseInt(port), typ};
			}).sort((a, b) => a.priority - b.priority).filter(c => c.transport == 'udp');

			this.#local_res(this.#local);
		};
		try_make_local();

		// 4. Wait for the remote signaling message
		const remote = await this.remote;

		// 5. Set the remote description:
		const sdp = [
			'v=0',
			'o=- 20 0 IN IP4 0.0.0.0',
			's=-',
			't=0 0',
			'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
			'c=IN IP4 0.0.0.0',
			...remote.sdp(this.#local.id),
			'a=sctp-port:5000',
			''
		].join('\n');
		await super.setRemoteDescription({ type: 'answer', sdp });

		// 6. TODO: Wait for the connection to complete, and then take over with the perfect negotiation pattern.
	}
	setLocalDescription() { throw new Error("Manual signaling is disabled."); }
	setRemoteDescription() { throw new Error("Manual signaling is disabled."); }
}
