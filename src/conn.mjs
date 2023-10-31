import { Id } from "./id.mjs";

export class Sig {
	id;
	ice_ufrag;
	ice_pwd;
	candidates = [];
	constructor() { Object.assign(this, ...arguments); }
}

const default_rtc_config = {
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

	constructor(rtc_config = default_rtc_config, local_id) {
		super(rtc_config);
		this.#local.id = local_id;

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
			this.#local.candidates = reg_all(/a=candidate:(.+)/g, this.localDescription.sdp).map(({1: candidate}) => {
				const [_foundation, _component, transport, priority, address, port, _typ, typ] = candidate.split(' ');
				return {priority: Number.parseInt(priority), transport, address, port: Number.parseInt(port), typ};
			}).sort((a, b) => a.priority - b.priority);

			this.#local_res(this.#local);
		};
		try_make_local();

		// 4. Wait for the remote signaling message
		const remote = await this.remote;
		const polite = this.#local.id < remote.id;

		// 5. Set the remote description:
		const sdp = [
			'v=0',
			'o=- 20 0 IN IP4 0.0.0.0',
			's=-',
			't=0 0',
			'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
			'c=IN IP4 0.0.0.0',
			`a=ice-ufrag:${remote.ice_ufrag}`,
			`a=ice-pwd:${remote.ice_pwd}`,
			...remote.id.sdp(),
			...remote.candidates.map((c, i) => `a=candidate:foundation 1 ${c.transport} ${i + 1} ${c.address} ${c.port} typ ${c.typ}`),
			// TODO: Address connections may wish to override the setup field
			`a=setup:${polite ? 'passive' : 'active'}`,
			'a=sctp-port:5000',
			''
		].join('\n');
		await super.setRemoteDescription({ type: 'answer', sdp });

		// 6. TODO: Wait for the connection to complete, and then take over with the perfect negotiation pattern.
	}
	setLocalDescription() { throw new Error("Manual signaling is disabled."); }
	setRemoteDescription() { throw new Error("Manual signaling is disabled."); }
}
