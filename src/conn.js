import { Id } from './id.js';

export class Sig {
	id;
	candidates;
	// ice_pwd;
	// ice_ufrag;
	// setup;
	// ice_lite;
	constructor() { Object.assign(this, ...arguments); }
	*sdp(polite) {
		yield* this.id.sdp();
		const ice_ufrag = this.ice_ufrag || String(this.id);
		yield 'a=ice-ufrag:' + ice_ufrag;
		const ice_pwd = this.ice_pwd || 'the/ice/password/constant';
		yield 'a=ice-pwd:' + ice_pwd;
		if (this.ice_lite) yield 'a=ice-lite';
		for (let i = 0; i < this.candidates.length; ++i) {
			const candidate = this.candidates[i];
			if (typeof candidate == 'string') yield 'a=candidate:' + candidate;
			else if (typeof candidate == 'object') {
				const {
					foundation = 'foundation',
					component = '1',
					transport = 'udp',
					priority = this.candidates.length - i,
					address,
					port = 3478,
					type = 'host'
				} = candidate;
				yield `a=candidate:${foundation} ${component} ${transport} ${priority} ${address} ${port} typ ${type}`;
			}
		}
		const setup = this.setup ?? (polite ? 'passive' : 'active');
		yield 'a=setup:' + setup;
	}
	add_sdp(sdp) {
		this.id ??= Id.from_sdp(sdp);
		this.ice_ufrag ??= /^a=ice-ufrag:(.+)/im.exec(sdp)[1];
		this.ice_pwd ??= /^a=ice-pwd:(.+)/im.exec(sdp)[1];
		this.candidates ??= Array.from(
			sdp.matchAll(/^a=candidate:([^ ]+) ([0-9]+) (udp) ([0-9]+) ([^ ]+) ([0-9]+) typ (host|srflx|relay)/img),
			([_fm, foundation, component, transport, priority, address, port, type]) => {
				return {priority: parseInt(priority), address, port: parseInt(port), type}
			}
		);
	}
}

export const default_configuration = {
	bundlePolicy: 'max-bundle',
	iceServers: [{urls: 'stun:global.stun.twilio.com'}]
};
export class Conn extends RTCPeerConnection {
	#config;
	#dc = this.createDataChannel('', {negotiated: true, id: 0});
	constructor(config = null) {
		super({ ...default_configuration, ...config, peerIdentity: null });
		this.#config = config;
		this.#signaling_task();
	}

	#local_res;
	#local = new Promise(res => this.#local_res = res);
	get local() { return this.#local; }
	
	#remote_res;
	#remote = new Promise(res => this.#remote_res = res);
	set remote(remote_desc) { this.#remote_res(remote_desc); }

	async #make_local(local_id) {
		while (this.iceGatheringState != 'complete') await new Promise(res => this.addEventListener('icegatheringstatechange', res, {once: true}));
		const local = new Sig({ id: local_id, ice_ufrag: this.#config?.ice_ufrag || '', ice_pwd: this.#config?.ice_pwd ?? '' });
		local.add_sdp(this.localDescription.sdp);
		this.#local_res(local);
	}
	async #signaling_task() {
		const offer = await super.createOffer();
		const local_id = Id.from_sdp(offer.sdp);
		
		// Mung the offer
		offer.sdp = offer.sdp.replace(/^a=ice-ufrag:(.+)/im, `a=ice-ufrag:${this.#config?.ice_ufrag || local_id}`);
		offer.sdp = offer.sdp.replace(/^a=ice-pwd:(.+)/im, `a=ice-pwd:${this.#config?.ice_pwd || 'the/ice/password/constant'}`);
		
		await super.setLocalDescription(offer);
		// TODO: If browsers remove the ability to mung ice credentials then we'll need to add a fallback.

		// Prepare for renegotiation
		let negotiation_needed = false; this.addEventListener('negotiationneeded', () => negotiation_needed = true);
		this.#dc.addEventListener('message', async ({ data }) => { try {
			const { candidate } = JSON.parse(data);
			if (candidate) await this.addIceCandidate(candidate);
		} catch {}});
		this.addEventListener('icecandidate', ({candidate}) => {
			if (candidate && this.#dc.readyState == 'open') {
				this.#dc.send(JSON.stringify({ candidate }));
			}
		});
		let remote_desc = false; this.#dc.addEventListener('message', ({data}) => { try {
			const { description } = JSON.parse(data);
			if (description) remote_desc = description;
		} catch {}})

		// Spawn a task to deliver our local signaling message once icegathering completes
		this.#make_local(local_id);

		// Finish the initial round of signaling
		const remote = await this.#remote;
		const polite = local_id < remote.id;
		await super.setRemoteDescription({
			type: 'answer',
			sdp: [
				'v=0',
				'o=WebRTC-with-addresses 42 0 IN IP4 0.0.0.0',
				's=-',
				't=0 0',
				'a=group:BUNDLE 0',
				'm=application 42 UDP/DTLS/SCTP webrtc-datachannel',
				'c=IN IP4 0.0.0.0',
				'a=mid:0',
				'a=sctp-port:5000',
				...remote.sdp(polite),
				''
			].join('\n')
		});

		// Switchover into handling renegotiation
		while (1) {
			if (['closing', 'closed'].includes(this.#dc.readyState)) { break; }
			else if (this.#dc.readyState == 'connecting') {
				await new Promise(res => this.#dc.addEventListener('open', res, {once: true}));
			}
			else if (negotiation_needed) {
				negotiation_needed = false;
				await super.setLocalDescription();
				try { this.#dc.send(JSON.stringify({ description: this.localDescription })); } catch {}
			}
			else if (remote_desc) {
				const desc = remote_desc; remote_desc = false;
				// Ignore incoming offers if we have a local offer and are also impolite
				if (desc?.type == 'offer' && this.signalingState == 'have-local-offer' && !polite) continue;

				await super.setRemoteDescription(desc);

				if (desc?.type == 'offer') negotiation_needed = true; // Call setLocalDescription.
			}
			else {
				// Wait for something to happen
				await new Promise(res => {
					this.addEventListener('negotiationneeded', res, {once: true});
					this.#dc.addEventListener('message', res, {once: true});
					this.#dc.addEventListener('close', res, {once: true});
				});
			}
		}
	}

	// Disable manual signaling because we provide automatic renegotiation over #dc
	createOffer() { throw new Error("Manual signaling disabled."); }
	createAnswer() { throw new Error("Manual signaling disabled."); }
	setLocalDescription() { throw new Error("Manual signaling disabled."); }
	setRemoteDescription() { throw new Error("Manual signaling disabled."); }

	// Disable stuff:
	addStream() { throw new Error("addStream is deprecated.") }
	setIdentityProvider() { throw new Error("Firefox's identity stuff is disabled") }
	getIdentityAssertion() { throw new Error("Firefox's identity stuff is disabled") }
	get peerIdentity() { throw new Error("Firefox's identity stuff is disabled") }

	// Generate a certificate with a sha-256 fingerprint as required by Id
	static generateCertificate() {
		return super.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' });
	}
	// Add our default config even when using setConfiguration
	setConfiguration(config = null) {
		super.setConfiguration({ ...default_configuration, ...config, peerIdentity: null });
	}
}
