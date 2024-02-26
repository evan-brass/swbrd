import { cert as default_cert, idf } from './cert.js';

export const defaults = {
	iceServers: [{urls: 'stun:global.stun.twilio.com'}]
};

export class Conn extends RTCPeerConnection {
	#dc = this.createDataChannel('', {negotiated: true, id: 0});
	#candidates = [];
	constructor(peerid, config = null) {
		peerid = BigInt(peerid);
		const cert = config?.cert ?? default_cert;

		super({
			...defaults,
			...config,
			certificates: [cert],
			bundlePolicy: 'max-bundle',
			rtcpMuxPolicy: 'require',
			peerIdentity: null,
		});

		this.#candidates.push(...(config?.candidates ?? []));

		const polite = BigInt(cert) < peerid;
		const {
			setup,
			ice_lite,
			ice_pwd,
		} = config ?? {};

		this.#signaling_task({
			cert, polite, peerid,
			setup, ice_lite, ice_pwd
		}).catch(() => this.close());
	}
	static async generateCertificate() {
		return await super.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' });
	}

	async addIceCandidate(candidate) {
		candidate.sdpMid ??= 'dc';
		if (Array.isArray(this.#candidates)) {
			this.#candidates.push(candidate);
		} else {
			return await super.addIceCandidate(candidate);
		}
	}

	async #signaling_task(/* Session: */ { cert, peerid, polite, setup, ice_lite, ice_pwd }) {
		ice_pwd ||= 'the/ice/password/constant';
		setup ||= polite ? 'active' : 'passive';

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

		// First pass of signaling
		const fingerprint = idf.fingerprint(peerid);
		const ice_ufrag = idf.toString(peerid).padStart(6, '0');
		await super.setRemoteDescription({ type: 'offer', sdp: [
			'v=0',
			'o=swbrd 42 0 IN IP4 0.0.0.0',
			's=-',
			't=0 0',
			'a=group:BUNDLE dc',
			`a=fingerprint:${fingerprint}`,
			`a=ice-ufrag:${ice_ufrag}`,
			`a=ice-pwd:${ice_pwd}`,
			'a=ice-options:trickle',
			...(ice_lite != undefined ? ['a=ice-lite'] : []),
			'm=application 42 UDP/DTLS/SCTP webrtc-datachannel',
			'c=IN IP4 0.0.0.0',
			'a=mid:dc',
			`a=setup:${setup}`,
			'a=sctp-port:5000',
			''
		].join('\n') });
		const answer = await super.createAnswer();
		answer.sdp = answer.sdp
			.replace(/^a=ice-ufrag:.+/im, `a=ice-ufrag:${idf.toString(cert)}`)
			.replace(/^a=ice-pwd:.+/im, `a=ice-pwd:${ice_pwd}`);
		await super.setLocalDescription(answer);

		// Add any initial candidates that we delayed delivering until after initial offer/answer
		let candidate;
		while (candidate = this.#candidates.shift()) {
			await super.addIceCandidate(candidate);
		}
		this.#candidates = false;

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

	// Disable manual signaling:
	createOffer() { throw new Error("Manual signaling is disabled on Conn"); }
	createAnswer() { throw new Error("Manual signaling is disabled on Conn"); }
	setLocalDescription() { throw new Error("Manual signaling is disabled on Conn"); }
	setRemoteDescription() { throw new Error("Manual signaling is disabled on Conn"); }

	// Re-provide defaults when calling setConfiguration
	setConfiguration(config = null) {
		super.setConfiguration({
			...defaults,
			...config,
			bundlePolicy: 'max-bundle',
			rtcpMuxPolicy: 'require',
			peerIdentity: null,
		});
	}

	// Disable things:
	addStream() { throw new Error("addStream is deprecated") }
	removeStream() { throw new Error("removeStream is deprecated") }
	getIdentityAssertion() { throw new Error("Identity assertions are disabled on Conn") }
	setIdentityProvider() { throw new Error("Identity assertions are disabled on Conn") }
	get peerIdentity() { throw new Error("Identity assertions are disabled on Conn") }
}
