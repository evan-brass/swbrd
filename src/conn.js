import { cert as default_cert } from './cert.js';
import { to_fingerprint, to_string } from "./id.js";

export const defaults = {
	iceServers: [{urls: 'stun:global.stun.twilio.com'}]
};

export class Conn extends RTCPeerConnection {
	#dc = this.createDataChannel('', {negotiated: true, id: 0});
	get dc() { return this.#dc; }

	#default_address = new Promise(res => this.addEventListener('icecandidate', ({ candidate }) => {
		if (candidate === null) return res('255.255.255.255');
		const {1: address} = /([^ ]+) [^ ]+ typ relay/i.exec(candidate.candidate) ?? {};
		if (address) return res(address);
	})).then(address => {
		this.#default_address = address;
		return address;
	});
	// TODO: Allow cert to be optional - In some cases it's possible (and desirable) to not use pregenerated certificates. This means we won't know our local pid until after createOffer which means we can't determine politeness until then which also means we can't use politeness to determine any parameters (currently just the setup parameter if it hasn't already been set).  In this scenario you are probably talking to an ICE Lite + DTLS server with optional client cert verification, which means that you (if it behaves well) don't need to mung your ICE credentials.
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

		this.#dc.binaryType = 'arraybuffer';

		const polite = BigInt(cert) < peerid;
		const {
			setup,
			ice_lite,
			ice_pwd,
		} = config ?? {};

		this.#signaling_task({
			cert, polite, peerid,
			setup, ice_lite, ice_pwd,
		}).catch(() => this.close());
	}

	async addIceCandidate(candidate) {
		if (candidate == null) return;

		if (typeof candidate != 'object') {
			candidate = { candidate: candidate };
		}

		// Can't add ICE candidates while the remote description is null:
		while (super.remoteDescription === null) await new Promise(res => this.addEventListener('signalingstatechange', res, {once: true}));
		
		candidate.usernameFragment ??= /a=ice-ufrag:(.+)/i.exec(super.remoteDescription.sdp)[1];
		candidate.candidate ??= 'candidate:' + [
			candidate.foundation || 'foundation',
			candidate.component || '1',
			candidate.transport || 'udp',
			candidate.priority || '42',
			candidate.address || await this.#default_address,
			candidate.port || '4666',
			'typ', candidate.type || 'relay',
			// WEIRD: For some reason, Firefox won't pair the candidate unless it has a related address and port (which are supposed to be optional?)
			'raddr', '0.0.0.0', 'rport', '0',
			'ufrag', candidate.usernameFragment,
		].join(' ');
		candidate.sdpMid ??= 'dc';
		return await super.addIceCandidate(candidate);
	}

	async #signaling_task(/* Session: */ { cert, peerid, polite, setup, ice_lite, ice_pwd }) {
		ice_pwd ||= 'the/ice/password/constant';
		// Read the following line as: "If I am polite, then the remote peer will be active therefore I must be passive": unless overridden, the polite peer is the DTLS server.
		setup ||= polite ? 'active' : 'passive';

		// Prepare for renegotiation
		let negotiation_needed = false; this.addEventListener('negotiationneeded', () => negotiation_needed = true);
		let remote_desc = false;
		this.#dc.addEventListener('message', async ({ data }) => {
			if (typeof data != 'string') return;
			let json;
			try { json = JSON.parse(data); } catch { return }
			if (typeof json != 'object') return;
			if (json?.description) remote_desc = description;
			if (json?.candidate) await this.addIceCandidate(json.candidate);
		});
		this.addEventListener('icecandidate', ({candidate}) => {
			if (candidate && this.#dc.readyState == 'open') {
				this.#dc.send(JSON.stringify({ candidate }));
			}
		});

		// First pass of signaling
		await super.setRemoteDescription({ type: 'offer', sdp: [
			'v=0',
			'o=swbrd 42 0 IN IP4 0.0.0.0',
			's=-',
			't=0 0',
			'a=group:BUNDLE dc',
			`a=fingerprint:${to_fingerprint(peerid)}`,
			`a=ice-ufrag:${to_string(peerid)}`,
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
			.replace(/^a=ice-ufrag:.+/im, `a=ice-ufrag:${to_string(cert)}`)
			.replace(/^a=ice-pwd:.+/im, `a=ice-pwd:${ice_pwd}`);
		await super.setLocalDescription(answer);

		// Switchover into handling renegotiation
		while (this.#dc.readyState != 'closed') {
			if (this.#dc.readyState == 'connecting') {
				await new Promise(res => this.#dc.addEventListener('open', res, {once: true}));
			}
			else if (negotiation_needed) {
				if (this.#dc.readyState == 'closing') continue;
				negotiation_needed = false;
				await super.setLocalDescription();
				try { this.#dc.send(JSON.stringify({ description: this.localDescription })); } catch {/* noop */}
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
		const certificates = this.getConfiguration()?.certificates;
		super.setConfiguration({
			...defaults,
			...config,
			bundlePolicy: 'max-bundle',
			rtcpMuxPolicy: 'require',
			peerIdentity: null,
			certificates,
		});
	}

	// Disable things:
	static generateCertificate() { throw new Error("generateCertificate is disabled on Conn. You can use `Cert.generate()` instead."); }
	addStream() { throw new Error("addStream is deprecated") }
	removeStream() { throw new Error("removeStream is deprecated") }
	getIdentityAssertion() { throw new Error("Identity assertions are disabled on Conn") }
	setIdentityProvider() { throw new Error("Identity assertions are disabled on Conn") }
	get peerIdentity() { throw new Error("Identity assertions are disabled on Conn") }
}
