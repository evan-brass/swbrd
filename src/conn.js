import { cert as default_cert } from './cert.js';
import { Id } from './id.js';
import { is_firefox, state } from './util.js';
import { Deter } from './deter.js';

export const defaults = {
	iceServers: [{
		urls: [
			'turn:turn.evan-brass.net',
			'turn:turn.evan-brass.net?transport=tcp',
			'turns:turn.evan-brass.net?transport=tcp',
			'turns:turn.evan-brass.net:443?transport=tcp',
		],
		username: 'user',
		credential: 'password',
	}],
};
const overrides = {
	bundlePolicy: 'max-bundle',
	rtcpMuxPolicy: 'require',
	peerIdentity: null,
};

class CandidateEvent extends CustomEvent {
	candidate;
	constructor(candidate) {
		super('candidate');
		this.candidate = candidate;
	}
}

export class Conn extends RTCPeerConnection {
	#dc = this.createDataChannel('', { negotiated: true, id: 0 });
	get dc() {
		return this.#dc;
	}

	#cert;
	get cert() {
		return this.#cert;
	}

	#pid;
	get pid() {
		return this.#pid;
	}

	// Make an authenticated connection to a given domain
	// - Makes a WebPKI checked TLS TURN connection to `domain`
	// - Conducts the same unauthenticated DTLS handshake as to_deter
	// - Once connected, the WebRTC config is reset to allow non-tcp network paths (direct, UDP TURN etc.)
	// - The DTLS connection remains secure over new network paths as long as the ciphersuite provides forward secrecy
	static async to_domain({
		domain = 'turn.evan-brass.net',
		port = 443,
		username = 'user',
		credential = 'password',
		...config
	}) {
		return await this.to_deter({
			...config,
			adjustment: {
				iceTransportPolicy: 'relay',
				iceServers: [{
					urls: `turns:${domain}:${port}?transport=tcp`,
					username, credential,
				}]
			},
		})
	}

	// Make a connection to a server that's using the deterministic certificate
	// - Prefix is roughly a /95
	// - We use 1 bit to signal whether we are connecting to the January or July certificate giving a /96
	// - 32 bits of randomness completes the ip address + 15 bits of randomness gives us the port
	// - Unless using to_domain, you should think of this as an unsecured UDP connection
	static async to_deter({
		base,
		...config
	} = {}) {
		const current = await Deter.generate();

		const ret = new this(current.pid, {
			setup: 'passive',
			...config,
		});

		ret.addIceCandidate(current.candidate({ base }));

		return ret;
	}

	// Make a connection between two Chrome browsers
	// - Chrome <-> Chrome via fixup
	// - This utilizes a quirk in Chrome where the ICE credentials in the SDP offer don't need to match the ICE credentials passed in the actual candidate.  RTCPeerConnection emits normal icecandidate events, but we early bind and intercept these.  You should instead listen on the custom candidate event, which will the contain the same ICE candidate, but modified to include the corrected ICE ufrag + ICE password.
	static with_candidates(peerid, config = null) {
		return new this(peerid, {
			// The default parameters in Conn match with_candidates
			...config,
		});
	}

	// Make a connection between two browsers using a TURN server that intercepts ICE connection tests
	// - IPv4 only to ensure 1 candidate pair
	// - Chrome <-> Chrome
	// - Firefox <-> Firefox
	// - Chrome <-> Firefox
	static with_candidates_dissolved(peerid, config = null) {
		return new this(peerid, {
			// HACK: Firefox is just such a pain in the ass.  In order for ICE-dissolve to work, both sides must pair the same candidates.  The reason for this is because Firefox enforces TURN permissions locally and if it gets successful ICE responses from one pair it likely won't add permissions for the other ICE pairs.  Then when data is received over a different pair it gets dropped.  We can ensure that we only pair 1 candidate by forcing both sides to only generate 1 candidate.  We do this by only allowing relaying and only using 1 ipv4 address for the TURN server.  This fucking sucks.  Ideally this restriction should only be imposed if one or the other peers is a Firefox chud, but you would need to encode that into the peer id or pass it as another argument... lame.
			adjustment: {
				iceTransportPolicy: 'relay',
				iceServers: [{
					urls: 'turns:turn-4only.evan-brass.net:443?transport=tcp',
					username: 'user',
					credential: 'password',
				}],
			},
			...config,
		});
	}

	constructor(peerid, {
		pid = Id.from(peerid),
		cert = default_cert,
		polite = cert.id < pid,
		// Read the following line as: "If I am polite, then the remote peer will be active therefore I must be passive": unless overridden, the polite peer is the DTLS server.
		setup = polite ? 'active' : 'passive',
		timeout = 10_000,
		adjustment = null,
		sctp_port = 5000,
		audio = false,
		...config
	} = {}) {
		super({
			...defaults,
			...config,
			...adjustment,
			certificates: [cert],
			...overrides,
		});
		this.#pid = pid;
		this.#cert = cert;

		this.#dc.binaryType = 'arraybuffer';

		// Add a timeout to close the conn if it fails to connect within timeout ms
		if (typeof timeout == 'number') {
			const t = setTimeout(() => {
				console.warn('Connection timeout expired!');
				this.close()
			}, timeout);
			this.addEventListener(
				'connectionstatechange',
				({ target: { connectionState } }) => {
					if (connectionState == 'connected') clearTimeout(t);
				},
			);
		}

		// Fixup the ICE candidates
		this.addEventListener('icecandidate', this.#fixup_candidates);

		this.#signaling_task({
			polite,
			config,
			adjustment,
			setup,
			sctp_port,
			audio,
		}).catch((e) => {
			console.error(e);
			this.close();
		});
	}

	async #signaling_task(
		{ polite, config, adjustment, setup, sctp_port, audio },
	) {
		// Prepare for renegotiation
		let negotiation_needed = false;
		this.addEventListener('negotiationneeded', () => negotiation_needed = true);
		let remote_desc = false;
		this.#dc.addEventListener('message', async ({ data }) => {
			if (typeof data != 'string') return;
			let json;
			try {
				json = JSON.parse(data);
			} catch {
				return;
			}
			if (typeof json != 'object') return;
			if (json?.description) remote_desc = json.description;
			// TODO: Wait on applying remote candidates until remote_desc == false? Or maybe just catch errors?
			if (json?.candidate) await this.addIceCandidate(json.candidate);
		});
		this.addEventListener('icecandidate', ({ candidate }) => {
			if (candidate && this.#dc.readyState == 'open') {
				this.#dc.send(JSON.stringify({ candidate }));
			}
		});

		// First pass of signaling
		await super.setRemoteDescription({
			type: 'offer',
			sdp: [
				'v=0',
				'o=swbrd 42 0 IN IP4 0.0.0.0',
				's=-',
				't=0 0',
				'a=group:BUNDLE dc' + (audio ? ' audio' : ''),
				`a=fingerprint:${this.pid.fingerprint}`,
				'a=ice-ufrag:dissolve',
				'a=ice-pwd:the/ice/password/constant',
				'a=ice-lite',
				`a=setup:${setup}`,
				'm=application 0 UDP/DTLS/SCTP webrtc-datachannel',
				'c=IN IP4 0.0.0.0',
				'a=bundle-only',
				'a=mid:dc',
				`a=sctp-port:${sctp_port}`,
				...(audio ? [
					'm=audio 0 UDP/TLS/RTP/SAVPF 100 101',
					'c=IN IP4 0.0.0.0',
					'a=bundle-only',
					'a=rtcp-mux',
					'a=mid:audio',
					'a=sendrecv',
					'a=rtpmap:100 opus/48000/2',
					'a=fmtp:100 useinbandfec=1',
					'a=rtpmap:101 telephone-event/8000',
					'a=rtcp-mux',
				] : []),
				'',
			].join('\n'),
		});

		// Audio
		if (audio) {
			const trans = super.getTransceivers().find(t => t.mid == 'audio');
			trans.direction = 'sendrecv';
		}

		// TODO: I'm worried that the sctp-port in the local description might change in the future...  Currently this is the only assumption that I'm aware of, everything else has been setup in the original offer.
		await super.setLocalDescription();

		// Switchover into handling renegotiation
		for (; ;) {
			// We don't need the datachannel to apply the adjustment, just waiting for DTLS to finish is enough.
			if (this.connectionState == 'closed') {
				break
			} else if (this.connectionState != 'connected') {
				await state({ 'connectionstatechange': this });
			}
			// Connection state must be 'connected'
			else if (adjustment) {
				adjustment = null;
				this.setConfiguration(config);
				this.restartIce();
			} else if (negotiation_needed) {
				negotiation_needed = false;

				await super.setLocalDescription();

				// Once we have a local description to send, we can't do any more renegotiation until we've enqueued the message.
				// If SCTP isn't being used by this connection, the signaling task will hang here until the Conn is closed.
				while (this.#dc.readyState == 'connecting') await state({ 'open': this.dc, 'close': this.dc });
				if (this.#dc.readyState != 'open') break; // We can no longer enqueue messages so we're done handling renegotiation.

				try {
					// HACK: Looks like Chrome is the dumbass in this situation.  It's advertising 'a=setup:actpass' even though the DTLS handshake has already been completed.  Firefox doesn't help us in this situation because it seems to pick 'a=setup:active' by default even though it was passive during setup.
					// Fuck my life.  We need to replace 'a=setup:actpass' with the actual value as taken from the current description.
					// Because we max bundling is in our overrides, there should only be ~one~ setup line.
					const description = this.localDescription;
					const { 0: current_setup } = this.currentLocalDescription.sdp.match(
						/a=setup:.+/img,
					);
					description.sdp = description.sdp.replace(
						/a=setup:actpass/img,
						current_setup,
					);

					this.#dc.send(JSON.stringify({ description }));
				} catch { /* noop */ }
			} else if (remote_desc) {
				const desc = remote_desc;
				remote_desc = false;
				// Ignore incoming offers if we have a local offer and are also impolite
				if (
					desc?.type == 'offer' && this.signalingState == 'have-local-offer' &&
					!polite
				) continue;

				await super.setRemoteDescription(desc);

				if (desc?.type == 'offer') negotiation_needed = true; // Call setLocalDescription.
			} else {
				// Wait for something to happen
				await state({
					'negotiationneeded': this,
					'message': this.dc,
					'close': this.dc,
				});
			}
		}
	}

	#fixup_candidates(e) {
		const { candidate } = e;
		e.stopImmediatePropagation();

		if (!(candidate?.candidate)) {
			this.dispatchEvent(new CandidateEvent(null));
			return;
		}

		// Parse the candidate
		const [prefix, rest] = candidate?.candidate.split(/(?=typ)/i);
		const props = new Map();
		for (const { 1: key, 2: val } of rest.matchAll(/([^ ]+) ([^ ]+)/ig)) {
			props.set(key, val);
		}

		// Adjust the props to include our full ICE credentials
		const { 1: ufrag } = /a=ice-ufrag:(.+)/im.exec(this.localDescription.sdp);
		const { 1: pwd } = /a=ice-pwd:(.+)/im.exec(this.localDescription.sdp);
		props.set('ufrag', ufrag);
		props.set('pwd', pwd);

		const suffix = Array.from(props.entries()).flat(1).join(' ');

		const fixed = new RTCIceCandidate({
			...candidate.toJSON(),
			candidate: prefix + suffix,
		});
		this.dispatchEvent(new CandidateEvent(fixed));
	}

	async addIceCandidate(candidate) {
		if (candidate == null) return;

		if (typeof candidate != 'object') {
			candidate = { candidate: candidate };
		} else if (candidate instanceof RTCIceCandidate) {
			candidate = candidate.toJSON();
		} else if (Array.isArray(candidate)) {
			const [address, port, type] = candidate;
			candidate = { address, port, type };
		}

		// Can't add ICE candidates while the remote description is null:
		// HACK: Firefox additionally seems to need the local description to be set before adding remote candidates. (Unless those candidates are set in the remote SDP).
		while (
			super.remoteDescription === null ||
			is_firefox && super.localDescription === null
		) {
			await state({ 'signalingstatechange': this });
		}

		// WEIRD: For some reason, Firefox won't pair the candidate unless it has a related address and port (which are supposed to be optional?)
		const firefox_hack1 = is_firefox ? ['raddr', '::', 'rport', '0'] : [];
		// This removes an error in Firefox when the usernameFragment is not recognized
		const firefox_hack2 = is_firefox ? { usernameFragment: null } : {};
		// Please Firefox, I beg you to deprecate your impl and just fucking switch to libwebrtc like Safari

		candidate.candidate ??= 'candidate:' + [
			candidate.foundation || 'foundation',
			candidate.component || '1',
			candidate.transport || 'udp',
			candidate.priority || '42',
			candidate.address || candidate.a,
			candidate.port || candidate.p,
			'typ',
			candidate.type || 'relay',
			...firefox_hack1,
			// WEIRD: Best as I can tell, Firefox has strange behavior around 'localhost' or '::1' candidate addresses
		].join(' ');
		candidate.sdpMid ??= 'dc';
		return await super.addIceCandidate({
			...candidate,
			...firefox_hack2,
		});
	}

	// Re-provide defaults when calling setConfiguration
	setConfiguration(config = null) {
		super.setConfiguration({
			...defaults,
			...config,
			...overrides,
			certificates: [this.#cert],
		});
	}

	// Disable manual signaling:
	createOffer() {
		throw new Error('Manual signaling is disabled on Conn');
	}
	createAnswer() {
		throw new Error('Manual signaling is disabled on Conn');
	}
	setLocalDescription() {
		throw new Error('Manual signaling is disabled on Conn');
	}
	setRemoteDescription() {
		throw new Error('Manual signaling is disabled on Conn');
	}

	// Disable things:
	static generateCertificate() {
		throw new Error(
			'generateCertificate is disabled on Conn. You can use `Cert.generate()` instead.',
		);
	}
	addStream() {
		throw new Error('addStream is deprecated');
	}
	removeStream() {
		throw new Error('removeStream is deprecated');
	}
	getIdentityAssertion() {
		throw new Error('Identity assertions are disabled on Conn');
	}
	setIdentityProvider() {
		throw new Error('Identity assertions are disabled on Conn');
	}
	get peerIdentity() {
		throw new Error('Identity assertions are disabled on Conn');
	}
}
