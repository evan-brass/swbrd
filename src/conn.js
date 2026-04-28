import { cert as default_cert } from './cert.js';
import { Id } from './id.js';
import { is_firefox, state } from './util.js';
import { pid as server_pid } from './deter.js';

export const defaults = {
	iceServers: [{
		urls: [
			'turn:turn.evan-brass.net',
			'turn:turn.evan-brass.net?transport=tcp',
			'turns:turn.evan-brass.net?transport=tcp',
			'turns:turn.evan-brass.net:443?transport=tcp',
		],
		username: 'guest',
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

	// Make a connection to a TURN server, then use cert prefix mechanism using private ipv6 address space fd01::/64
	// - TURN can be multiplexed with HTTP
	// - IPv6 not require for either client or server
	// - Server doesn't need ipv6 prefix, /128 would
	static to_server(urls = "turns:turn.evan-brass.net:443?transport=tcp", config = null) {
		return new this(server_pid, {
			iceTransportPolicy: 'relay',
			iceServers: [{ urls, username: 'guest', credential: 'password' }],
			setup: 'passive',
			cert_prefix: 'fd01::',
			...config,
		});
	}
	// Make a direct connection to a server using the cert-prefix mechanism
	// - Client must have IPv6
	// - Server must have IPv6 /64
	static to_server_direct(cert_prefix = '2a01:4ff:1f0:7e46:', config = null) {
		return new this(server_pid, {
			iceServers: [],
			setup: 'passive',
			cert_prefix,
			...config,
		});
	}
	// Make a connection between two Chrome browsers
	// - Chrome <-> Chrome via fixup
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
				iceServers: [{ urls: 'turns:turn-4only.evan-brass.net:443?transport=tcp', username: 'guest', credential: 'password' }]
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
		cert_prefix = false,
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
			const t = setTimeout(() => this.close(), timeout);
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
			cert_prefix,
		}).catch((e) => {
			console.error(e);
			this.close();
		});
	}

	async #signaling_task(
		{ polite, config, adjustment, setup, cert_prefix },
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
				'a=group:BUNDLE dc',
				`a=fingerprint:${this.pid.fingerprint}`,
				'a=ice-ufrag:dissolve',
				'a=ice-pwd:the/ice/password/constant',
				'a=ice-lite',
				'm=application 0 UDP/DTLS/SCTP webrtc-datachannel',
				'c=IN IP4 0.0.0.0',
				'a=bundle-only',
				'a=mid:dc',
				`a=setup:${setup}`,
				'a=sctp-port:5000',
				'',
			].join('\n'),
		});

		// TODO: I'm worried that the sctp-port in the local description might change in the future...  Currently this is the only assumption that I'm aware of, everything else has been setup in the original offer.
		await super.setLocalDescription();

		// The cert prefix mechanism combines 16 bits from the pid with a /64 to get a /80 within which we add a random ip+port ICE candidate.
		// Why would you do this?  Because the destination ip+port can act as a connection identifier since WebRTC doesn't support DTLS CID
		if (cert_prefix) {
			const [port, ...segments] = crypto.getRandomValues(new Uint16Array(4));
			const prefix = cert_prefix + (this.pid & 0xffffn).toString(16);
			const address = segments.reduce((a, v) => a + ':' + v.toString(16), prefix);
			this.addIceCandidate({ address, port: port | 0x8000 });
		}

		// Switchover into handling renegotiation
		for (; ;) {
			if (this.#dc.readyState == 'connecting') {
				await state({ 'open': this.dc, 'close': this.dc });
			} else if (this.#dc.readyState == 'closed') {
				break;
			} else if (adjustment) {
				adjustment = null;
				this.setConfiguration(config);
				this.restartIce();
			} else if (negotiation_needed && this.#dc.readyState != 'closing') {
				negotiation_needed = false;

				await super.setLocalDescription();
				try {
					// HACK: Looks like Chrome is the dumbass in this situation.  It's advertising 'a=setup:actpass' even though the DTLS handshake has already been completed.  Firefox doesn't help us in this situation because it seems to pick 'a=setup:active' by default even though it was passive during setup.
					// Fuck my life.  We need to replace 'a=setup:actpass' with the actual value as taken from the current description.
					const description = this.localDescription;
					const { 0: current_setup } = this.currentLocalDescription.sdp.match(/a=setup:.+/img);
					description.sdp = description.sdp.replace(/a=setup:actpass/img, current_setup);

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
		const firefox_hack2 = is_firefox ? { usernameFragment: null } : {}
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
			,
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
