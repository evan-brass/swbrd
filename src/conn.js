import { cert as default_cert } from './cert.js';
import { default_ice_pwd } from './const.js';
import { algorithm, from_bytes, to_fingerprint, to_string } from './id.js';
import { is_firefox, state } from './util.js';

export const defaults = {
	iceServers: [{
		// urls: 'turn:stun.evan-brass.net',
		urls: 'turn:localhost?transport=tcp',
		username: 'guest',
		credential: 'password',
	}],
};
const overrides = {
	bundlePolicy: 'max-bundle',
	rtcpMuxPolicy: 'require',
	peerIdentity: null,
};

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

	get polite() {
		if (!this.#cert) {
			throw new Error(
				'Connection failed: cert was overridden, but other parameters required politeness prior to generating the local answer. Perhaps you needed to also override the setup.',
			);
		}
		return (BigInt(this.cert) < this.pid);
	}

	constructor(peerid, {
		setup,
		ice_lite,
		ice_pwd,
		mung = true,
		timeout = 10_000,
		starter = ['::ffff:255.255.255.255', 65535],
		...config
	} = {}) {
		const cert = config?.cert ?? default_cert;

		super({
			...defaults,
			...config,
			certificates: cert ? [cert] : [],
			...overrides,
		});
		this.#pid = BigInt(peerid);
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

		this.#signaling_task({
			setup,
			ice_lite,
			ice_pwd,
			mung,
		}).catch((e) => {
			console.error(e);
			this.close();
		});
		if (starter) this.addIceCandidate(starter);
	}

	async addIceCandidate(candidate) {
		if (candidate == null) return;

		if (typeof candidate != 'object') {
			candidate = { candidate: candidate };
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

		candidate.usernameFragment ??=
			/a=ice-ufrag:(.+)/i.exec(super.remoteDescription.sdp)[1];
		candidate.candidate ??= 'candidate:' + [
			candidate.foundation || 'foundation',
			candidate.component || '1',
			candidate.transport || 'udp',
			candidate.priority || '42',
			candidate.address || candidate.a,
			candidate.port || candidate.p,
			'typ',
			candidate.type || 'relay',
			// WEIRD: Best as I can tell, Firefox has strange behavior around 'localhost' or '::1' candidate addresses
			// WEIRD: For some reason, Firefox won't pair the candidate unless it has a related address and port (which are supposed to be optional?)
			'raddr',
			'::',
			'rport',
			'0',
			// 'ufrag', candidate.usernameFragment,
		].join(' ');
		candidate.sdpMid ??= 'dc';
		return await super.addIceCandidate(candidate);
	}

	async #signaling_task(/* Session: */ { setup, ice_lite, ice_pwd, mung }) {
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
				`a=fingerprint:${to_fingerprint(this.pid)}`,
				`a=ice-ufrag:${to_string(this.pid)}`,
				`a=ice-pwd:${ice_pwd || default_ice_pwd}`,
				'a=ice-options:trickle',
				...(ice_lite != undefined ? ['a=ice-lite'] : []),
				'm=application 42 UDP/DTLS/SCTP webrtc-datachannel',
				'c=IN IP4 0.0.0.0',
				'a=mid:dc',
				// Read the following line as: "If I am polite, then the remote peer will be active therefore I must be passive": unless overridden, the polite peer is the DTLS server.
				`a=setup:${setup || (this.polite ? 'active' : 'passive')}`,
				'a=sctp-port:5000',
				'',
			].join('\n'),
		});

		let answer;
		// Depending on mung, we may need the cert earlier or later. This function is a noop if the cert was provided.
		const need_cert = () => {
			this.#cert ||= from_bytes(
				Array.from(
					(answer ?? this.localDescription).sdp.matchAll(
						/^a=fingerprint:([^ ]+) ([0-9a-f]{2}(:[0-9a-f]{2})+)/img,
					),
					({ 1: alg, 2: value }) => ({ alg, value }),
				).find((v) => v.alg.toLowerCase() == algorithm)
					.value.split(':'),
			);
		};

		// Mung our answer
		if (mung) {
			answer = await super.createAnswer();
			need_cert();
			answer.sdp = answer.sdp
				.replace(/^a=ice-ufrag:.+/im, `a=ice-ufrag:${to_string(this.#cert)}`)
				.replace(/^a=ice-pwd:.+/im, `a=ice-pwd:${ice_pwd || default_ice_pwd}`);
		}
		await super.setLocalDescription(answer);
		need_cert();

		// Switchover into handling renegotiation
		while (this.#dc.readyState != 'closed') {
			if (this.#dc.readyState == 'connecting') {
				await state({ 'open': this.dc, 'close': this.dc });
			} else if (negotiation_needed) {
				if (this.#dc.readyState == 'closing') continue;
				negotiation_needed = false;

				/**
				 * HACK: Needed because Firefox doesn't preserve munged ICE credentials.
				 * This causes Firefox to unknowingly trigger an ICE restart and then
				 * when the answer contains new ICE credentials, it throws an error saying
				 * it didn't ask for an ICE restart (even though it actually did).
				 *
				 * ISSUE: https://bugzilla.mozilla.org/show_bug.cgi?id=1916752 (The don't intend to fix)
				 */
				if (mung && is_firefox) {
					super.restartIce();
					mung = false;
				}
				await super.setLocalDescription();
				try {
					this.#dc.send(JSON.stringify({ description: this.localDescription }));
				} catch { /* noop */ }
			} else if (remote_desc) {
				const desc = remote_desc;
				remote_desc = false;
				// Ignore incoming offers if we have a local offer and are also impolite
				if (
					desc?.type == 'offer' && this.signalingState == 'have-local-offer' &&
					!this.polite
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

	// Re-provide defaults when calling setConfiguration
	setConfiguration(config = null) {
		super.setConfiguration({
			...defaults,
			...config,
			...overrides,
			certificates: this.#cert instanceof RTCCertificate ? [this.#cert] : [],
		});
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
