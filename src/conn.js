import { Id } from "./id.js";

export class Sig {
	// Required fields:
	id;
	candidates;
	// Optional Fields: [setup, ice_lite, ice_pwd]
	constructor() {
		Object.assign(this, ...arguments);
		if (!(this.id instanceof Id)) this.id = new Id(this.id);
		if (!Array.isArray(this.candidates)) this.candidates = [];
	}
	*sdp(polite) {
		yield* this.id.sdp();
		if (this.ice_lite) {
			yield 'a=ice-lite';
		}
		yield `a=ice-ufrag:${this.id}`;
		yield `a=ice-pwd:${this.ice_pwd || 'the/ice/password/constant'}`;
		for (let i = 0; i < this.candidates.length; ++i) {
			const c = this.candidates[i];
			yield `a=candidate:foundation 1 ${c.transport || 'udp'} ${c.priority ?? i + 1} ${c.address} ${c.port || '3478'} typ ${c.typ || 'host'}${
				c.transport == 'tcp' ? ' tcptype passive' : ''
			}`;
		}
		yield `a=setup:${this.setup || polite ? 'passive' : 'active'}`;
	}
	add_sdp(sdp) {
		this.id.add_sdp(sdp);
		for (const {1: candidate} of sdp.matchAll(/a=candidate:(.+)/ig)) {
			// console.log(candidate);
			const res = /[^ ]+ [0-9]+ udp ([0-9]+) ([^ ]+) ([0-9]+) typ (host|srflx|relay)/i.exec(candidate);
			if (!res) continue;
			const [_, priority, address, port, typ] = res;
			this.candidates.push({transport: 'udp', priority: parseInt(priority), address, port: parseInt(port), typ});
		}
		this.candidates.sort((a, b) => a.priority - b.priority);
	}
}

export const default_config = {
	iceServers: [
		{ urls: 'stun:global.stun.twilio.com:3478' },
		{ urls: 'stun:stun.l.google.com:19302' }
	]
};

export class Conn extends RTCPeerConnection {
	// The zero datachannel (used for connection renegotiation)
	#dc = this.createDataChannel('', {negotiated: true, id: 0});
	connected = new Promise((res, rej) => {
		this.#dc.addEventListener('open', () => res(this), {once: true});
		this.#dc.addEventListener('error', ({error}) => rej(error), {once: true});
		this.#dc.addEventListener('close', () => rej(new Error("closed")), {once: true});
	});

	// Local
	#local_id_res;
	local_id = new Promise(res => this.#local_id_res = res);
	local = (async () => {
		// Wait for ICE gathering to complete:
		while (this.iceGatheringState != 'complete') await new Promise(res => this.addEventListener('icegatheringstatechange', res, {once: true}));

		const ret = new Sig();
		ret.add_sdp(this.localDescription.sdp);
		return ret;
	})();

	// Remote
	#remote_res;
	#remote = new Promise(res => this.#remote_res = res);
	get remote() { return this.#remote; }
	set remote(sig) { this.#remote = sig; this.#remote_res(this.#remote); }

	constructor(config = null) {
		super({ ...default_config, ...config});
		this.#signal_task();
	}
	setConfiguration(config = null) {
		super.setConfiguration({ ...default_config, ...config });
	}
	#perfect(polite) {
		let making_offer = false;

		const send_signaling = async obj => {
			while (this.#dc.readyState !== 'open') {
				if (this.#dc.readyState !== 'connecting') throw new Error('Renegotiation channel is either closing or already closed.');
				await new Promise((res, rej) => {
					this.#dc.addEventListener('open', res, {once: true});
					this.#dc.addEventListener('close', rej, {once: true});
					this.#dc.addEventListener('error', rej, {once: true});
				});
			}
			this.#dc.send(JSON.stringify(obj));
		};

		this.addEventListener('negotiationneeded', async () => {
			try {
				making_offer = true;
				await super.setLocalDescription();

				await send_signaling({ description: this.localDescription });
			}
			catch (e) { console.error(e); }
			finally {
				making_offer = false;
			}
		});

		this.addEventListener('icecandidate', async ({ candidate }) => {
			if (this.#dc.readyState == 'open') await send_signaling({ candidate });
		});

		let ignore_offer = false;
		this.#dc.addEventListener('message', async ({ data }) => {
			try {
				const { description, candidate } = JSON.parse(data);

				if (description) {
					const offer_collision = description.type === 'offer' &&
						(making_offer || super.signalingState !== 'stable');

					ignore_offer = !polite && offer_collision;
					if (ignore_offer) return;

					await super.setRemoteDescription(description);
					if (description.type === 'offer') {
						await super.setLocalDescription();
						await send_signaling({ description: this.localDescription });
					}
				}

				if (candidate) {
					try { await this.addIceCandidate(candidate); }
					catch (e) { if (!ignore_offer) throw e; }
				}
			}
			catch (e) { console.error(e); }
		});
	}
	async #signal_task() {
		// Create our local offer:
		const offer = await super.createOffer();

		// Gather our local id from the offer
		this.local_id = new Id();
		this.local_id.add_sdp(offer.sdp);
		this.#local_id_res(this.local_id);

		// Mung our ICE credentials to match our local_id
		offer.sdp = offer.sdp
			.replace(/a=ice-ufrag:.+/, `a=ice-ufrag:${this.local_id}`)
			.replace(/a=ice-pwd:.+/, 'a=ice-pwd:the/ice/password/constant');
			
		// Apply the offer
		await super.setLocalDescription(offer);

		// Wait for the remote signaling message:
		const remote = await this.remote;

		// Start the perfect negotiation pattern
		const polite = remote.id < this.local_id;
		// TODO: Merge the perfect negotiation pattern into this signaling task
		this.#perfect(polite);

		// Set the remote description:
		const sdp = [
			'v=0',
			'o=- 20 0 IN IP4 0.0.0.0',
			's=-',
			't=0 0',
			'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
			'c=IN IP4 0.0.0.0',
			...remote.sdp(polite),
			'a=sctp-port:5000',
			''
		].join('\n');
		await super.setRemoteDescription({ type: 'answer', sdp });
	}
	// Conn does automatic renegotiation over #dc so we disable manual signaling
	setLocalDescription() { throw new Error("Manual signaling is disabled."); }
	setRemoteDescription() { throw new Error("Manual signaling is disabled."); }
	createOffer() { throw new Error("Manual signaling is disabled."); }
	createAnswer() { throw new Error("Manual signaling is disabled."); }
}
