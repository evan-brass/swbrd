import { buftobinstr, atob_url, btoa_url } from "./b64url.js";

// Currently, all the hash algorithms are distinguishable via their length.  Later we might need a tagging mechanism to disambiguate fingerprint algorithms
const untagged = new Map([
	['sha-512', 64],
	['sha-384', 48],
	['sha-256', 32],
	['sha-1',   20],
].map(a => [a, a.toReversed()]).flat());

export class Id {
	// If you're wondering why the hashes are stored on this object as binary strings, it's because strings are more indexeddb friendly than array buffers and we want Ids to be easily persisted.
	constructor(init) {
		if (typeof init == 'string') {
			const binstr = atob_url(init);
			const alg = untagged.get(binstr.length);
			if (alg) this[alg] = binstr;
		} else {
			Object.assign(this, ...arguments);
		}
		if (!this.#first_alg()) return null;
	}
	#first_alg() {
		for (const alg of untagged.keys()) {
			if (alg in this) return alg;
		}
	}
	#hex(key = this.#first_alg()) {
		if (!key) return [];
		return Array.from(this[key], s => s.charCodeAt(0).toString(16).padStart(2, '0'));
	}
	*sdp() {
		for (const key in this) {
			yield `a=fingerprint:${key} ${this.#hex(key).join(':')}`;
		}
	}
	add_sdp(sdp) {
		for (const {1: alg, 2: value} of sdp.matchAll(/a=fingerprint:([^ ]+) (.+)/g)) {
			const key = alg.toLowerCase();
			if (key in this) continue;
			this[key] = buftobinstr(value.split(':').map(s => parseInt(s, 16)));
		}
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'number') {
			return BigInt('0x' + this.#hex().join(''));
		} else {
			return btoa_url(this[this.#first_alg()]);
		}
	}
}

export async function make_id(cert, fingerprints = ['sha-256']) {
	const ret = new Id();
	const are_we_done = () => fingerprints.every(algorithm => algorithm in ret);

	// Try getFingerprints
	if ('getFingerprints' in cert) {
		for (const {algorithm, value} of cert.getFingerprints()) {
			ret[algorithm] = buftobinstr(value.split(':').map(s => parseInt(s, 16)));
		}
	}
	if (are_we_done()) return ret;

	// Use temporary connection:
	{
		const a = new RTCPeerConnection({
			certificates: [cert]
		});
		try {
			a.createDataChannel('_');
			await a.setLocalDescription();
			console.log(a.localDescription.sdp);

			// Collect fingerprints via the SDP:
			ret.add_sdp(a.localDescription.sdp);
			if (are_we_done()) return ret;

			if ('getRemoteCertificates' in a.sctp?.transport) {
				// Collect fingerprints via getRemoteCertificates on RTCDtlsTransport (only available in Chrome):
				const b = new RTCPeerConnection();
				a.addEventListener('icecandidate', ({candidate}) => b.addIceCandidate(candidate));
				b.addEventListener('icecandidate', ({candidate}) => b.addIceCandidate(candidate));
				try {
					const connected = new Promise(res => b.addEventListener('connectionstatechange', () => {
						if (b.connectionState == 'connected') res();
					}));
					await b.setRemoteDescription(a.localDescription);
					await b.setLocalDescription();
					await a.setRemoteDescription(b.localDescription);
					
					await connected;
					
					const bytes = b.sctp.transport.getRemoteCertificates()[0];
					for (const alg of [
						'SHA-1',
						'SHA-256',
						'SHA-384',
						'SHA-512'
					]) {
						ret[alg.toLowerCase()] = buftobinstr(await crypto.subtle.digest(alg, bytes));
					}

					if (are_we_done()) return ret;
				} finally {
					b.close()
				}
			}
		} finally {
			a.close();
		}
	}
}
