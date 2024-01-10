import { binstrtobuf, buftobinstr, atob_url, btoa_url } from "./b64url.js";

export const advanced_usage = {
	// This hash algorithm will be used when converting an Id into a bigint.
	id_alg: 'sha-256'
};

// Currently, all the hash algorithms are distinguishable via their length.  Later we might need a tagging mechanism to disambiguate fingerprint algorithms
const untagged = new Map([
	['sha-1',   20],
	['sha-256', 32],
	['sha-384', 48],
	['sha-512', 64]
].map(a => [a, a.toReversed()]).flat());

export class Id {
	// If you're wondering why the hashes are stored on this object as binary strings, it's because strings are more indexeddb friendly than array buffers and we want Ids to be easily persisted.
	constructor(init) {
		if (typeof init == 'string') {
			for (const v of init.split(',')) {
				try {
					const binstr = atob_url(v);
					const alg = untagged.get(binstr.length);
					if (alg) this[alg] = binstr;
				} catch {/* */}
			}
			if (!(advanced_usage.id_alg in this)) {
				return null; // Id parsing failed to produce an Id with the required fingerprint algorithm
			}
		} else {
			Object.assign(this, ...arguments);
		}
	}
	*sdp() {
		for (const [alg, value] of Object.entries(this)) {
			const buff = [...binstrtobuf(value)];
			yield `a=fingerprint:${alg} ${buff.map(b => b.toString(16).padStart(2, '0')).join(':')}`;
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
			const binstr = this[advanced_usage.id_alg] ?? '\0';
			return BigInt(binstrtobuf(binstr).reduce((a, v) => a + v.toString(16).padStart(2, '0'), '0x'));
		} else {
			return Object.values(this).map(binstr => btoa_url(binstr)).join(',');
		}
	}
}

export async function make_id(cert, fingerprints = [advanced_usage.id_alg]) {
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
