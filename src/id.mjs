import { binstrtobuf, buftobinstr, atob_url, btoa_url } from "./b64url.mjs";
import { reg_all } from "./util.mjs";

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
].map(a => [a, a.slice().reverse()]).flat());

export class Id {
	constructor(init) {
		if (typeof init == 'string') {
			for (const v of init.split(',')) {
				try {
					const binstr = atob_url(v);
					const alg = untagged.get(binstr.length);
					if (alg) this[alg] = binstr;
				} catch {/* */}
			}
		} else {
			Object.assign(this, ...arguments);
		}
	}
	sdp() {
		return Object.entries(this)
			.map(([alg, v]) => binstrtobuf(v).reduce((a, v, i) => a + (i > 0 ? ':' : '') + v.toString(16).padStart(2, '0'), `a=fingerprint:${alg} `));
	}
	add_sdp(sdp) {
		for (const {1: alg, 2: value} of reg_all(/a=fingerprint:([^ ]+) (.+)/g, sdp)) {
			if (alg in this) continue;
			this[alg] = buftobinstr(value.split(':').map(s => parseInt(s, 16)));
		}
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'number') {
			const binstr = this[advanced_usage.id_alg] ?? '\0';
			return BigInt(binstrtobuf(binstr).reduce((a, v) => a + v.toString(16).padStart(2, '0'), '0x'));
		} else {
			return fingerprints.map(h => {
				const tag = untagged.has(h) ? '' : String.fromCharCode(tagged.get(h));
				return btoa_url(tag + this[h]);
			}).join(',');
		}
	}
}

/**
 * Create an Id from an RTCCertificate.  This uses a few different methods (depending on what is supported by this browser) to gather certificate fingerprints.  In general sha-256 fingerprints are always available.  Other algorithms are currently only available in Chrome.  In Firefox, a temporary RTCPeerConnection is used to gather fingerprints, where as in Chrome / Safari no temporary connection is needed (for sha-256 at least).
 * @param {RTCCertificate} cert 
 * @returns {Promise<Id | undefined>}
 */
export async function make_id(cert) {
	const ret = new Id();
	const are_we_done = () => fingerprints.every(algorithm => algorithm in ret);

	// Try getFingerprints
	if ('getFingerprints' in cert) {
		for (const {algorithm, value} of cert.getFingerprints()) {
			ret[algorithm] = buftobinstr(value.split(':').map(s => Number.parseInt(s, 16)));
		}
		if (are_we_done()) return ret;
	}

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
			const reg = /a=fingerprint:([^ ]+) ([a-fA-F0-9]{2}(?:\:[a-fA-F0-9]{2})*)/g;
			let t;
			while ((t = reg.exec(a.localDescription.sdp))) {
				const {1: alg, 2: value} = t;
				ret[alg.toLowerCase()] = buftobinstr(value.split(':').map(s => Number.parseInt(s, 16)));
			}
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
						const v = await crypto.subtle.digest(alg, bytes);
						ret.add_fingerprint(alg.toLowerCase(), new Uint8Array(v));
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
