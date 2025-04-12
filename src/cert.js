import { algorithm, from_bytes, to_string } from './id.js';

const day_in_ms = 24 * 60 * 60 * 1000;
const year_in_ms = 365 * day_in_ms;

export class Cert extends RTCCertificate {
	id;
	static async generate(
		keygenAlgorithm = {
			name: 'ECDSA',
			namedCurve: 'P-256',
			expires: Date.now() + year_in_ms,
		},
	) {
		const ret = await RTCPeerConnection.generateCertificate(keygenAlgorithm);
		Object.setPrototypeOf(ret, this.prototype);

		let fingerprint;
		// Try to retreive the fingerprint using getFingerprints
		if (ret?.getFingerprints) {
			for (const { algorithm, value } of ret.getFingerprints()) {
				if (algorithm.toLowerCase() == algorithm) {
					fingerprint = value;
					break;
				}
			}
		}

		// Try to retreive the fingerprint using a temporary connection
		if (!fingerprint) {
			const temp = new RTCPeerConnection({ certificates: [ret] });
			temp.createDataChannel('');
			const offer = await temp.createOffer();
			for (
				const { 1: algorithm, 2: value } of offer.sdp.matchAll(
					/^a=fingerprint:([^ ]+) ([0-9a-f]{2}(:[0-9a-f]{2})+)/img,
				)
			) {
				if (algorithm.toLowerCase() == algorithm) {
					fingerprint = value;
					break;
				}
			}
			temp.close();
		}

		// If we didn't get the required fingerprint, then return nothing
		if (!fingerprint) return;

		ret.id = from_bytes(fingerprint.split(':'));
		Object.freeze(ret);

		return ret;
	}
	static async load(key = import.meta.url, keygenAlgorithm) {
		function wrap(req) {
			return new Promise((res, rej) => {
				req.onsuccess = () => res(req.result);
				req.onerror = () => rej(req.error);
			});
		}
		const openreq = indexedDB.open('swbrd', 1);
		openreq.onupgradeneeded = (
			{ oldVersion: _ov, newVersion: _nv, target: { result: db } },
		) => {
			db.createObjectStore('certs');
		};
		openreq.onblocked = ({ oldVersion, newVersion }) =>
			rej(
				new Error(
					`Certificate Database blocked: ${oldVersion} -> ${newVersion}`,
				),
			);
		const db = await wrap(openreq);

		// Generate a replacement in case the existing certificate has expired / doesn't match the algorithm / etc.
		const candidate = await this.generate(keygenAlgorithm);

		const trans = db.transaction('certs', 'readwrite');
		const certs = trans.objectStore('certs');
		const cursor_req = certs.openCursor(key);
		let cursor;
		while ((cursor = await wrap(cursor_req))) {
			const { cert, id, algorithm: alg } = cursor.value;
			if (cert.expires - Date.now() < 2 * day_in_ms) {
				cursor.delete();
			} else if (alg != algorithm) {
				cursor.continue();
			} else {
				Object.setPrototypeOf(cert, this.prototype);
				cert.id = id;
				Object.freeze(cert);
				return cert;
			}
		}
		await wrap(certs.put({
			cert: candidate,
			id: candidate.id,
			algorithm,
		}, key));

		return candidate;
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'number') return this.id;
		return to_string(this.id);
	}
}

export const cert = await Cert.load();
