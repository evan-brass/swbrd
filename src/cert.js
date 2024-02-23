import { base58 } from './base58.js';

export const idf = new class IdFingerprint {
	algorithm;
	bytes;
	constructor() { Object.assign(this, ...arguments); }
	[Symbol.toPrimitive](hint) {
		if (hint == 'number') return 8 * this.bytes;
		else return this.algorithm;
	}
	toString(id) {
		return base58(BigInt(id));
	}
	fromString(s) {
		let ret = base58(String(s));
		if (ret) ret = BigInt.asUintN(Number(this), ret);
		return ret;
	}
	fingerprint(id) {
		return `${this.algorithm} ${BigInt(id).toString(16).padStart(2 * this.bytes, '0').replace(/[0-9a-f]{2}/ig, ':$&').slice(1)}`;
	}
}({ algorithm: 'sha-256', bytes: 32 });

export class Cert extends RTCCertificate {
	id;
	static async generate(params = { name: 'ECDSA', namedCurve: 'P-256' }) {
		const ret = await RTCPeerConnection.generateCertificate(params);
		Object.setPrototypeOf(ret, this.prototype);

		let fingerprint;
		// Try to retreive the fingerprint using getFingerprints
		if (ret?.getFingerprints) {
			for (const {algorithm, value} of ret.getFingerprints()) {
				if (algorithm.toLowerCase() == String(idf)) {
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
			for (const {1: algorithm, 2: value} of offer.sdp.matchAll(/^a=fingerprint:([^ ]+) ([0-9a-f]{2}(:[0-9a-f]{2})+)/img)) {
				if (algorithm.toLowerCase() == String(idf)) {
					fingerprint = value;
					break;
				}
			}
			temp.close();
		}

		// If we didn't get the required fingerprint, then return nothing
		if (!fingerprint) return;

		ret.id = BigInt.asUintN(
			Number(idf),
			BigInt('0x' + fingerprint.split(':').join(''))
		);
		Object.freeze(ret);

		return ret;
	}
	static async load(key = import.meta.url) {
		function wrap(req) {
			return new Promise((res, rej) => {
				req.onsuccess = () => res(req.result);
				req.onerror = () => rej(req.error);
			});
		}
		const openreq = indexedDB.open('swbrd', 1);
		openreq.onupgradeneeded = ({oldVersion, newVersion, target: {result: db}}) => {
			db.createObjectStore('certs');
		};
		openreq.onblocked = ({ oldVersion, newVersion }) => rej(new Error(`Certificate Database blocked: ${oldVersion} -> ${newVersion}`));
		const db = await wrap(openreq);

		// Generate a replacement in case the existing certificate has expired / doesn't match the idf / etc.
		const candidate = await this.generate();

		const trans = db.transaction('certs', 'readwrite');
		const certs = trans.objectStore('certs');
		const cursor_req = certs.openCursor(key);
		let cursor;
		while (cursor = await wrap(cursor_req)) {
			const { cert, id, algorithm } = cursor.value;
			if (cert.expires - Date.now() < 2 * (24 * 60 * 60 * 1000)) {
				cursor.delete();
			}
			else if (algorithm != String(idf)) {
				cursor.continue();
			}
			else {
				Object.setPrototypeOf(cert, this.prototype);
				cert.id = id;
				Object.freeze(cert);
				return cert;
			}
		}
		await wrap(certs.put({
			cert: candidate,
			id: candidate.id,
			algorithm: String(idf)
		}, key));

		return candidate;
	}
	[Symbol.toPrimitive](hint) {
		if (hint == 'number') return this.id;
		return this.toString();
	}
}

export const cert = await Cert.load();
