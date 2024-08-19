import { Class, Method, Stun } from '../switch/stun.js';
import { encoder } from './util.js';

export async function* listen(dc, {
	pwd = 'the/ice/password/constant'
} = {}) {
	const cred = await crypto.subtle.importKey('raw', encoder.encode(pwd), {
		name: 'HMAC',
		hash: 'SHA-1'
	}, true, ['sign', 'verify']);

	while (dc.readyState != 'closed') {
		let data = await new Promise(res => {
			dc.addEventListener('message', ({ data }) => res(data), {once: true});
			dc.addEventListener('close', () => res(), {once: true});
		});
		if (data instanceof Blob) {
			try { data = await data.arrayBuffer(); } catch { continue; }
		}
		else if (!(data instanceof ArrayBuffer)) continue;
	
		// Read the data as a TURN Data Indication
		if (data.byteLength < 20) continue;
		const ind = new Stun(data);
		if (ind.class != Class.indication || ind.method != Method.data) continue;
		const xpeer = ind.xpeer, inner = ind.data;
		if (!inner) continue;
	
		// Read the contents of the indication as an ICE Connection Test
		if (inner.byteLength < 20) continue;
		const test = new Stun(inner.buffer, inner.byteOffset, inner.byteLength);
		if (test.class != Class.request || test.method != Method.binding) continue;
		const username = test.username, priority = test.priority;
		if (!username) continue;
		const [lufrag, rufrag] = username.split(':');
	
		if (!await test.verify(cred)) continue;

		const ret = { lufrag, rufrag };

		if (xpeer) {
			ret.candidate = {
				address: xpeer.ip instanceof Uint8Array ? xpeer.ip.join('.') : Array.from(
					xpeer.ip,
					v => v.toString(16)
				).join(':'),
				port: xpeer.port,
				priority,
				usernameFragment: rufrag,
			};
		}

		yield ret;
	}
}
