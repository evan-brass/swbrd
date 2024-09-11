// import { Class, Method, Stun } from '../switch/stun.js';
import { encoder } from './util.js';
import { Addr } from './addr.js';
import { from_string } from "./id.js";
import { default_ice_pwd, default_turn_credential, default_turn_username } from "./const.js";
import { Conn } from "./conn.js";
// import { cert as default_cert } from './cert.js';
import { Sha1Integrity, Stun, TextAttr, U32Attr } from './stun.js';

const global_answered = new Map();

export class Listener extends Conn {
	#adjustment;
	
	#proto;
	#host;
	#turn_username;
	#turn_credential;

	config;
	timeout = 100_000;

	#ice_pwd = default_ice_pwd;
	#cred;
	get ice_pwd() { return this.#ice_pwd; }
	set ice_pwd(value) {
		if (typeof value == 'number') {
			value = btoa(
				String.fromCharCode(
					...crypto.getRandomValues(new Uint8Array(value))
				)
			).replace(/=/g, '');
		}
		this.#ice_pwd = value;
		this.#cred = undefined;
	}

	answered = global_answered;

	get addr() {
		const search = new URLSearchParams();
		if (this.#turn_username != default_turn_username) {
			search.set('turn_username', encodeURIComponent(this.#turn_username));
		}
		if (this.#turn_credential != default_turn_credential) {
			search.set('turn_credential', encodeURIComponent(this.#turn_credential));
		}
		const password = this.ice_pwd == default_ice_pwd ? '' : ':' + encodeURIComponent(
			this.ice_pwd
		);

		return new Addr(`${this.#proto}${this.cert}${password}@${this.#host}${search.size ? '?' : ''}${search}`);
	}

	constructor(arg, config = null) {
		const bind_addr = arg instanceof Addr ? arg : new Addr(String(arg));
		const adjustment = bind_addr.temp_adjustment();

		super(bind_addr.id, {
			...config,
			...adjustment,
			setup: bind_addr.searchParams.get('setup') ?? 'passive',
			ice_pwd: bind_addr.authority.password,
		});

		this.#adjustment = adjustment;

		// These are the pieces of the address we care about when answering connections
		this.#proto = bind_addr.protocol;
		this.#host = bind_addr.authority.host;
		this.#turn_username = bind_addr.searchParams.get('turn_username') ?? default_turn_username;
		this.#turn_credential = bind_addr.searchParams.get('turn_credential') ?? default_turn_credential;

		this.config = config;

		// Asyncronously add ICE canidates
		(async () => {
			for (const candidate of bind_addr.candidates()) {
				await this.addIceCandidate(candidate);
			}
		})();
	}

	async *[Symbol.asyncIterator](raw_tests = false) {
		while (this.dc.readyState != 'closed') {
			let data = await new Promise(res => {
				this.dc.addEventListener('message', ({ data }) => res(data), {once: true});
				this.dc.addEventListener('close', () => res(), {once: true});
			});
			if (data instanceof Blob) {
				try { data = await data.arrayBuffer(); } catch { continue; }
			}
			else if (!(data instanceof ArrayBuffer)) continue;

			// Read the data as a TURN Data Indication
			if (data.byteLength < 20) continue;
			const ind = new Stun(data);
			if (ind.class != 'indication' || ind.method != 'data') continue;
			const xpeer = ind.attrs.find(a => a.type == 'peer');
			const inner = ind.attrs.find(a => a.type == 'data')?.value;
			if (!inner) continue;

			// Read the contents of the indication as an ICE Connection Test
			if (inner.byteLength < 20) continue;
			const test = new Stun(inner);
			if (test.class != 'request' || test.method != 'binding') continue;
			const username = test.attrs.find(a => a.type == 'username');
			const priority = test.attrs.find(a => a.type == 'priority');
			const integrity = test.attrs.find(a => a.type == 'integrity');
			if (!(username instanceof TextAttr && integrity instanceof Sha1Integrity && priority instanceof U32Attr)) continue;
			const [lufrag, rufrag] = username.value.split(':');
			const [lid, rid] = [lufrag, rufrag].map(from_string);

			// Verify the HMAC Signature on the request against our ice_pwd
			if (!this.#cred) {
				this.#cred = await crypto.subtle.importKey('raw', encoder.encode(this.#ice_pwd), {
					name: 'HMAC',
					hash: 'SHA-1'
				}, true, ['sign', 'verify']);
			}
			if (!await integrity.verify(this.#cred)) continue;

			const candidate = xpeer ? {
				address: String(xpeer.ip),
				port: xpeer.port,
				priority: priority.value,
				type: 'relay',
				usernameFragment: rufrag,
			} : false;

			// TODO: Remove raw_tests and replace with two different iterator functions.
			if (raw_tests) { yield { lid, rid, candidate }; continue; }

			if (!candidate) continue;
			if (BigInt(this.cert) != lid) continue;
			if (typeof rid != 'bigint') continue;
			if (this.answered.has(rid)) {
				// MAYBE: Possibly add the candidate as an additional candidate? If we don't already have this candidate? Or would that be a bad?
				continue;
			}

			// Create the answering connection:
			const answer = new Conn(rid, {
				...this.config,
				...this.#adjustment,
				mung: true, // Munging is required when answering connections, even if munging was not required while connecting to the relay server.
				ice_pwd: this.ice_pwd,
				setup: 'active',
			});
			this.answered.set(rid, answer);

			// Start a timer that closes the answer if it doesn't connect
			const timer = setTimeout(() => { console.log('timing out', answer); answer.close(); }, this.timeout);
			answer.addEventListener('connectionstatechange', () => {
				if (answer.connectionState == 'connected') {
					clearTimeout(timer);

					// Remove the adjustment and restartICE:
				}
				else if (answer.connectionState == 'closed') {
					this.answered.delete(rid);
				}
			});

			// Spawn a task to add the candidate + reset the config:
			// This is essentially the same thing that .connect() does.
			(async () => {
				await answer.addIceCandidate(candidate);

				while (answer.dc.readyState != 'open') await new Promise(res => answer.dc.addEventListener('open', res, {once: true}));

				// Remove the adjustment
				answer.setConfiguration(this.config);
				answer.restartIce();
			})();

			yield answer;
		}
	}
}
