import { algorithm, from_string } from './id.js';
import { Conn } from './conn.js';
import { query_txt } from './dns.js';
import { default_turn_credential, default_turn_username } from './const.js';
import { is_firefox, state } from './util.js';
/**
 * Example Addr-esses:
 * const a = new Addr('udp:seed.evan-brass.net'); await a.resolve_id(); const conn = a.connect();
 * const conn = new Addr('udp:vMLqtj41eqxrH4ExSw893MLbgDm1JHWqkv9R9AMqhHDE@example.com').connect();
 * const conn = new Addr('turn+tcp:U5PYjsHYz77HroCoCTy7hM9YuZ9G6oFZ6z3mWrFCP8uF@127.0.0.1').connect();
 */
export class Addr extends URL {
	#id;
	get id() {
		if (!this.#id) {
			const { username } = this.authority;
			this.#id = from_string(username);
		}
		return this.#id;
	}

	async resolve_id() {
		if (this.id) return this.#id;
		const { hostname } = this.authority;
		for await (
			const txt of query_txt(hostname, { prefix: `swbrd(${algorithm})=` })
		) {
			this.#id ??= from_string(txt);
		}
		return this.#id;
	}
	#authority;
	get authority() {
		if (this.#authority?.href != this.href) {
			// Use two URLS to unhide default ports: new URL('https://test.com:443').port == '' and new URL('http://test.com:80').port == ''
			const http = new URL(this.href.replace(/^[^:]+:/, 'http:'));
			const https = new URL(this.href.replace(/^[^:]+:/, 'https:'));
			const host = (http.host.length < https.host.length)
				? https.host
				: http.host;
			const port = parseInt(http.port || https.port || 3478);
			const address = http.hostname.replaceAll(/[\[\]]/g, '');
			this.#authority = {
				href: this.href,
				username: decodeURIComponent(http.username),
				password: decodeURIComponent(http.password),
				hostname: http.hostname,
				host,
				port,
				address,
			};
		}
		return this.#authority;
	}
	temp_adjustment() {
		const turn_res = /^(turns?)(?:\+(tcp|udp))?:/i.exec(this.protocol);
		if (!turn_res) return null;
		const { 1: proto, 2: transport } = turn_res;
		const { host } = this.authority;
		return {
			/**
			 * HACK: If iceTransportPolicy=='relay' then Firefox will kill local relay candidates if they become prflx candidates.
			 * Chrome will mark the local candidate as prflx but that doesn't stop it from utilizing it.
			 * - https://www.rfc-editor.org/rfc/rfc9429#section-4.1.1
			 * - https://www.rfc-editor.org/rfc/rfc9429#sec.ice-candidate-policy
			 *
			 * ISSUE: If I knew what the right thing to do was...
			 */
			iceTransportPolicy: is_firefox ? 'all' : 'relay',
			iceServers: [{
				urls: `${proto}:${host}${transport ? '?transport=' + transport : ''}`,
				username: decodeURIComponent(
					this.searchParams.get('turn_username') || default_turn_username,
				),
				credential: decodeURIComponent(
					this.searchParams.get('turn_credential') || default_turn_credential,
				),
			}],
		};
	}
	*candidates() {
		// Yield candidate search params
		const candidates = Array.from(
			this.searchParams.getAll('candidate'),
			(val) => {
				val = decodeURIComponent(val);
				let json;
				try {
					json = JSON.parse(val);
				} catch { /* */ }
				if (typeof json == 'object') return json;
				return { candidate: 'candidate:' + val };
			},
		);

		yield* candidates;

		if (candidates.length > 0) return;

		// Yield protocol specific candidate
		const { username, address, port } = this.authority;
		const usernameFragment = decodeURIComponent(username);

		if (/^udp:/i.test(this.protocol)) {
			yield { address, port, usernameFragment };
		} else if (/^(turns?)(?:\+(tcp|udp))?:/i.test(this.protocol)) {
			yield {
				address: is_firefox ? 'fe80::ffff:ffff:ffff:ffff' : 'ff02::1',
				port: 65535,
				usernameFragment,
			};
		}
	}
	connect(config = null) {
		if (!this.id) return;

		// Adjust the config if needed
		const adjustment = this.temp_adjustment();

		const { password: ice_pwd } = this.authority;
		const setup = decodeURIComponent(
			this.searchParams.get('setup') ?? 'passive',
		);

		/**
		 * HACK: Needed because Firefox doesn't switch roles when it receives 487 switch-role errors
		 * If 487 works, you shouldn't need to explicitly state that you're connecting to
		 * an ice-lite server, and you shouldn't need to know the credentials of your clients.
		 *
		 * When responding to ICE requests you only need to know your own ICE credentials.
		 *
		 * ISSUE: https://bugzilla.mozilla.org/show_bug.cgi?id=1940001
		 */
		const ice_lite = this.searchParams.get('ice-lite');

		// Create the connection
		const ret = new Conn(this.id, {
			ice_pwd,
			setup,
			ice_lite,
			adjustment,
			...config,
		});

		// Spawn the task to signal the connection
		(async () => {
			for (const candidate of this.candidates()) {
				await ret.addIceCandidate(candidate);
			}
		})();

		return ret;
	}
}
