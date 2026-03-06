import { Id } from './id.js';
import { cert as default_cert } from './cert.js';
import { Conn } from './conn.js';
import { query_txt } from './dns.js';
import { default_turn_credential } from './const.js';
import { is_firefox } from './util.js';
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
			this.#id = new Id(username);
		}
		return this.#id;
	}

	async resolve_id() {
		if (this.id) return this.#id;
		const { hostname } = this.authority;
		for await (
			const txt of query_txt(hostname, { prefix: `swbrd(${algorithm})=` })
		) {
			this.#id ??= new Id(txt);
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
		const { address, port } = this.authority;
		if (/^udp:/i.test(this.protocol)) {
			yield { address, port };
		} else if (/^(turns?)(?:\+(tcp|udp))?:/i.test(this.protocol)) {
			yield {
				address: 'fe80::ffff:ffff:ffff:ffff',
				port: 65535,
			};
		}
	}
	connect(config = null) {
		if (!this.id) return;
		const pid = this.id;

		// Adjust the config if needed
		let ice_lite;
		if (this.searchParams.has('ice-lite')) ice_lite = true;
		let cert = config?.cert;
		let ice_ufrag = config?.ice_ufrag;
		let adjustment = null;
		const turn_res = /^(turns?)(?:\+(tcp|udp))?:/i.exec(this.protocol);
		if (turn_res) {
			const { 1: proto, 2: transport } = turn_res;
			const { host } = this.authority;

			// Turn addresses need to know the local cert to generate the Turn username for the adjustment
			cert ||= default_cert;
			ice_ufrag ||= 'dissolve';

			/**
			 * HACK: Firefox refuses to resolve role conflicts more than once.
			 *
			 * CODE: https://searchfox.org/mozilla-central/source/dom/media/webrtc/transport/third_party/nICEr/src/ice/ice_peer_ctx.c#858
			 *
			 * I use double-answer connections in Conn because by generating the offer, I can control bundling and mid's
			 * such that subsequent browser generated offers can be passed directly to the RTCPeerConnection.
			 *
			 * Without this, a fixup step would be needed on renegotiated sdp which would be more fragile.
			 * Another reason for using double-answer instead of double-offer connections is to force added media (audio/
			 * video transceivers) to be renegotiated over the datachannel using the browsers' normal media signaling paths.
			 *
			 * Since the browser is answering it will take the controlled role, but my dissolve system needs the browser
			 * to be controlling so that it can nominate candidate pairs without needing to receive an incoming request.
			 *
			 * This is the first role-conflict.  A second role conflict will occur once the peers renegotiate and start
			 * pairing non-relay candidates / using new ice credentials.
			 *
			 * To get Firefox to be controlling even while it answers, we have to use ice-lite.  Firefox has weird, but
			 * in our case desirable behavior with ice-lite: thinking the remote peer is ice-lite doesn't stop Firefox
			 * from switching roles.
			 *
			 * In Chrome setting ice-lite does appear to prevent switching roles.  At least that's what I think is going
			 * on.  Chrome seems to struggle switching off the relay candidate pair in general, but I swear I've seen it
			 * happen at least once.  If Chrome uses latency to select candidate pairs, then dissolve has an advantage
			 * because it is halfway between the two peers.  Hopefully I can make dissolve suck enough to improve Chrome's
			 * selection behavior over time.
			 *
			 * In any case, it's only Firefox that is limiting the number of renegotiations, so we'll only set ice-lite
			 * in Firefox.  This removes the role-conflict from dissolve, leaving a single role-conflict
			 * during renegotiation.
			 *
			 * Hopefully browser behavior doesn't change in the wrong direction 🤞
			 */
			ice_lite ??= is_firefox;

			adjustment = {
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
					username: `${to_string(pid)}:${to_string(cert)}`,
					credential: decodeURIComponent(
						this.searchParams.get('turn_credential') || default_turn_credential,
					),
				}],
			};
		}

		let { password: ice_pwd } = this.authority;
		if (ice_pwd === '') ice_pwd = undefined;

		let setup = decodeURIComponent(
			this.searchParams.get('setup') ?? 'passive',
		);
		if (setup === '') setup = undefined;

		// Create the connection
		const ret = new Conn(pid, {
			cert,
			ice_ufrag,
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
