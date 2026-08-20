// One connection to one Puddle.
//
// The path is the one tests/channels.html walks: Conn.to_domain authenticates
// the domain over TLS-TURN, the negotiated id-0 channel opening means SCTP is
// up, and only then do we open the DCEP channel whose protocol string the
// daemon's directory maps to the puddle extension.
//
// Everything after that is one JSON object per message, in both directions.

import { Conn } from 'swbrd/conn.js';

const PROTOCOL = 'rainboots.v1';

// A puddle that goes away comes back, with a widening gap so a server that is
// down for an hour is not hammered for an hour.
const RETRY_MIN = 2_000;
const RETRY_MAX = 60_000;

export class PuddleClient extends EventTarget {
	domain;
	/** 'closed' | 'connecting' | 'connected' */
	state = 'closed';
	/** Our own peer id, once the puddle has told us what it sees. */
	me = null;
	/** Our nick here, or null. */
	nick = null;
	/** peer id -> nick or null.  Includes us. */
	users = new Map();
	/** Why we are not connected, when that is worth showing. */
	trouble = null;

	#conn = null;
	#chan = null;
	#retry = RETRY_MIN;
	#timer = null;
	#stopped = true;
	#generation = 0;

	constructor(domain) {
		super();
		this.domain = domain;
	}

	start() {
		if (!this.#stopped) return;
		this.#stopped = false;
		this.#retry = RETRY_MIN;
		this.#dial();
	}

	stop() {
		this.#stopped = true;
		clearTimeout(this.#timer);
		this.#generation += 1;
		this.#teardown('closed');
	}

	get connected() {
		return this.state === 'connected';
	}

	knows(peer) {
		return this.users.has(peer);
	}

	nick_of(peer) {
		return this.users.get(peer) ?? null;
	}

	async #dial() {
		const generation = ++this.#generation;
		const stale = () => this.#stopped || generation !== this.#generation;

		this.#set_state('connecting', null);
		try {
			const conn = await Conn.to_domain({
				domain: this.domain,
				timeout: 20_000,
			});
			if (stale()) return conn.close();
			this.#conn = conn;

			// The id-0 channel opening is how we know the association is up;
			// a DCEP channel opened before that has nowhere to go.
			await opened(conn.dc, 20_000);
			if (stale()) return conn.close();

			const chan = conn.createDataChannel('rainboots', { protocol: PROTOCOL });
			await opened(chan, 20_000);
			if (stale()) return conn.close();
			this.#chan = chan;

			chan.addEventListener('message', ({ data }) => this.#receive(data));
			chan.addEventListener(
				'close',
				() => this.#lost('the puddle closed the channel'),
			);
			conn.addEventListener(
				'connectionstatechange',
				() => {
					if (
						conn.connectionState === 'failed' ||
						conn.connectionState === 'closed'
					) this.#lost('the connection dropped');
				},
			);

			this.#retry = RETRY_MIN;
			this.#set_state('connected', null);
		} catch (e) {
			if (stale()) return;
			this.#lost(e?.message ?? String(e));
		}
	}

	#lost(why) {
		if (this.#stopped || this.state === 'closed') return;
		this.#teardown('closed', why);
		this.#timer = setTimeout(() => this.#dial(), this.#retry);
		this.#retry = Math.min(RETRY_MAX, this.#retry * 2);
	}

	#teardown(state, why = null) {
		try {
			this.#conn?.close();
		} catch {
			// Already closed.
		}
		this.#conn = null;
		this.#chan = null;
		this.me = null;
		this.nick = null;
		this.users.clear();
		this.#set_state(state, why);
	}

	#set_state(state, trouble) {
		this.state = state;
		this.trouble = trouble;
		this.dispatchEvent(new CustomEvent('state'));
		this.dispatchEvent(new CustomEvent('roster'));
	}

	send(message) {
		if (this.#chan?.readyState !== 'open') return false;
		this.#chan.send(JSON.stringify(message));
		return true;
	}

	// Anything starting with a slash is a command, because this is a chat
	// program and that is where people's fingers go.
	say(text) {
		text = String(text ?? '');
		if (text.startsWith('/')) return this.#command(text);
		return this.send({ op: 'say', text });
	}

	#command(line) {
		const [word, ...rest] = line.slice(1).split(/\s+/);
		switch (word.toLowerCase()) {
			case 'nick': {
				const [nick, ...password] = rest;
				if (!nick || !password.length) {
					this.#notice('usage: /nick <nick> <password>');
					return true;
				}
				this.claim_nick(nick, password.join(' '));
				return true;
			}
			case 'help':
				this.#notice(
					'/nick <nick> <password> -- claim a nick, or take it back',
				);
				return true;
			default:
				this.#notice(`no such command: /${word}`);
				return true;
		}
	}

	#attempt = null;

	claim_nick(nick, password) {
		this.#attempt = { nick, password };
		return this.send({ op: 'nick', nick, password });
	}

	// The `from` we send is checked by the puddle against the fingerprint it
	// authenticated, so filling it in is not a formality -- getting it wrong is
	// how a forgery is caught.
	signal(to, candidate) {
		if (!this.me) return false;
		return this.send({ op: 'signal', from: this.me, to, candidate });
	}

	#receive(data) {
		if (typeof data != 'string') return;
		let json;
		try {
			json = JSON.parse(data);
		} catch {
			return;
		}
		if (json === null || typeof json != 'object') return;

		switch (json.op) {
			case 'welcome':
				this.me = json.you;
				this.nick = json.nick ?? null;
				this.users = new Map(
					json.users.map(({ id, nick }) => [id, nick ?? null]),
				);
				this.dispatchEvent(new CustomEvent('roster'));
				break;
			case 'join':
				this.users.set(json.id, json.nick ?? null);
				this.dispatchEvent(new CustomEvent('roster'));
				this.#notice(`${json.nick ?? short(json.id)} splashed in`);
				break;
			case 'part': {
				const who = this.users.get(json.id);
				this.users.delete(json.id);
				this.dispatchEvent(new CustomEvent('roster'));
				this.#notice(`${who ?? short(json.id)} splashed out`);
				break;
			}
			case 'nick': {
				const was = this.users.get(json.id);
				this.users.set(json.id, json.nick);
				if (json.id === this.me) this.nick = json.nick;
				this.dispatchEvent(new CustomEvent('roster'));
				this.#notice(`${was ?? short(json.id)} is now known as ${json.nick}`);
				break;
			}
			case 'nick_ok': {
				this.nick = json.nick;
				this.dispatchEvent(new CustomEvent('roster'));
				// Worth remembering only now that the puddle has accepted it.
				const attempt = this.#attempt;
				this.#attempt = null;
				if (attempt) {
					this.dispatchEvent(
						new CustomEvent('login', {
							detail: { nick: json.nick, password: attempt.password },
						}),
					);
				}
				break;
			}
			case 'nick_err':
				this.#notice(`nick refused: ${json.reason}`);
				break;
			case 'msg':
				this.dispatchEvent(new CustomEvent('msg', { detail: json }));
				break;
			case 'signal':
				this.dispatchEvent(new CustomEvent('signal', { detail: json }));
				break;
			case 'error':
				this.#notice(json.reason);
				break;
		}
	}

	#notice(text) {
		this.dispatchEvent(
			new CustomEvent('notice', { detail: { text, at: Date.now() } }),
		);
	}
}

// A peer with no nick is shown as the front of their id.  Short enough to read,
// long enough to tell two people apart, and never mistakable for a name.
export function short(peer) {
	return String(peer).slice(0, 8);
}

// Resolve when a datachannel opens; reject if it closes or errors first.
function opened(dc, ms) {
	if (dc.readyState === 'open') return Promise.resolve(dc);
	return new Promise((resolve, reject) => {
		const timer = setTimeout(
			() => reject(new Error(`'${dc.label}' never opened`)),
			ms,
		);
		const settle = (fn) => (arg) => {
			clearTimeout(timer);
			fn(arg);
		};
		dc.addEventListener('open', settle(() => resolve(dc)), { once: true });
		dc.addEventListener(
			'close',
			settle(() => reject(new Error(`'${dc.label}' closed before it opened`))),
			{ once: true },
		);
		dc.addEventListener(
			'error',
			settle(({ error }) => reject(error ?? new Error('datachannel error'))),
			{ once: true },
		);
	});
}
