// Direct messages: a connection between two people that no puddle carries.
//
// The puddle's only part in a DM is passing ICE candidates back and forth, and
// it can only pass ones the sender really sent -- it checks `from` against the
// fingerprint it authenticated.  Once the candidates have been exchanged the
// two browsers hold a DTLS connection to each other whose certificates are the
// peer ids themselves, so even a puddle that lies about who is who cannot get
// between them: it can refuse to introduce you, but it cannot impersonate the
// person it introduced.
//
// DMs are keyed by peer id and nothing else.  You are one person in every
// puddle -- same certificate, same id -- so meeting someone in two puddles does
// not make two conversations, and a candidate arriving through either one
// belongs to the same connection.
//
// Relay-only by default: with iceTransportPolicy 'relay' the only address
// either end learns is a TURN server's.  "Use unrelayed" gives that up, and is
// deliberately one-sided -- revealing your own address is your call to make and
// needs nobody's agreement.

import { Conn } from 'swbrd/conn.js';
import { is_firefox } from 'swbrd/util.js';

// Whether this browser can hold up its end of a DM.
//
// `Conn.with_candidates` works by putting the real ICE credentials inside the
// candidate rather than in the SDP, which only Chrome will pair.  Firefox
// refuses, so a DM built this way can never connect there and the honest thing
// is to say so up front instead of letting both ends wait out a timeout.
//
// Not permanent: `Conn.with_candidates_dissolved` gets Firefox talking through
// a TURN server that intercepts the connectivity checks.  It needs both ends to
// agree on which mode they are using, which is a puddle protocol this does not
// have yet.
export const DM_SUPPORTED = !is_firefox;

// Long enough for someone to notice a popup and decide.
const DIAL_TIMEOUT = 45_000;
const PAIR_POLL = 3_000;

// How long candidates from someone we just turned down are ignored.
//
// Refusing is one end-of-candidates message, and it closes their Conn as soon as
// they read it -- but their ICE agent had already gathered a handful, and those
// are in flight.  Each straggler arriving after the conversation was deleted
// would look like a stranger getting in touch and raise a fresh invitation, so
// saying no once would pop a dialog per candidate.  Refusing has to mean they
// are gone for a while, not that they come back until they run out of
// candidates.
const REFUSAL_COOLDOWN = 60_000;

export class DM extends EventTarget {
	peer;
	/** 'invited' | 'dialing' | 'connected' | 'declined' | 'failed' | 'closed' */
	state = 'closed';
	/** Who started it: 'us' or 'them'. */
	origin;
	/** { mine, text, at } */
	messages = [];
	/** Whether we are currently restricting ourselves to relay candidates. */
	relayed = true;
	/** The ICE pair actually carrying this, once there is one. */
	pair = null;

	#conn = null;
	#route;
	#pending = [];
	#timer = null;
	#poll = null;

	constructor(peer, route, origin) {
		super();
		this.peer = peer;
		this.#route = route;
		this.origin = origin;
	}

	get live() {
		return this.state === 'dialing' || this.state === 'connected' ||
			this.state === 'invited';
	}

	// Someone we are already talking to sent us a candidate, or we have just
	// accepted an invitation and the buffered ones are being drained.
	take(candidate) {
		if (this.#conn) {
			this.#conn.addIceCandidate(candidate);
			return;
		}
		// Still an unanswered invitation: hold them until there is somewhere to
		// put them.  Bounded, because an unanswered popup should not be a place
		// to pour memory into.
		if (this.#pending.length < 64) this.#pending.push(candidate);
	}

	dial() {
		if (this.#conn) return;
		this.#set_state('dialing');

		const conn = Conn.with_candidates(this.peer, {
			iceTransportPolicy: this.relayed ? 'relay' : 'all',
			timeout: DIAL_TIMEOUT,
		});
		this.#conn = conn;

		// Listen on 'candidate', never 'icecandidate': Conn intercepts the
		// native event and re-dispatches it with the real ICE credentials
		// patched in, which is the whole trick that makes this work.
		conn.addEventListener('candidate', ({ candidate }) => {
			this.#route(this.peer, candidate ? candidate.toJSON() : null);
		});

		// Conn fires this when the peer ends their candidates without having
		// sent any: they are declining, not failing.
		conn.addEventListener('refused', () => this.#finish('declined'));

		conn.addEventListener('connectionstatechange', () => {
			if (conn.connectionState === 'connected') {
				clearTimeout(this.#timer);
				this.#set_state('connected');
				this.#watch_pair();
			} else if (conn.connectionState === 'failed') {
				this.#finish('failed');
			}
		});

		conn.dc.addEventListener('message', ({ data }) => this.#receive(data));

		this.#timer = setTimeout(() => {
			if (this.state !== 'connected') this.#finish('failed');
		}, DIAL_TIMEOUT + 1_000);

		for (const candidate of this.#pending.splice(0)) {
			conn.addIceCandidate(candidate);
		}
	}

	send(text) {
		text = String(text ?? '').slice(0, 2000);
		if (!text.trim()) return false;
		if (this.#conn?.dc?.readyState !== 'open') return false;
		// The id-0 channel is also Conn's signalling transport.  That is safe to
		// share: Conn only looks at messages carrying `description` or
		// `candidate`, and ignores everything else -- including this.
		this.#conn.dc.send(JSON.stringify({ op: 'dm', text, at: Date.now() }));
		this.#record({ mine: true, text, at: Date.now() });
		return true;
	}

	// Gather our own addresses too, and restart ICE so a direct pair can win.
	//
	// Unilateral on purpose: this exposes *our* address to them, and their own
	// policy is theirs to choose.
	//
	// One way, and not because it would be hard to write the other direction.
	// Tightening the policy back to 'relay' is accepted -- setConfiguration
	// succeeds and getConfiguration() reports 'relay' -- but Chrome keeps the
	// non-relay pair it has already selected, so an ICE restart changes
	// nothing and the traffic keeps flowing over the address you just tried to
	// stop revealing.  A button that quietly did nothing would be worse than no
	// button, so getting back to relay-only means closing the DM and dialling
	// it again.
	unrelay() {
		if (!this.relayed) return;
		this.relayed = false;
		this.dispatchEvent(new CustomEvent('state'));
		const conn = this.#conn;
		if (!conn || conn.connectionState === 'closed') return;
		conn.setConfiguration({ iceTransportPolicy: 'all' });
		conn.restartIce();
	}

	close() {
		this.#finish('closed');
	}

	#receive(data) {
		if (typeof data != 'string') return;
		let json;
		try {
			json = JSON.parse(data);
		} catch {
			return;
		}
		if (json?.op !== 'dm' || typeof json.text != 'string') return;
		this.#record({
			mine: false,
			text: json.text.slice(0, 2000),
			at: Number(json.at) || Date.now(),
		});
	}

	#record(message) {
		this.messages.push(message);
		if (this.messages.length > 500) this.messages.shift();
		this.dispatchEvent(new CustomEvent('message', { detail: message }));
	}

	#finish(state) {
		clearTimeout(this.#timer);
		clearInterval(this.#poll);
		this.#poll = null;
		try {
			this.#conn?.close();
		} catch {
			// Already closed.
		}
		this.#conn = null;
		this.#pending.length = 0;
		this.pair = null;
		this.#set_state(state);
	}

	#set_state(state) {
		this.state = state;
		this.dispatchEvent(new CustomEvent('state'));
	}

	// The selected pair is what the DM panel reports, and it is the only honest
	// answer to "can they see my address".
	#watch_pair() {
		const transport = this.#conn?.sctp?.transport?.iceTransport;
		if (!transport) return;
		transport.addEventListener(
			'selectedcandidatepairchange',
			() => this.#read_pair(),
		);
		// An ICE restart can settle on a new pair without always waking that
		// event, so keep a slow poll going as well.
		clearInterval(this.#poll);
		this.#poll = setInterval(() => this.#read_pair(), PAIR_POLL);
		this.#read_pair();
	}

	#read_pair() {
		const transport = this.#conn?.sctp?.transport?.iceTransport;
		const selected = transport?.getSelectedCandidatePair?.();
		const next = selected
			? { local: describe(selected.local), remote: describe(selected.remote) }
			: null;
		if (JSON.stringify(next) === JSON.stringify(this.pair)) return;
		this.pair = next;
		this.dispatchEvent(new CustomEvent('pair'));
	}
}

function describe(candidate) {
	if (!candidate) return null;
	return {
		type: candidate.type ?? 'unknown',
		address: candidate.address ?? '?',
		port: candidate.port ?? 0,
		protocol: candidate.protocol ?? '?',
	};
}

export class DirectMessages extends EventTarget {
	/** peer id -> DM */
	all = new Map();

	/** peer id -> when we will listen to them again.  See REFUSAL_COOLDOWN. */
	#refused = new Map();

	#route;

	/** `route(peer, candidate)` sends one signal through whichever puddle can reach them. */
	constructor(route) {
		super();
		this.#route = route;
	}

	get(peer) {
		return this.all.get(peer) ?? null;
	}

	// Start, or bring forward, a conversation with someone.
	open(peer) {
		if (!DM_SUPPORTED) return null;
		// Dialling somebody is as clear a change of mind as there is, so it
		// ends any cooldown we were holding them under.
		this.#refused.delete(peer);
		let dm = this.all.get(peer);
		if (dm && dm.live) return dm;
		if (!dm) dm = this.#make(peer, 'us');
		dm.dial();
		this.dispatchEvent(new CustomEvent('change'));
		return dm;
	}

	// A candidate arrived for us, through some puddle.
	incoming(from, candidate) {
		// Somebody is calling a browser that cannot answer.  Refuse it for them
		// rather than raising a popup over a connection that could never form:
		// this is the same end-of-candidates a person clicking reject sends, so
		// their Conn closes now instead of in forty-five seconds.
		if (!DM_SUPPORTED) {
			if (candidate !== null) this.#route(from, null);
			return null;
		}

		const existing = this.all.get(from);
		if (
			existing && existing.state !== 'closed' && existing.state !== 'declined'
		) {
			existing.take(candidate);
			return existing;
		}

		if (this.#cooling_off(from)) return null;

		// End of candidates from someone we are not talking to is not an
		// invitation, it is the tail of one we already dealt with.
		if (candidate === null) return null;

		const dm = this.#make(from, 'them');
		dm.take(candidate);
		this.dispatchEvent(new CustomEvent('change'));
		this.dispatchEvent(new CustomEvent('invite', { detail: dm }));
		return dm;
	}

	accept(peer) {
		if (!DM_SUPPORTED) return null;
		const dm = this.all.get(peer);
		if (!dm || dm.state !== 'invited') return null;
		dm.dial();
		this.dispatchEvent(new CustomEvent('change'));
		return dm;
	}

	// Ending our candidates without ever sending one is the refusal: their Conn
	// sees end-of-candidates with nothing applied and closes on the spot,
	// instead of sitting there until it times out.
	reject(peer) {
		const dm = this.all.get(peer);
		if (!dm) return;
		this.#route(peer, null);
		dm.close();
		this.all.delete(peer);

		const now = Date.now();
		// Drop anyone whose cooldown has run out while we were not looking, so
		// this map tracks people we are currently ignoring rather than everyone
		// we have ever ignored.
		for (const [id, until] of this.#refused) {
			if (until <= now) this.#refused.delete(id);
		}
		this.#refused.set(peer, now + REFUSAL_COOLDOWN);

		this.dispatchEvent(new CustomEvent('change'));
	}

	/** True while `peer` is still being ignored after a refusal. */
	#cooling_off(peer) {
		const until = this.#refused.get(peer);
		if (until === undefined) return false;
		if (Date.now() < until) return true;
		this.#refused.delete(peer);
		return false;
	}

	forget(peer) {
		const dm = this.all.get(peer);
		if (!dm) return;
		dm.close();
		this.all.delete(peer);
		this.dispatchEvent(new CustomEvent('change'));
	}

	#make(peer, origin) {
		const dm = new DM(peer, this.#route, origin);
		if (origin === 'them') dm.state = 'invited';
		this.all.set(peer, dm);
		for (const event of ['state', 'message', 'pair']) {
			dm.addEventListener(
				event,
				() => this.dispatchEvent(new CustomEvent('change', { detail: dm })),
			);
		}
		// Forwarded separately from 'change' so a caller can tell "something
		// about this conversation moved" from "they said something", which is
		// the difference between redrawing a list and ringing a bell.
		dm.addEventListener(
			'message',
			({ detail }) =>
				this.dispatchEvent(
					new CustomEvent('said', { detail: { dm, message: detail } }),
				),
		);
		return dm;
	}
}
