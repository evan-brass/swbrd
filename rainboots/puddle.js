#!/usr/bin/env -S deno run --allow-read --allow-write --allow-net
// Puddle: the back end of Rainboots.
//
//   deno run --allow-read --allow-write --allow-net puddle.js --socket /run/swbrd/ext/puddle.sock
//
// (--allow-net is what Deno 2 wants for a Unix listener; nothing here touches
// the network, and the systemd unit runs with PrivateNetwork=yes to prove it.)
//
// A switchboard extension, so the shape is the same as extensions/echo.js: the
// daemon dials this socket once per datachannel whose DCEP protocol the
// directory maps here, and the first frame it writes names the peer.  That name
// -- the base36 rendering of the certificate fingerprint from the finished DTLS
// handshake -- is the only identity in this system, and the only one worth
// trusting.  Everything else, nicks included, is decoration this process hands
// out and could just as easily lie about.
//
// What a Puddle does:
//
//   - keeps a roster of who is here and broadcasts what they say;
//   - lets people claim a nick with a password, IRC-style, so the same name can
//     be picked up from another browser or after a certificate rotation;
//   - relays ICE candidates between peers so they can build a direct DM, and
//     drops any candidate whose claimed `from` is not the fingerprint we
//     authenticated.  That check is the whole reason this can be an open relay
//     without becoming a spoofing tool.
//
// What a Puddle deliberately does not do: keep scrollback.  A server with no
// history has none to hand over.

import { Channel } from '../src/chan.js';

// ---------------------------------------------------------------- parameters

const args = parse_args(Deno.args);
const SOCKET = args.socket ?? '/run/swbrd/ext/puddle.sock';
const STATE = args.state ?? '/var/lib/swbrd/puddle/nicks.json';

const PROTOCOL = 'rainboots.v1';

// Everything below is attacker controlled, so all of it is bounded.
const MAX_TEXT = 2000;
const MAX_CANDIDATE = 512;
const MAX_FRAME = 8 * 1024;
// Tabs, mostly.  Also the cap on how much fan-out one peer id can buy.
const MAX_SESSIONS_PER_PEER = 8;
// A slow reader stops being served rather than being buffered without bound.
const MAX_QUEUED = 256;
// Token bucket: a burst is fine, a sustained flood is not.
const BUCKET_SIZE = 30;
const BUCKET_REFILL_PER_SEC = 5;

const NICK_RE = /^[a-z0-9_\[\]\\^{}|`-]{1,24}$/i;
const PBKDF2_ITERATIONS = 210_000;

// ---------------------------------------------------------------- nick store

// nick (lowercased) -> { nick, salt, hash, iterations, created }
//
// Registration is permanent and independent of who is currently online: that is
// the point of the password.  Which peer id currently *holds* a nick lives in
// memory only, in `holders` below.
const registry = new Map();

async function load_registry() {
	let text;
	try {
		text = await Deno.readTextFile(STATE);
	} catch (e) {
		if (e instanceof Deno.errors.NotFound) return;
		throw e;
	}
	for (const record of JSON.parse(text)) {
		registry.set(record.nick.toLowerCase(), record);
	}
	console.log(`loaded ${registry.size} nicks from ${STATE}`);
}

let saving = null;
let save_again = false;

// Write a temporary file and rename it over the real one, so a crash mid-write
// leaves the previous registry rather than half of this one.  Calls that arrive
// while a save is in flight collapse into one follow-up save.
function save_registry() {
	if (saving) {
		save_again = true;
		return saving;
	}
	saving = (async () => {
		do {
			save_again = false;
			const body = JSON.stringify(Array.from(registry.values()), null, '\t');
			const tmp = `${STATE}.tmp`;
			try {
				await Deno.mkdir(dirname(STATE), { recursive: true });
				await Deno.writeTextFile(tmp, body);
				await Deno.rename(tmp, STATE);
			} catch (e) {
				console.error('could not persist nicks:', e.message ?? e);
				return;
			}
		} while (save_again);
	})().finally(() => saving = null);
	return saving;
}

function dirname(path) {
	const at = path.lastIndexOf('/');
	return at <= 0 ? '/' : path.slice(0, at);
}

async function derive(password, salt, iterations) {
	const key = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(password),
		'PBKDF2',
		false,
		['deriveBits'],
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
		key,
		256,
	);
	return new Uint8Array(bits);
}

// Length is not secret; the bytes are.
function same_bytes(a, b) {
	if (a.length != b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
	return diff === 0;
}

const b64 = {
	encode: (bytes) => btoa(String.fromCharCode(...bytes)),
	decode: (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0)),
};

// ------------------------------------------------------------------- roster

// peer id -> Set<Session>.  One person with three tabs is one member of the
// roster with three sessions, so joins and parts fire on the first and last.
const peers = new Map();
// peer id -> nick, for whoever currently holds one.
const nicks = new Map();
// nick (lowercased) -> peer id, the reverse of `nicks`.
const holders = new Map();

function roster() {
	return Array.from(
		peers.keys(),
		(id) => ({ id, nick: nicks.get(id) ?? null }),
	);
}

function broadcast(message, { except = null } = {}) {
	for (const [id, sessions] of peers) {
		if (id === except) continue;
		for (const session of sessions) session.send(message);
	}
}

function deliver(id, message) {
	const sessions = peers.get(id);
	if (!sessions) return false;
	for (const session of sessions) session.send(message);
	return true;
}

// -------------------------------------------------------------------- session

let next_session = 1;

class Session {
	id;
	chan;
	tag;
	#queue = Promise.resolve();
	#queued = 0;
	#closed = false;
	#tokens = BUCKET_SIZE;
	#refilled = performance.now();

	constructor(chan) {
		this.chan = chan;
		this.id = chan.open.id;
		this.tag = `${this.id.slice(0, 8)}#${next_session++}`;
	}

	// Sends are queued rather than awaited by the caller: a broadcast must not
	// be held up by whichever member of the room is reading slowest.  The queue
	// is bounded, so a peer that never reads is dropped instead of being
	// buffered until this process runs out of memory.
	send(message) {
		if (this.#closed) return;
		if (this.#queued >= MAX_QUEUED) {
			console.warn(`${this.tag}: not keeping up, dropping`);
			this.close();
			return;
		}
		this.#queued += 1;
		this.#queue = this.#queue
			.then(() =>
				this.#closed ? undefined : this.chan.send(JSON.stringify(message))
			)
			.catch(() => this.close())
			.finally(() => this.#queued -= 1);
	}

	// True if this session may spend one message's worth of budget.
	allow() {
		const now = performance.now();
		this.#tokens = Math.min(
			BUCKET_SIZE,
			this.#tokens + (now - this.#refilled) / 1000 * BUCKET_REFILL_PER_SEC,
		);
		this.#refilled = now;
		if (this.#tokens < 1) return false;
		this.#tokens -= 1;
		return true;
	}

	close() {
		if (this.#closed) return;
		this.#closed = true;
		this.chan.close();
	}
}

// --------------------------------------------------------------------- serve

async function serve(conn) {
	const chan = await Channel.accept(conn);
	if (chan.open.protocol !== PROTOCOL) {
		// The directory should never route anything else here, but an extension
		// owns its own notion of what it serves.
		await chan.reject(`this socket serves ${PROTOCOL}`);
		return;
	}

	const session = new Session(chan);
	const { id } = session;

	let sessions = peers.get(id);
	if (sessions && sessions.size >= MAX_SESSIONS_PER_PEER) {
		await chan.reject('too many connections for this peer id');
		return;
	}

	const fresh = !sessions;
	if (fresh) peers.set(id, sessions = new Set());
	sessions.add(session);
	console.log(`${session.tag}: joined (${peers.size} here)`);

	session.send({
		op: 'welcome',
		you: id,
		nick: nicks.get(id) ?? null,
		users: roster(),
	});
	if (fresh) {
		broadcast({ op: 'join', id, nick: nicks.get(id) ?? null }, { except: id });
	}

	try {
		for await (const msg of chan) {
			if (msg.text == null) continue; // Binary is not part of this protocol.
			if (msg.data.length > MAX_FRAME) {
				session.send({ op: 'error', reason: 'message too large' });
				continue;
			}
			if (!session.allow()) {
				session.send({ op: 'error', reason: 'slow down' });
				continue;
			}
			let json;
			try {
				json = JSON.parse(msg.text);
			} catch {
				session.send({ op: 'error', reason: 'not json' });
				continue;
			}
			await handle(session, json);
		}
	} finally {
		session.close();
		sessions.delete(session);
		if (!sessions.size) {
			peers.delete(id);
			const nick = nicks.get(id);
			if (nick !== undefined) {
				nicks.delete(id);
				holders.delete(nick.toLowerCase());
			}
			broadcast({ op: 'part', id });
			console.log(`${session.tag}: left (${peers.size} here)`);
		}
	}
}

async function handle(session, json) {
	if (json === null || typeof json != 'object') return;
	switch (json.op) {
		case 'nick':
			return await claim_nick(session, json);
		case 'say':
			return say(session, json);
		case 'signal':
			return signal(session, json);
		default:
			session.send({ op: 'error', reason: `unknown op ${String(json.op)}` });
	}
}

async function claim_nick(session, { nick, password }) {
	if (typeof nick != 'string' || !NICK_RE.test(nick)) {
		return session.send({
			op: 'nick_err',
			reason: 'that is not a usable nick',
		});
	}
	if (
		typeof password != 'string' || password.length < 1 || password.length > 256
	) {
		return session.send({ op: 'nick_err', reason: 'a nick needs a password' });
	}

	const key = nick.toLowerCase();
	const held_by = holders.get(key);
	if (held_by !== undefined && held_by !== session.id) {
		return session.send({
			op: 'nick_err',
			reason: 'someone else is using that nick',
		});
	}

	let record = registry.get(key);
	if (record) {
		const salt = b64.decode(record.salt);
		const derived = await derive(password, salt, record.iterations);
		if (!same_bytes(derived, b64.decode(record.hash))) {
			console.log(`${session.tag}: bad password for ${record.nick}`);
			return session.send({ op: 'nick_err', reason: 'wrong password' });
		}
	} else {
		const salt = crypto.getRandomValues(new Uint8Array(16));
		const hash = await derive(password, salt, PBKDF2_ITERATIONS);
		record = {
			nick,
			salt: b64.encode(salt),
			hash: b64.encode(hash),
			iterations: PBKDF2_ITERATIONS,
			created: new Date().toISOString(),
		};
		registry.set(key, record);
		save_registry();
		console.log(`${session.tag}: registered ${nick}`);
	}

	// Give up whatever we were called before.
	const previous = nicks.get(session.id);
	if (previous !== undefined) holders.delete(previous.toLowerCase());
	nicks.set(session.id, record.nick);
	holders.set(key, session.id);

	session.send({ op: 'nick_ok', nick: record.nick });
	broadcast({ op: 'nick', id: session.id, nick: record.nick });
}

function say(session, { text }) {
	if (typeof text != 'string') return;
	text = text.slice(0, MAX_TEXT);
	if (!text.trim()) return;
	broadcast({
		op: 'msg',
		from: session.id,
		nick: nicks.get(session.id) ?? null,
		text,
		at: Date.now(),
	});
}

// The one security-relevant path in this file.
//
// `from` is carried in the message rather than filled in by us on purpose: it
// makes the check explicit and testable from the browser side.  A peer that
// claims to be someone else gets its message dropped, not rewritten -- rewriting
// would quietly turn a forgery attempt into a valid message from the forger.
function signal(session, { from, to, candidate }) {
	if (from !== session.id) {
		console.warn(
			`${session.tag}: dropped a signal claiming to be from ${
				String(from).slice(0, 16)
			}`,
		);
		return session.send({ op: 'error', reason: 'that is not your peer id' });
	}
	if (typeof to != 'string' || !to || to === session.id) return;

	const clean = clean_candidate(candidate);
	if (clean === undefined) return;

	// Silence on an unknown `to`: whether a given peer id is online is not
	// something an arbitrary peer should be able to probe for.
	deliver(to, { op: 'signal', from: session.id, to, candidate: clean });
}

// Reduce whatever arrived to the four fields RTCIceCandidateInit actually has,
// so nothing else can ride along to the other peer.  `null` is meaningful: it
// is end-of-candidates, which is how a DM is declined.  `undefined` means the
// message was malformed and should be dropped.
function clean_candidate(candidate) {
	if (candidate === null) return null;
	if (candidate === undefined || typeof candidate != 'object') return undefined;
	if (
		typeof candidate.candidate != 'string' ||
		candidate.candidate.length > MAX_CANDIDATE
	) {
		return undefined;
	}
	return {
		candidate: candidate.candidate,
		sdpMid: typeof candidate.sdpMid == 'string' ? candidate.sdpMid : null,
		sdpMLineIndex: Number.isInteger(candidate.sdpMLineIndex)
			? candidate.sdpMLineIndex
			: null,
		usernameFragment: typeof candidate.usernameFragment == 'string'
			? candidate.usernameFragment.slice(0, 256)
			: null,
	};
}

// ---------------------------------------------------------------------- main

function parse_args(argv) {
	const out = {};
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === '--socket' || arg === '-s') out.socket = argv[++i];
		else if (arg === '--state') out.state = argv[++i];
		else if (!arg.startsWith('-')) out.socket ??= arg;
		else if (arg === '--help' || arg === '-h') {
			console.log('usage: puddle.js [--socket PATH] [--state PATH]');
			Deno.exit(0);
		}
	}
	return out;
}

await load_registry();

// A stale socket from a previous run would make bind fail.
try {
	Deno.removeSync(SOCKET);
} catch {
	// Nothing there to clean up.
}

const listener = Deno.listen({ path: SOCKET, transport: 'unix' });
console.log(`puddle listening on ${SOCKET}, serving ${PROTOCOL}`);

for await (const conn of listener) {
	serve(conn).catch((e) => console.error('channel failed:', e.message ?? e));
}
