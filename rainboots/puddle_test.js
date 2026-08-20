// Drives puddle.js the way the daemon does: one Unix connection per datachannel,
// opening with a control frame that names the peer.  Because the daemon is the
// only thing that ever writes that frame, and it fills the id in from the
// finished DTLS handshake, this test can hand the puddle any identity it likes
// -- which is exactly what is needed to check that a peer cannot claim someone
// else's.
//
//   deno test -A rainboots/puddle_test.js

import { CONTROL, decode, encode, EOR, PPID_STRING } from '../src/chan.js';

// Hand-rolled rather than jsr:@std/assert.  Nothing else in this repo has a
// JavaScript dependency, and two assertions are not worth being the first.
function assert(cond, why = 'assertion failed') {
	if (!cond) throw new Error(why);
}

function assertEquals(actual, expected) {
	const a = JSON.stringify(actual);
	const b = JSON.stringify(expected);
	if (a !== b) throw new Error(`expected ${b}\n     got ${a}`);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// The daemon's side of a channel: write the open, then speak JSON.
class Peer {
	#conn;
	#buf = new Uint8Array(0);
	#eof = false;

	static async dial(socket, id) {
		const peer = new Peer();
		peer.#conn = await Deno.connect({ path: socket, transport: 'unix' });
		const open = JSON.stringify({
			op: 'open',
			fp: 'ff'.repeat(32),
			id,
			label: 'rainboots',
			protocol: 'rainboots.v1',
			stream: 2,
			ordered: true,
			reliability: { kind: 'reliable' },
			priority: 512,
			initiator: 'peer',
		});
		await peer.#write(encode(0, CONTROL | EOR, encoder.encode(open)));
		return peer;
	}

	async #write(bytes) {
		let off = 0;
		while (off < bytes.length) {
			off += await this.#conn.write(bytes.subarray(off));
		}
	}

	send(message) {
		return this.#write(
			encode(PPID_STRING, EOR, encoder.encode(JSON.stringify(message))),
		);
	}

	async recv() {
		for (;;) {
			const frame = decode(this.#buf);
			if (frame) {
				this.#buf = this.#buf.subarray(frame.wireLength);
				if (frame.flags & CONTROL) continue;
				return JSON.parse(decoder.decode(frame.payload));
			}
			if (this.#eof) return null;
			const chunk = new Uint8Array(64 * 1024);
			const n = await this.#conn.read(chunk);
			if (n === null) {
				this.#eof = true;
				return null;
			}
			const grown = new Uint8Array(this.#buf.length + n);
			grown.set(this.#buf);
			grown.set(chunk.subarray(0, n), this.#buf.length);
			this.#buf = grown;
		}
	}

	// The next message whose op is one of `ops`, so an unrelated join or part
	// racing in cannot make a test flaky.
	async until(...ops) {
		for (;;) {
			const message = await this.recv();
			if (message === null) {
				throw new Error(`channel closed waiting for ${ops}`);
			}
			if (ops.includes(message.op)) return message;
		}
	}

	close() {
		try {
			this.#conn.close();
		} catch {
			// Already gone.
		}
	}
}

// Start a puddle and wait until it is actually listening.
//
// The socket file is removed first so that its reappearance is proof this
// process bound it.  Without that, a restart finds the killed process's socket
// still on disk -- SIGKILL does not unlink it -- and races ahead to connect to
// nothing.
async function spawn_puddle(socket, state) {
	try {
		await Deno.remove(socket);
	} catch {
		// Nothing there, which is the normal case.
	}
	const child = new Deno.Command(Deno.execPath(), {
		args: [
			'run',
			'--allow-read',
			'--allow-write',
			'--allow-net',
			new URL('./puddle.js', import.meta.url).pathname,
			'--socket',
			socket,
			'--state',
			state,
		],
		stdout: 'null',
		stderr: 'inherit',
	}).spawn();

	for (let i = 0; i < 200; i += 1) {
		try {
			await Deno.stat(socket);
			return child;
		} catch {
			await new Promise((res) => setTimeout(res, 25));
		}
	}
	throw new Error(`puddle never bound ${socket}`);
}

async function stop_puddle(child) {
	try {
		child.kill('SIGKILL');
	} catch {
		// Already dead.
	}
	await child.status;
}

// One puddle process per test, with its own socket and its own nick file.
async function with_puddle(fn) {
	const dir = await Deno.makeTempDir({ prefix: 'puddle-test-' });
	const socket = `${dir}/puddle.sock`;
	const state = `${dir}/nicks.json`;
	const child = await spawn_puddle(socket, state);
	try {
		return await fn({ socket, state });
	} finally {
		await stop_puddle(child);
		await Deno.remove(dir, { recursive: true });
	}
}

const ALICE = 'alice000000000000000000000000000000';
const BOB = 'bob00000000000000000000000000000000';
const MALLORY = 'mallory0000000000000000000000000000';

Deno.test('a peer is welcomed by the id the daemon gave us', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		const welcome = await alice.until('welcome');
		assertEquals(welcome.you, ALICE);
		assertEquals(welcome.nick, null);
		assertEquals(welcome.users, [{ id: ALICE, nick: null }]);
		alice.close();
	});
});

Deno.test('the roster fills in and empties out', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');

		const bob = await Peer.dial(socket, BOB);
		await bob.until('welcome');

		assertEquals(await alice.until('join'), {
			op: 'join',
			id: BOB,
			nick: null,
		});

		bob.close();
		assertEquals(await alice.until('part'), { op: 'part', id: BOB });
		alice.close();
	});
});

Deno.test('what one peer says, the others hear', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		const bob = await Peer.dial(socket, BOB);
		await bob.until('welcome');

		await alice.send({ op: 'say', text: 'hello puddle' });
		const heard = await bob.until('msg');
		assertEquals(heard.from, ALICE);
		assertEquals(heard.text, 'hello puddle');
		assert(typeof heard.at == 'number');

		alice.close();
		bob.close();
	});
});

Deno.test('a nick is registered once and then needs its password', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		await alice.send({ op: 'nick', nick: 'Rainy', password: 'hunter2' });
		assertEquals(await alice.until('nick_ok', 'nick_err'), {
			op: 'nick_ok',
			nick: 'Rainy',
		});
		alice.close();

		// A different peer id, the same nick, the wrong password.
		const mallory = await Peer.dial(socket, MALLORY);
		await mallory.until('welcome');
		await mallory.send({ op: 'nick', nick: 'rainy', password: 'guess' });
		const refused = await mallory.until('nick_ok', 'nick_err');
		assertEquals(refused.op, 'nick_err');

		// ...and the right one, which is the whole point of registering: the
		// nick comes back on a different certificate.
		await mallory.send({ op: 'nick', nick: 'rainy', password: 'hunter2' });
		assertEquals(await mallory.until('nick_ok', 'nick_err'), {
			op: 'nick_ok',
			nick: 'Rainy',
		});
		mallory.close();
	});
});

Deno.test('a nick nobody could type is refused', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		for (const nick of ['', 'has space', 'x'.repeat(25), 'ünïcode', 'a\nb']) {
			await alice.send({ op: 'nick', nick, password: 'hunter2' });
			assertEquals((await alice.until('nick_ok', 'nick_err')).op, 'nick_err');
		}
		alice.close();
	});
});

Deno.test('candidates are routed to the peer they are addressed to', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		const bob = await Peer.dial(socket, BOB);
		await bob.until('welcome');

		await alice.send({
			op: 'signal',
			from: ALICE,
			to: BOB,
			candidate: {
				candidate: 'candidate:1 1 udp 42 ::1 9 typ relay',
				sdpMid: 'dc',
			},
		});
		const relayed = await bob.until('signal');
		assertEquals(relayed.from, ALICE);
		assertEquals(relayed.to, BOB);
		assertEquals(
			relayed.candidate.candidate,
			'candidate:1 1 udp 42 ::1 9 typ relay',
		);
		// Whitelisted down to RTCIceCandidateInit, nothing else riding along.
		assertEquals(
			Object.keys(relayed.candidate).sort(),
			['candidate', 'sdpMLineIndex', 'sdpMid', 'usernameFragment'].sort(),
		);

		alice.close();
		bob.close();
	});
});

Deno.test('end of candidates relays as null, which is how a DM is declined', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		const bob = await Peer.dial(socket, BOB);
		await bob.until('welcome');

		await bob.send({ op: 'signal', from: BOB, to: ALICE, candidate: null });
		const relayed = await alice.until('signal');
		assertEquals(relayed.from, BOB);
		assertEquals(relayed.candidate, null);

		alice.close();
		bob.close();
	});
});

// The reason a Puddle can relay signalling for strangers without becoming a
// tool for impersonating them.
Deno.test('a candidate claiming someone else as its sender is dropped', async () => {
	await with_puddle(async ({ socket }) => {
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		const bob = await Peer.dial(socket, BOB);
		await bob.until('welcome');
		const mallory = await Peer.dial(socket, MALLORY);
		await mallory.until('welcome');

		// Mallory tries to look like Alice to Bob.
		await mallory.send({
			op: 'signal',
			from: ALICE,
			to: BOB,
			candidate: {
				candidate: 'candidate:1 1 udp 42 ::1 9 typ relay',
				sdpMid: 'dc',
			},
		});
		assertEquals((await mallory.until('error', 'signal')).op, 'error');

		// Then sends an honest one, so the test can prove Bob's channel was
		// working the whole time and the forgery is what went missing.
		await mallory.send({
			op: 'signal',
			from: MALLORY,
			to: BOB,
			candidate: {
				candidate: 'candidate:2 1 udp 42 ::1 9 typ relay',
				sdpMid: 'dc',
			},
		});
		const first = await bob.until('signal');
		assertEquals(first.from, MALLORY);
		assertEquals(
			first.candidate.candidate,
			'candidate:2 1 udp 42 ::1 9 typ relay',
		);

		alice.close();
		bob.close();
		mallory.close();
	});
});

Deno.test('several tabs are one member of the roster', async () => {
	await with_puddle(async ({ socket }) => {
		const watcher = await Peer.dial(socket, BOB);
		await watcher.until('welcome');

		const tab1 = await Peer.dial(socket, ALICE);
		await tab1.until('welcome');
		assertEquals((await watcher.until('join')).id, ALICE);

		const tab2 = await Peer.dial(socket, ALICE);
		const welcome = await tab2.until('welcome');
		// The second tab sees itself already in the room, and nobody was told
		// about a second arrival.
		assertEquals(welcome.users.filter((u) => u.id === ALICE).length, 1);

		// A message reaches both tabs.
		await watcher.send({ op: 'say', text: 'ping' });
		assertEquals((await tab1.until('msg')).text, 'ping');
		assertEquals((await tab2.until('msg')).text, 'ping');

		// Closing one tab is not leaving.
		tab1.close();
		await watcher.send({ op: 'say', text: 'still here?' });
		assertEquals((await tab2.until('msg')).text, 'still here?');

		tab2.close();
		assertEquals((await watcher.until('part')).id, ALICE);
		watcher.close();
	});
});

Deno.test('registrations survive a restart', async () => {
	const dir = await Deno.makeTempDir({ prefix: 'puddle-test-' });
	const socket = `${dir}/puddle.sock`;
	const state = `${dir}/nicks.json`;

	try {
		let child = await spawn_puddle(socket, state);
		const alice = await Peer.dial(socket, ALICE);
		await alice.until('welcome');
		await alice.send({
			op: 'nick',
			nick: 'puddleduck',
			password: 'correct horse',
		});
		assertEquals((await alice.until('nick_ok', 'nick_err')).op, 'nick_ok');
		alice.close();
		// The write is debounced, so give the rename a moment to land.
		await new Promise((res) => setTimeout(res, 250));
		await stop_puddle(child);

		child = await spawn_puddle(socket, state);
		const bob = await Peer.dial(socket, BOB);
		await bob.until('welcome');
		await bob.send({ op: 'nick', nick: 'puddleduck', password: 'wrong' });
		assertEquals((await bob.until('nick_ok', 'nick_err')).op, 'nick_err');
		await bob.send({
			op: 'nick',
			nick: 'puddleduck',
			password: 'correct horse',
		});
		assertEquals((await bob.until('nick_ok', 'nick_err')).op, 'nick_ok');
		bob.close();
		await stop_puddle(child);
	} finally {
		await Deno.remove(dir, { recursive: true });
	}
});
