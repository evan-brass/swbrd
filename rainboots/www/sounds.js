// Sound effects, synthesized rather than shipped.
//
// Not one audio file: Rainboots precaches itself and has to work offline, so
// every asset is a thing to cache, version and get wrong.  These are a couple of
// oscillators and an envelope apiece, which costs nothing and happens to be
// exactly the palette a chat client from 1997 had.
//
// Everything is deliberately short and quiet.  A notification sound you notice
// twice is a notification sound you turn off.

const VOLUME = 0.05;

let ctx = null;
let enabled = true;

export function set_enabled(on) {
	enabled = Boolean(on);
}

// A page may not make noise before the user has interacted with it, so the
// context is built on the first gesture rather than at load.  Until then every
// sound here is silently skipped, which is the correct behaviour rather than a
// failure.
function wake() {
	try {
		ctx ??= new AudioContext();
	} catch {
		return;
	}
	if (ctx.state === 'suspended') ctx.resume().catch(() => {});
}

addEventListener('pointerdown', wake, { capture: true });
addEventListener('keydown', wake, { capture: true });

function ready() {
	return enabled && ctx?.state === 'running' ? ctx : null;
}

// One note: a square wave through a fast attack and an exponential tail.  Square
// rather than sine because this is a chat client with a monospace font.
function note(at, hz, { length = 0.09, gain = VOLUME, type = 'square' } = {}) {
	const osc = ctx.createOscillator();
	const env = ctx.createGain();
	osc.type = type;
	osc.frequency.setValueAtTime(hz, at);
	env.gain.setValueAtTime(0.0001, at);
	env.gain.linearRampToValueAtTime(gain, at + 0.006);
	env.gain.exponentialRampToValueAtTime(0.0001, at + length);
	osc.connect(env).connect(ctx.destination);
	osc.start(at);
	osc.stop(at + length + 0.02);
}

function phrase(notes, options) {
	if (!ready()) return;
	const now = ctx.currentTime + 0.01;
	for (const [step, hz] of notes) note(now + step, hz, options);
}

export const sounds = {
	/** Somebody said something in a puddle you were not looking at. */
	message: () => phrase([[0, 660]], { length: 0.07, gain: VOLUME * 0.8 }),

	/** The same, but in a DM: two notes, so you can tell without looking. */
	dm: () => phrase([[0, 660], [0.075, 990]], { length: 0.07 }),

	/** Somebody wants to talk to you privately.  The only one that carries. */
	invite: () => phrase([[0, 523], [0.11, 659], [0.22, 784]], { length: 0.11 }),

	/** They said no.  Falling, because everything else here rises. */
	declined: () =>
		phrase([[0, 494], [0.09, 370]], {
			length: 0.1,
			type: 'triangle',
		}),
};
