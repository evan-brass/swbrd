#!/usr/bin/env -S deno run
// Check that src/chan.js puts the same bytes on the wire as crates/chan does.
//
// The vectors below are the ones asserted in `chan::interop::wire_vectors`; if
// the two files ever disagree about the frame layout, one of these fails.

import { CONTROL, decode, encode, EOR, UNORDERED } from '../src/chan.js';

const te = new TextEncoder();
const cases = [
	['string message', 51, EOR, te.encode('hi'), [0, 0, 0, 2, 0, 0, 0, 51, 0, 1, 0, 0, 104, 105]],
	['unordered binary', 53, EOR | UNORDERED, Uint8Array.of(0xde, 0xad), [
		0, 0, 0, 2, 0, 0, 0, 53, 0, 3, 0, 0, 0xde, 0xad,
	]],
	['control', 0, CONTROL | EOR, te.encode('{}'), [
		0, 0, 0, 2, 0, 0, 0, 0, 0x80, 1, 0, 0, 123, 125,
	]],
	['empty binary', 57, EOR, new Uint8Array(0), [0, 0, 0, 0, 0, 0, 0, 57, 0, 1, 0, 0]],
];

let failed = 0;
for (const [name, ppid, flags, payload, expected] of cases) {
	const got = Array.from(encode(ppid, flags, payload));
	if (JSON.stringify(got) !== JSON.stringify(expected)) {
		console.error(`FAIL ${name}\n  want ${expected}\n  got  ${got}`);
		failed++;
		continue;
	}
	// And it survives the round trip back through decode.
	const back = decode(new Uint8Array(expected));
	if (!back || back.ppid !== ppid || back.flags !== flags) {
		console.error(`FAIL ${name} (decode)`);
		failed++;
		continue;
	}
	console.log(`ok   ${name}`);
}

// A frame split anywhere must read as "not yet", never as corrupt.
const whole = encode(51, EOR, te.encode('0123456789'));
for (let cut = 0; cut < whole.length; cut++) {
	if (decode(whole.subarray(0, cut)) !== null) {
		console.error(`FAIL partial frame at ${cut} decoded as complete`);
		failed++;
	}
}
console.log('ok   partial frames are incomplete, not invalid');

Deno.exit(failed ? 1 : 0);
