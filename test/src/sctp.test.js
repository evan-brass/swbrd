import { InitChunk, Sctp, Param } from "../../src/sctp.js";
import { assertEquals, assertInstanceOf } from '@std/assert';

const vector1 = new Uint8Array([
	19, 136, 19, 136, 0, 0, 0, 0, 48, 209,
	253, 171, 1, 0, 0, 30, 242, 239, 187, 30,
	0, 80, 0, 0, 255, 255, 255, 255, 41, 46,
	132, 194, 192, 0, 0, 4, 128, 8, 0, 6,
	130, 192, 0, 0
]);

Deno.test(function vector1_decode() {
	const test = new Sctp(vector1);

	assertEquals(test.sport, 5000);
	assertEquals(test.dport, 5000);
	assertEquals(test.vtag, 0);

	const [
		init,
		end
	] = test.chunks;
	assertInstanceOf(init, InitChunk);
	assertEquals(init.vtag, 0xf2efbb1e);
	assertEquals(init.rwnd, 5242880);
	assertEquals(init.out, 65535);
	assertEquals(init.in, 65535);
	assertEquals(init.tsn, 690914498);
	const [
		param1,
		param2,
		endp
	] = init.params;
	assertInstanceOf(param1, Param);
	assertInstanceOf(param2, Param);
	assertEquals(endp, undefined);

	assertEquals(end, undefined);

	// You can't verify the checksum until you've read the chunks (to populate the .children and thus update the .byteLength of the Sctp which otherwise doesn't have a length field)
	assertEquals(test.checksum, test.expected_checksum);
});

Deno.test(function vector1_encode() {
	debugger;
	const result = new Uint8Array(vector1.byteLength);
	const test = new Sctp(result.buffer, {
		dport: 5000,
		sport: 5000,
		vtag: 0,
	});
	const init = test.append(InitChunk, {
		flags: 0,
		vtag: 0xf2efbb1e,
		rwnd: 5242880,
		out: 65535,
		in: 65535,
		tsn: 690914498
	});

	assertInstanceOf(init, InitChunk);
	const p1 = init.append(Param, {
		type: 49152,
	});
	assertInstanceOf(p1, Param);

	const p2 = init.append(Param, {
		setByteLength: 6,
		type: 32776
	});
	assertInstanceOf(p2, Param);
	p2.setUint16(4, 33472);

	test.checksum = test.expected_checksum;

	assertEquals(result, vector1);
});
