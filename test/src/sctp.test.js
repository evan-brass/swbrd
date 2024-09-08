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
	assertEquals(init.num_in, 65535);
	assertEquals(init.num_out, 65535);
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
});
