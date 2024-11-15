import { assertEquals } from 'jsr:@std/assert';
import { Wire } from "../../src/wire.js";

Deno.test(function maxByteLengths() {
	const t1 = new ArrayBuffer(40, {maxByteLength: 100});

	// Even though a byteLength is specified here, Wire will unset it because byteOffset + byteLength == buffer.byteLength.
	const w1 = new Wire(t1, { byteOffset: 10, byteLength: 30 });
	assertEquals(w1.byteOffset, 10);
	assertEquals(w1.maxByteLength, 90);

	const w2 = new Wire(t1, { byteOffset: 20, byteLength: 10 });
	assertEquals(w2.byteOffset, 20);
	assertEquals(w2.maxByteLength, 10);

	const w3 = new Wire(new Uint8Array(t1, 5));
	assertEquals(w3.byteOffset, 5);
	assertEquals(w3.maxByteLength, 95);

	// Check to make sure that the maxByteLength's don't shrink after resize
	t1.resize(60);
	assertEquals(w1.maxByteLength, 90);
	assertEquals(w2.maxByteLength, 10);
	assertEquals(w3.maxByteLength, 95);

	// Check the maxByteLength of children
	const child1 = new Wire(t1, { byteOffset: 20 });
	const child2 = new Wire(t1, { byteOffset: 30 });
	const parent = new Wire(t1, { children: [child1, child2] });
	child1.parent = child2.parent = parent;

	assertEquals(child1.byteLength, 0);
	assertEquals(child2.byteLength, 0);
	assertEquals(parent.byteLength, 30);

	assertEquals(parent.maxByteLength, 100);
	assertEquals(child1.maxByteLength, 10);
	assertEquals(child2.maxByteLength, 70);

	// Use child byteLength setter to resize the buffer
	assertEquals(t1.byteLength, 60);
	child2.byteLength = 40;
	assertEquals(t1.byteLength, 70);

	// Replace child1 with a new wire
	const child1_b = new Wire(child1);
	assertEquals(child1.parent, null);
	assertEquals(parent.children[0], child1_b);
	assertEquals(child1_b.parent, parent);
	assertEquals(child1_b.maxByteLength, 10);
	assertEquals(child1_b.byteOffset, 20);
});
