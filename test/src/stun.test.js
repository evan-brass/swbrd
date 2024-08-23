import { assertEquals } from '@std/assert';
import { Stun, MAGIC_COOKIE, TextAttr, U32Attr, U64Attr, Sha1Integrity, FingerprintAttr } from "../../src/stun.js";
import { encoder } from '../../src/util.js';

// RFC 5769
const vector1 = new Uint8Array([
	0x00, 0x01, 0x00, 0x58,
	0x21, 0x12, 0xa4, 0x42,
	0xb7, 0xe7, 0xa7, 0x01,
	0xbc, 0x34, 0xd6, 0x86,
	0xfa, 0x87, 0xdf, 0xae,
	0x80, 0x22, 0x00, 0x10,
	0x53, 0x54, 0x55, 0x4e,
	0x20, 0x74, 0x65, 0x73,
	0x74, 0x20, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74,
	0x00, 0x24, 0x00, 0x04,
	0x6e, 0x00, 0x01, 0xff,
	0x80, 0x29, 0x00, 0x08,
	0x93, 0x2f, 0xf9, 0xb1,
	0x51, 0x26, 0x3b, 0x36,
	0x00, 0x06, 0x00, 0x09,
	0x65, 0x76, 0x74, 0x6a,
	0x3a, 0x68, 0x36, 0x76,
	0x59, 0x20, 0x20, 0x20, // Weirdly, this is padded using spaces instead of zeros?
	0x00, 0x08, 0x00, 0x14,
	0x9a, 0xea, 0xa7, 0x0c,
	0xbf, 0xd8, 0xcb, 0x56,
	0x78, 0x1e, 0xf2, 0xb5,
	0xb2, 0xd3, 0xf2, 0x49,
	0xc1, 0xb5, 0x71, 0xa2,
	0x80, 0x28, 0x00, 0x04,
	0xe5, 0x7a, 0x3b, 0xcf,
]);
const vector1_key = await crypto.subtle.importKey('raw', encoder.encode('VOkJxbRl1RmTxUk/WvJxBt'), { name: 'HMAC', hash: 'SHA-1' }, true, ['sign', 'verify']);

Deno.test(async function vector1_decode() {
	const test = new Stun(vector1);
	assertEquals(test.class, 'request');
	assertEquals(test.method, 'binding');
	assertEquals(test.cookie, MAGIC_COOKIE);
	const [
		software,
		priority,
		controlled,
		username,
		integrity,
		fingerprint,
		end
	] = test.attrs;
	assertEquals(software?.type, 'software');
	assertEquals(software.value, 'STUN test client');
	assertEquals(priority?.type, 'priority');
	assertEquals(priority.value, 0x6e0001ff);
	assertEquals(controlled?.type, 'ice controlled');
	assertEquals(controlled.value, 0x932ff9b151263b36n);
	assertEquals(username?.type, 'username');
	assertEquals(username.value, 'evtj:h6vY');
	assertEquals(integrity?.type, 'integrity');
	assertEquals(await integrity.verify(vector1_key), true);
	assertEquals(fingerprint?.type, 'fingerprint');
	assertEquals(fingerprint.actual, 0xe57a3bcf);
	assertEquals(fingerprint.expected(), fingerprint.actual);
	assertEquals(end, undefined);
});

Deno.test(async function vector1_encode() {
	const buffer = new ArrayBuffer(0, {maxByteLength: vector1.byteLength});
	crypto.getRandomValues(new Uint8Array(buffer));

	const test = new Stun(buffer, {
		setByteLength: Stun.minByteLength,
		class: 'request',
		method: 'binding',
		cookie: MAGIC_COOKIE,
	});
	test.txid.set([
		0xb7, 0xe7, 0xa7, 0x01,
		0xbc, 0x34, 0xd6, 0x86,
		0xfa, 0x87, 0xdf, 0xae
	]);
	const software = 'STUN test client';
	test.append(TextAttr, {
		setByteLength: TextAttr.minByteLength + software.length,
		type: 'software',
		value: software
	});
	assertEquals(test.length, 20);
	test.append(U32Attr, {
		type: 'priority',
		value: 0x6e0001ff
	});
	assertEquals(test.length, 28);
	test.append(U64Attr, {
		type: 'ice controlled',
		value: 0x932ff9b151263b36n
	});
	assertEquals(test.length, 40);
	const username = 'evtj:h6vY';
	const username_attr = test.append(TextAttr, {
		setByteLength: TextAttr.minByteLength + username.length,
		type: 'username',
		value: username
	});

	// Replace the padding with spaces:
	new Uint8Array(buffer, username_attr.byteOffset + 4 + username.length, 3).fill(0x20);

	assertEquals(test.length, 56);
	const integrity = test.append(Sha1Integrity, {
		type: 'integrity'
	});
	assertEquals(test.length, 80);
	await integrity.sign(vector1_key);
	const fingerprint = test.append(FingerprintAttr, {
		type: 'fingerprint'
	});
	assertEquals(test.length, 88);
	fingerprint.actual = fingerprint.expected();

	assertEquals(new Uint8Array(buffer), vector1);
})
