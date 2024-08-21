import { parse_ipaddr } from "../../src/ipaddr.js";
import { assertEquals } from '@std/assert/mod.ts';

Deno.test(function loopbacks() {
	// IPv4 Loopback
	assertEquals(parse_ipaddr('127.0.0.1'), new Uint8Array([127, 0, 0, 1]));
	assertEquals(parse_ipaddr('::ffff:127.0.0.1'), new Uint8Array([127, 0, 0, 1]));
	assertEquals(parse_ipaddr('::ffff:7f00:0001'), new Uint8Array([127, 0, 0, 1]));

	// IPv4 Loopback - mapped
	assertEquals(parse_ipaddr('127.0.0.1', true), new Uint16Array([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]));
	assertEquals(parse_ipaddr('::ffff:127.0.0.1', true), new Uint16Array([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]));
	assertEquals(parse_ipaddr('::ffff:7f00:0001', true), new Uint16Array([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]));

	// IPv6 Loopback
	assertEquals(parse_ipaddr('::1'), new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]));
	assertEquals(parse_ipaddr('::0.0.0.1'), new Uint16Array([0, 0, 0, 0, 0, 0, 0, 1]));
});

Deno.test(function shortened() {
	assertEquals(parse_ipaddr('2001:0db8:0000:0000:0000:8a2e:0370:7334'), new Uint16Array([0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334]))
	assertEquals(parse_ipaddr('2001:0db8::8a2e:0370:7334'), new Uint16Array([0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334]))
});
