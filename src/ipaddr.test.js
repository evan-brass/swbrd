import { parse_ipaddr, Ip4, Ip6 } from "../../src/ipaddr.js";
import { assertEquals } from 'jsr:@std/assert';

const loopback4 = new Ip4(127, 0, 0, 1);
const loopback4m = new Ip6(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1);
const loopback6 = new Ip6(0, 0, 0, 0, 0, 0, 0, 1);

Deno.test(function loopbacks() {
	// IPv4 Loopback
	assertEquals(parse_ipaddr('127.0.0.1'), loopback4);
	assertEquals(parse_ipaddr('::ffff:127.0.0.1'), loopback4m);
	assertEquals(parse_ipaddr('::ffff:7f00:0001'), loopback4m);

	// IPv6 Loopback
	assertEquals(parse_ipaddr('::1'), loopback6);
	assertEquals(parse_ipaddr('::0.0.0.1'), loopback6);
});

Deno.test(function shortened() {
	assertEquals(parse_ipaddr('2001:0db8:0000:0000:0000:8a2e:0370:7334'), new Ip6(0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334));
	assertEquals(parse_ipaddr('2001:0db8::8a2e:0370:7334'), new Ip6(0x2001, 0x0db8, 0, 0, 0, 0x8a2e, 0x0370, 0x7334));
});

Deno.test(function map_canon() {
	assertEquals(loopback4.mapped(), loopback4m);
	assertEquals(loopback4.canonical(), loopback4);
	assertEquals(loopback4m.canonical(), loopback4);
	assertEquals(loopback4m.mapped(), loopback4m);
});
