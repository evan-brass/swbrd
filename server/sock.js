import { Ip6 } from '../src/ipaddr.js';

// Chrome is weird about sending 192.x -> 127.x (but the server then responds from 192.x and Chrome ignores the response) so if you want to run this on your local machine, you likely need to bind to 127.0.0.1:3478 which `deno task dev` will do for you.
export const sock = Deno.listenDatagram({transport: 'udp', hostname: '::', port: 3478});
export const send = new ArrayBuffer(2048);
export const broadcast = new Ip6(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff);
