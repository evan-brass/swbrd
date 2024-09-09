// HACK: Chrome is weird about sending 192.x -> 127.x which the server then response from 192.x and Chrome ignores the response.
// Shouldn't be an issue when deployed, because a server shouldn't receive requests from localhost.
const hostname = (Deno.build.os == 'darwin') ? '::ffff:127.0.0.1' : '::';
export const sock = Deno.listenDatagram({transport: 'udp', hostname, port: 3478});
export const send = new ArrayBuffer(2048);
