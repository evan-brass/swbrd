export const sock = Deno.listenDatagram({ transport: 'udp', hostname: '::', port: 3478 });
export const send = new ArrayBuffer(40, {maxByteLength: 2048});
