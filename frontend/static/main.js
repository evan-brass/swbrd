import { Addr, Id, make_id, Conn, Sig } from 'swbrd';
// import { buftobinstr, btoa_url } from 'swbrd/b64url.js'

const t = new WebSocket(`ws${location.protocol == 'https:' ? 's' : ''}://${location.host}/bind`);
['open', 'message', 'error', 'close'].forEach(ev => t.addEventListener(ev, console.log));

// const test = new WebSocket('wss://local.evan-brass.net/broadcast');
// test.addEventListener('message', ({ data }) => console.log(JSON.parse(data)));
// [
// 	'open',
// 	// 'message',
// 	'error',
// 	'close'
// ].forEach(ev => test.addEventListener(ev, console.log));

const all_events = [
	'connectionstatechange',
	'datachannel',
	'icecandidate',
	'icecandidateerror',
	'iceconnectionstatechange',
	'icegatheringstatechange',
	'negotiationneeded',
	'signalingstatechange',
	'track'
];

// const a = new Conn();
// all_events.forEach(ev => a.addEventListener(ev, console.log));
// console.log(await a.local);
// a.remote = new Sig({
// 	id: new Id('GjSxeQsUF1m1ftpcw-Ug82EhHitF_sKMeL39FESeEa0'),
// 	candidates: [{address: '255.255.255.255', port: 3478}]
// });
// console.log(a.remote);

const certa = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
const certb = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
const addra = new Addr(`swbrd://${await make_id(certa)}@local.evan-brass.net:443`);
const addrb = new Addr(`swbrd://${await make_id(certb)}@local.evan-brass.net:443`);

// Example: Bind an address at a TURN Hub (a Switchboard or swbrd:)
// const listener = new Addr(`swbrd://local.evan-brass.net`).bind(
// 	{ certificates: [certa] }, // RTCPeerConnection Configuration
// 	() => true // Filtering function for which connections to accept and which to ignore.
// );
// console.log('my addr:', listener.addr);
// for await (const conn of listener) {
// 	// TODO: Do something with the connections.
// 	console.log(conn)
// }

console.log(addra, addrb);
const conna = addrb.connect({ certificates: [certa] });
const connb = addra.connect({ certificates: [certb] });
all_events.forEach(ev => {
	conna.addEventListener(ev, console.log.bind(console, 'a'))
	connb.addEventListener(ev, console.log.bind(console, 'b'))
});
await Promise.race([conna.connected, connb.connected]);
console.log('connected!');

// const addr = new Addr('swbrd://local.evan-brass.net');
// const c = addr.connect();
// all_events.forEach(ev => c.addEventListener(ev, console.log));
// await c.connected;
// console.log('c connected');

// const cert = await RTCPeerConnection.generateCertificate({name:'ECDSA', namedCurve:'P-256'});
// console.log(await make_id(cert));
// console.log(new Addr('udp:local.evan-brass.net:4666'));


// const addr = new Addr(`swbd://local.evan-brass.net`);
// const c = await addr.connect();
// console.log(c);
// c.addEventListener('connectionstatechange', () => console.log(c.connectionState));

// const a = new Addr(`swbrd://local.evan-brass.net`).connect();
// const b = new EventTarget();
// const a = new Conn();
// const b = new Conn();
// all_events.forEach(ev => a.addEventListener(ev, e => console.log('a', e), b.addEventListener(ev, e => console.log('b', e))));
// console.log(a);
// console.log(b);
// const [a_loc, b_loc] = await Promise.all([a.local, b.local]);
// console.log('a', a_loc);
// console.log('b', b_loc);
// b.remote = a_loc;
// a.remote = b_loc;
// await a.connected;
// console.log('a connected');
