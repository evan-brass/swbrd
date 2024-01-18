import { Addr, Id, make_id, Conn, Sig } from 'swbrd';
// import { buftobinstr, btoa_url } from 'swbrd/b64url.js'

// const t = new WebSocket(`ws${location.protocol == 'https:' ? 's' : ''}://${location.host}/bind`);
// ['open', 'message', 'error', 'close'].forEach(ev => t.addEventListener(ev, console.log));

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
const all_events_dc = ['bufferedamountlow', 'close', 'closing', 'error', 'message', 'open'];

// const a = new Conn();
// all_events.forEach(ev => a.addEventListener(ev, console.log));
// console.log(await a.local);
// a.remote = new Sig({
// 	id: new Id('GjSxeQsUF1m1ftpcw-Ug82EhHitF_sKMeL39FESeEa0'),
// 	candidates: [{address: '255.255.255.255', port: 3478}]
// });
// console.log(a.remote);


// -- SIMULTANEOUS USING SIG MSGS --
// const a = new Conn();
// const b = new Conn();
// all_events.map(e => [[a, e], [b, e]]).flat(1)
// 	.forEach(([c, e]) => c.addEventListener(e, console.log));

// const [sa, sb] = await Promise.all([a.local, b.local]);
// [sa, sb].forEach(console.log);
// a.remote = sb;
// b.remote = sa;


// -- SIMULTANEOUS USING BROADCAST IP (Doesn't work - haven't yet figured out why)--
// const config = {
// 	iceTransportPolicy: 'relay',
// 	iceServers: [
// 		{urls: 'turn:localhost?transport=tcp', username: 'the/turn/username/constant', credential: 'the/turn/credential/constant' }
// 	]
// };
// const a = new Conn(config);
// const b = new Conn(config);
// all_events.map(e => [[a, e], [b, e]]).flat(1)
// 	.forEach(([c, e]) => c.addEventListener(e, console.log));
// const [siga, sigb] = await Promise.all([a.local, b.local]);
// // Replace the actual IP addresses of every candidate with the IPv4 broadcast address
// [...siga.candidates, ...sigb.candidates].forEach(c => c.address = '255.255.255.255');

// a.remote = sigb;
// b.remote = siga;


// -- ADDRESS BIND V1 --
// const certa = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
// const addra = new Addr(`turn://${await make_id(certa)}@hub.evan-brass.net:3478`);

// (async () => {
// 	for await (const conn of addra.bindv1({ certificates: [certa] })) {
// 		all_events.forEach(ev => conn.addEventListener(ev, e => console.log('listen', e)));
// 		console.log(conn);
// 	}
// })();

// const connb = addra.connect();
// all_events.forEach(ev => connb.addEventListener(ev, e => console.log('connect', e)));


// -- BIND (Connection to Bind service and open bind dc) --
// const certa = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
// const a = new Addr('udp:S7DI-ku29DAG2utqz27mn--xmJvZU591-28zCP0tCSE@127.0.0.1:3478').connect({ certificates: [certa] });
// all_events.forEach(e => a.addEventListener(e, console.log));
// const dc = a.createDataChannel('bind');
// all_events_dc.forEach(e => dc.addEventListener(e, console.log));


// -- BIND --
const certa = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
const bind_server = new Addr('turn:local.evan-brass.net');
const listener = await bind_server.bind({certificates: [certa]});

(async () => {
	for await (const conn of listener) {
		console.log('incoming conn', conn);
		all_events.forEach(e => conn.addEventListener(e, console.log));
	}
})();
console.log(listener);

// Try connecting to our listener:
const b = listener.addr.connect();
all_events.forEach(e => b.addEventListener(e, console.log));


// -- SIMULTANEOUS CONNECTIONS --
// const certa = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
// const addra = new Addr(`turn://${await make_id(certa)}@hub.evan-brass.net:3478`);
// const certb = await RTCPeerConnection.generateCertificate({name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'});
// const addrb = new Addr(`turn://${await make_id(certb)}@hub.evan-brass.net:3478`);

// const conna = addrb.connect({ certificates: [certa] });
// const connb = addra.connect({ certificates: [certb] });
// all_events.forEach(ev => conna.addEventListener(ev, e => console.log('a', e)));
// all_events.forEach(ev => connb.addEventListener(ev, e => console.log('b', e)));
// console.log(conna);
// console.log(connb);

// console.log('a', await conna.local);
// console.log('b', await connb.local);


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

// console.log(addra, addrb);
// const conna = addrb.connect({ certificates: [certa] });
// const connb = addra.connect({ certificates: [certb] });
// await Promise.race([conna.connected, connb.connected]);
// console.log('connected!');

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
