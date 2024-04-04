import { idf } from "../src/cert.js";
import { Conn, Cert, Addr, cert } from '../src/index.js';
import { Class, Method, Stun } from "../src/stun.js";
import { Listener } from '../src/listen.js';

// const addr = new Addr('turn+tcp:AC2ZoeeWTZAyFrpZAczuqRpQQ9vyKebnnAvTocdZyzeD@local.evan-brass.net');
// await addr.resolve_id();

// const conn = addr.connect();
// console.log(addr);
// console.log(conn);

// const certb = await Cert.generate();

// const listener = new Listener();

// const test = listener.address.connect({cert: certb});
// console.log(test);

// for await(const conn of listener) {
// 	console.log(conn);
// }

// console.log(await new Addr('udp:seed.evan-brass.net').resolve_id());

// const c = new Addr(`turn:${cert}@localhost`).connect({cert: certb});
// console.log(c);

const certa = await Cert.generate();
const certb = await Cert.generate();

const a = new Addr(`turn+tcp:${certb}@127.0.0.1`).connect({ cert: certa });
const b = new Addr(`turn+tcp:${certa}@127.0.0.1`).connect({ cert: certb });
// a.addEventListener('icecandidate', async ({candidate}) => await b.addIceCandidate(candidate));
// b.addEventListener('icecandidate', async ({candidate}) => await a.addIceCandidate(candidate));

// setInterval(async () => {
// 	const stats = Object.groupBy(
// 		(await a.getStats()).values(),
// 		s => s.type
// 	);
// 	console.log(stats);
// }, 3000);

// [
// 	'connectionstatechange',
// 	'datachannel',
// 	'icecandidate',
// 	'icecandidateerror',
// 	'iceconnectionstatechange',
// 	'icegatheringstatechange',
// 	'negotiationneeded',
// 	'signalingstatechange',
// 	'track'
// ].forEach(ev => a.addEventListener(ev, console.log));
// while (a.connectionState == 'new') await new Promise(res => a.addEventListener('connectionstatechange', res, {once: true}));
// [
// 	'statechange'
// ].forEach(ev => a.sctp.addEventListener(ev, console.log));
// [
// 	'statechange',
// 	'error'
// ].forEach(ev => a.sctp.transport.addEventListener(ev, console.log));
// [
// 	'gatheringstatechange',
// 	'selectedcandidatepairchange',
// 	'statechange'
// ].forEach(ev => a.sctp.transport.iceTransport.addEventListener(ev, console.log));

// const a = new Conn(certb, { cert: certa });
// const b = new Conn(certa, { cert: certb });

// a.addEventListener('icecandidate', async ({candidate}) => await b.addIceCandidate(candidate));
// b.addEventListener('icecandidate', async ({candidate}) => await a.addIceCandidate(candidate));

// == Basic usage: [simultaneous signaling, datachannel transmission] ==
// const a = new Conn();
// const b = new Conn();
// const [siga, sigb] = await Promise.all([a.local, b.local]);
// a.remote = sigb; b.remote = siga;
// console.log(siga, sigb);
// console.log(a);
// console.log(b);


// const t = new RTCPeerConnection();
// t.createDataChannel('');
// const trans = t.addTransceiver('audio');
// console.log(trans);
// console.log(await t.createOffer());
// await t.setRemoteDescription({ type: 'offer', sdp: `v=0
// o=switchboard 42 0 IN IP4 0.0.0.0
// s=-
// t=0 0
// a=group:BUNDLE dc
// a=ice-ufrag:hYSFYDSeOKnO6qG-ytP5QGmttcIURy-BhGM47eU5y54
// a=ice-pwd:the/ice/password/constant
// a=ice-options:trickle
// a=fingerprint:sha-256 85:84:85:60:34:9E:38:A9:CE:EA:A1:BE:CA:D3:F9:40:69:AD:B5:C2:14:47:2F:81:84:63:38:ED:E5:39:CB:9E
// m=application 42 UDP/DTLS/SCTP webrtc-datachannel
// c=IN IP4 0.0.0.0
// a=mid:dc
// a=setup:passive
// a=sctp-port:5000
// `});
// let {sdp} = await t.createAnswer();
// sdp = sdp
// 	.replace(/^a=ice-ufrag:.+/im, 'a=ice-ufrag:please+work')
// 	// .replace(/^a=setup:.+/im, 'a=setup:passive');
// await t.setLocalDescription({type: 'answer', sdp});
// console.log(t.localDescription.sdp);
