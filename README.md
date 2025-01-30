# Switchboard

WebRTC connection wrapper and client-side addresses.

# Connection Wrapper

The connection wrapper - Conn - removes the need for an initial offer / answer
by requiring pregenerated certificates. Conn initialy negotiates a simple
connection with only datachannel support, and then uses an internal datachannel
to renegotiate the connection whenever media changes or ice restarts require it.

```javascript
import { Cert } from './src/cert.js';
import { Conn } from './src/conn.js';

// -- Step 1: Get your certificates ready --
let certa, certb;
//  - Option 1: Reuse a certificate from IndexedDB (generating a new certificate if the existing cert is not present or has expired)
certa = await Cert.load('testa');
certb = await Cert.load('testb');

//  - Option 2: Generate fresh certificates
// certa = await Cert.generate();
// certb = await Cert.generate();

// -- Step 2: Turn your certificate into an id --
const ida = BigInt(certa);
const idb = BigInt(certb);

// -- Step 3: Create each side of the connection using your certificate and your peer's id --
const a = new Conn(idb, { cert: certa });
const b = new Conn(ida, { cert: certb });
// - Log the connection status
a.addEventListener(
	'connectionstatechange',
	() => console.log('a', a.connectionState),
);
b.addEventListener(
	'connectionstatechange',
	() => console.log('b', b.connectionState),
);

// -- Step 4: Pass ICE candidates (ip+port pairs) --
a.addEventListener(
	'icecandidate',
	async ({ candidate }) => await b.addIceCandidate(candidate),
);
b.addEventListener(
	'icecandidate',
	async ({ candidate }) => await a.addIceCandidate(candidate),
);

// -- Step 5: Add event listeners for incoming datachannels / tracks --
a.addEventListener(
	'datachannel',
	({ channel }) => console.log('datachannel from b', channel),
);
a.addEventListener('track', ({ track }) => console.log('track from b', track));
b.addEventListener(
	'datachannel',
	({ channel }) => console.log('datachannel from a', channel),
);
b.addEventListener('track', ({ track }) => console.log('track from a', track));

// -- Step 6: Create your datachannels or add your tracks. --
//  - Option 1: Create DataChannels
const _data = a.createDataChannel('Hello World', { protocol: 'greeter.json' });

//  - Option 2: Add Audio / Video tracks to the connection
const _transVid = a.addTransceiver('video');
const _transAud = b.addTransceiver('audio');

//  - Option 3: Trigger an ICE restart to find new network paths between the peers
a.restartIce();
```

# Addresses

Building on the Conn wrapper, this library provide Addr'esses. These addresses
are long-lived, reusable, and can represent both WebRTC servers and browser
peers. No HTTP requests of any kind (no websocket) are used, meaning that the
origin-agnostic properties of WebRTC are preserved.

```javascript
import { Addr } from './src/addr.js';

const example = new Addr(
	'turn:ucCm6JK3s22XuCRiTZVFpWajUq0tIpB7lDn1Sv8dRv3@stun.evan-brass.net',
);
const conn = example.connect();

// conn is just a normal Conn: you can do whatever you want with it:
conn.addEventListener('datachannel', console.log);
const _data = conn.createDataChannel('Hello World');
const _transVid = conn.addTransceiver('video');
```

As with Conn - and RTCPeerConnection - the connection could fail meaning its
`.connectionState` could go from `new` -> `connecting` -> `failed` without ever
reaching `connected`. If you are passing ICE candidates manually, then this
could occur if no network path can be found between the two sides of the
connection - you probably needed a TURN server. When using Addr's, this could
happen when the peer is offline or not listening to that address anymore.

In order to get your own address, you can connect to a relay server and listen
for when other people attempt to connect through that server to you.

```javascript
import { Listener } from './src/listen.js';

const listener = new Listener(
	'turn:RxLSBa3c1ZUuY2FHqKoPDuee91GDA3vDZk36rPk6W73@stun.evan-brass.net',
);
// Generate a random password for this listener using 16 random bytes
listener.ice_pwd = 16;

console.log('Your address is', listener.addr);

for await (const incoming of listener) {
	console.log('incoming connection', incoming);

	// incoming is just a normal Conn: you can do whatever you want with it
	const _kad = incoming.createDataChannel('kademlia');
}
```

The `incoming` Conn might fail to connect. Unlike other Conns, the Listener adds
a timeout that will close the Conn if its connection state doesn't transition
into `connected` within a timeout.

But what is that Listener? It's just a subclass of Conn! You can do whatevery
you... actually this server doesn't support multiple datachannels, or media (if
you're familier with WebRTC unreliable, it's roughly the same). But that's the
power of Addr and Conn! One format can represent a variety of different remote
WebRTC configurations. Listener is making a connection to a special _hosted_
peer inside the relay server. As a relay server, it can monitor the packets
going through it and can pick out the ICE connection tests that contain your
peerid as the destination. These are encapsulated as binary datachannel messages
so that you can parse them client-side.

How does your peerid get into the ICE connection test? The short answer is that
the username field is the only plaintext field that we can influence via SDP
munging. We set our local ICE ufrag to be our peerid and the remote ICE ufrag to
be our peer's peerid. These ufrags are combined into the plaintext username
field. But the raw ICE connection test wouldn't normally be readable from the
browser. That's why we need the relay server to encapuslate the packets, and
make them accessible to us.

Another way of explaining the ICE ufrag's is to say that they are a way of
sharing arbitrary data prior to the DTLS handshake. In our case it conveys the
DTLS fingerprint of the connecting peer, which we feed into the DTLS handshake:
effectively we are immitating a DTLS server that accepts any peer certificate by
having the peers declare what their certificate's hash will be and then checking
that against the certificate that they end up providing.

Parsing the ICE connection test client-side is important because it means you
don't have to leak your ICE password to the server and can verify the integrity
on your own. This can give you some confidence that the peer connecting to you
used the address you generated. There's still a lot of denial of service attacks
that a malicious server can perform, but I intend to continue working on the
Addr'essses and maybe there will be a V2 someday with better protection.

The most important thing is that WebRTC is always end-to-end encrypted so the
relay can't read any of your data. And since we're using WebRTC, NAT traversal
is built-in meaning you can migrate your connection off of the relay server
using just an ICE restart (which is automatically triggered by Addr).
Effectively, the relay server is only needed for the first few seconds of the
connection.

For technical reasons, the TURN implementation of the relay is broken in such a
way that it will appear to die (timeout) after a few seconds anyway - unless you
are connecting to the hosted peer, those connections don't time out.

The overarching goal for the relay is to handle everything statelessly, which it
succeeds to do until the DTLS handshake when you connect to the hosted peer.
This means the state stored on the server scales linearly with addresses bound,
not clients connecting to those addresses. The computation complexity per packet
/ request is roughly constant. Lastly, the network data sent is currently more
than data received, but I intend to add unreliability into the server (drop some
% of packets) to balance data sent to be < data received to prevent
amplification attacks. WebRTC has many different layers of retransmission
built-in, but I don't currently have experimental results for what % could be
tolerated.

I designed this server this way so that it would be cheap and easy for me to run
a free instance, but you could run your own instance and lock it down to only
give out addresses to certain peers, or to run over TCP/TLS instead of UDP, etc.
I've designed the Addr format in what I believe will be a way to support
alternative relay servers, but if it doesn't fit the bill, then you could
subclass Addr and use search parameters for you configuration.

You can spin up the server via `deno task start` and it probably won't work,
because I suck at writing cross platform code. If it did work, then you can
Listen through it using
`turn:ucCm6JK3s22XuCRiTZVFpWajUq0tIpB7lDn1Sv8dRv3@localhost`.

# What's next?

My goal with this project was to build WebRTC addresses, so that I could then
more easily implement overlay networks such as Kademlia. Someday I hope this
repo contains a reference Kademlia implementation that incorporates other ideas
like cross-origin, embeddable, overlay networks that aggregate WebRTC
connectsion accross multiple websites / browser tabs to present a single peer in
the network reducing churn. If we get there, then my next goal would be adding
kademlia as an address format.

```javascript
import { Addr } from './src/addr.js';

const peer = new Addr('kad:3AlTKotxyX1LxNjDkzKOmWFlWJREMKo4DT2aPy9kA8t')
	.connect();
```

And then on top of that I want to extend the addresses to allow connecting to a
datachannel at a peer, so that you can specify which service you want from that
peer:

```javascript
const channel = new Addr(
	'kad:3AlTKotxyX1LxNjDkzKOmWFlWJREMKo4DT2aPy9kA8t/torrent',
);
const channel = new Addr(
	'kad:D70BLWaqxKfdWUjQR4J6xTY4Ys9jQMzbn7ZZKep42a0/chess',
);
const channel = new Addr(
	'kad:D70BLWaqxKfdWUjQR4J6xTY4Ys9jQMzbn7ZZKep42a0/webvrchat',
);

import { network_client } from 'x';

const torrent_server = await network_client.install('torrent');

torrent_server.seed(new Blob('Hello World'), { filename: 'cool' }); // I don't really know how torrenting works...
```

I've got a lot of ideas here that will likely not come to fruition. And heck I
wouldn't care about any of this if we just had a sane, non-interactive, P2P
network API in the browser.
