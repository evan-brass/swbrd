# Switchboard
WebRTC connection wrapper and client-side addresses.

# Connection Wrapper
The connection wrapper - Conn - removes the need for an initial offer / answer by requiring pregenerated certificates.
Conn initialy negotiates a simple connection with only datachannel support, and then uses an internal
datachannel to renegotiate the connection whenever media changes or ice restarts require it.

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
const a = new Conn(idb, {cert: certa});
const b = new Conn(ida, {cert: certb});
// - Log the connection status
a.addEventListener('connectionstatechange', () => console.log('a', a.connectionState));
b.addEventListener('connectionstatechange', () => console.log('b', b.connectionState));


// -- Step 4: Pass ICE candidates (ip+port pairs) --
a.addEventListener('icecandidate', async ({candidate}) => await b.addIceCandidate(candidate));
b.addEventListener('icecandidate', async ({candidate}) => await a.addIceCandidate(candidate));


// -- Step 5: Add event listeners for incoming datachannels / tracks --
a.addEventListener('datachannel', ({channel}) => console.log('datachannel from b', channel));
a.addEventListener('track', ({track}) => console.log('track from b', track));
b.addEventListener('datachannel', ({channel}) => console.log('datachannel from a', channel));
b.addEventListener('track', ({track}) => console.log('track from a', track));


// -- Step 6: Create your datachannels or add your tracks. --
//  - Option 1: Create DataChannels
const _data = a.createDataChannel('Hello World', {protocol: 'greeter.json'});

//  - Option 2: Add Audio / Video tracks to the connection
const _transVid = a.addTransceiver('video');
const _transAud = b.addTransceiver('audio');

//  - Option 3: Trigger an ICE restart to find new network paths between the peers
a.restartIce();
```

## Notes
Manual signalling is disabled on Conn:
```javascript
conn.createOffer(); // ERROR
conn.createAnswer(); // ERROR
conn.setLocalDescription(); // ERROR
conn.setRemoteDescription(); // ERROR
```

You can only provide one cert to Conn, and it must be an RTCCertificate and castable to a BigInt (which Cert takes care of). If you
leave the cert field blank when creating a Conn, then your default cert is used.
```javascript
import { Conn } from './src/conn.js';
import { cert } from './src/cert.js';

console.assert(new Conn(42n).cert === cert);
```

Because of how we define politeness you **can't reliably connect to your own id**:
```javascript
const self = await Cert.generate();
new Conn(BigInt(self), {cert: self}); // Probably a bad idea.
```
Unless you specify it manually, both sides of the connection will be the DTLS client, so the handshake will error. If you get past the DTLS handshake then connection renegotiation will get stuck. Just use a temporary certificate instead.

# Addresses
TODO: Explain addresses
