# Switchboard

Addresses for WebRTC, that don't require HTTP requests of any kind.
```javascript
import { Cert } from 'swbrd/cert.js';
import { Addr } from 'swbrd/addr.js';

const certa = await Cert.load('peera');
const certb = await Cert.load('peerb');

const a = new Addr(`turn+tcp:${certb}@stun.evan-brass.net?setup`)
    .connect({ cert: certa });
const b = new Addr(`turn+tcp:${certa}@stun.evan-brass.net?setup`)
    .connect({ cert: certb });
log_everything(a, 'a');
log_everything(b, 'b');
```
