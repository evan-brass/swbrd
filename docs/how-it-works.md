# How the Conn wrapper works

Conn's renegotiation uses the
[perfect negotiation pattern](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Perfect_negotiation).
The pregenerated certificates are fingerprinted (using sha-256) and the hash is
convert to a 32-byte BigInt: this is the peer's id. The polite peer is the peer
with the smaller id.

Unless overridden, the polite peer is also the DTLS server. Both peers start out
as the ICE controlled agent, but ICE
[role conflict resolution](https://datatracker.ietf.org/doc/html/rfc8445#section-7.3.1.1)
picks a peer to become the controlling agent.

Cert is a subclass of RTCCertificate that uses
[RTCCertificate.getFingerprints()](https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate/getFingerprints)
or a temporary RTCPeerConnection to get the sha-256 fingerprint for the
certificate. Conn only works using this subclass, so it disables
`.generateCertificate()`.

```javascript
await Conn.generateCertificate(); // Throws an ERROR
```

The default keyAlgorithm used by `Cert.generate()` and `Cert.load()` is ECDSA
over P-256 and expiring in 365 days. You can override those defaults:

```javascript
const keygenAlgorithm = {
	name: "RSASSA-PKCS1-v1_5",
	modulusLength: 2048,
	publicExponent: new Uint8Array([1, 0, 1]),
	hash: "SHA-256",
	expires: Date.now() + 24 * 60 * 60 * 1000,
};
await Cert.generate(keygenAlgorithm);
await Cert.load('special cert', keygetAlgorithm);
```

I'm pretty sure that all browsers' DTLS implementations support ECDSA <-> RSA
key exchanges.

SDP munging might be used to set the ICE ufrag and ICE pwd. The ufrag is set to the
peer's id (as a base62 number). Unless overridden, the pwd is set to a constant:
`the/ice/password/constant`.

Lots of things are disabled on Conn. Notably, manual signalling is disabled:

```javascript
conn.createOffer(); // Throws an ERROR
conn.createAnswer(); // Throws an ERROR
conn.setLocalDescription(); // Throws an ERROR
conn.setRemoteDescription(); // Throws an ERROR
```

# How the Addr's work
