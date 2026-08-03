# Security notes

What this system does and does not protect, why, and where the sharp edges are.
Written against the tree as of `a4578f1`.

This is a working analysis, not a formal audit. Findings are labelled
**F1**–**F9** and collected in [Findings](#findings) at the end.

## Contents

- [Review checklist](#review-checklist)
- [Threat model](#threat-model)
- [Identity and authentication](#identity-and-authentication)
- [Handshaking inside TURNS](#handshaking-inside-turns)
- [Migrating off the TURN path](#migrating-off-the-turn-path)
- [Denial of service](#denial-of-service)
- [Server-side and host concerns](#server-side-and-host-concerns)
- [Browser-side concerns](#browser-side-concerns)
- [Findings](#findings)

## Review checklist

The questions this document works through, written before reading the code:

**Identity and key material**

1. What is a peer's identity, and what binds a session to it?
2. Where does each private key live, who else can hold it, and what is its
   lifetime?
3. Is the deterministic certificate's private key recoverable from published
   material? By whom?
4. Does anything verify the certificate beyond its fingerprint (signature,
   validity dates, chain)?
5. What do the ICE credentials authenticate, given the shared constant password?

**Channel guarantees**

6. Handshake inside TURNS: what exactly is authenticated, by whom, to whom?
7. Is forward secrecy real here, and what does it buy given a public certificate
   key?
8. What is the active-attacker story versus the passive-attacker story, and
   where is the boundary?
9. What happens to those guarantees when the path changes after the handshake?
10. Can the relay operator read, forge, or splice traffic?

**Path and mobility**

11. What authorises a connection to move to a new address? Is it
    replay-protected?
12. Is the anti-replay watermark synchronised with the live record counter?
13. Can a third party redirect, hijack, or wedge an established connection?

**Denial of service**

14. Can an attacker create server state from a spoofed source address (return
    routability)?
15. Are there per-client or global caps on allocations, sockets, fds, memory?
16. Is anything a reflector or amplifier? What is the factor?
17. What is the blast radius of a single panic, given `panic = "abort"` and
    `overflow-checks`?
18. Is any input length attacker-controlled and used to index a slice?

**Authorisation and abuse**

19. Do the TURN credentials gate anything? Are permissions enforced?
20. Can the relay be used to reach arbitrary third parties (open relay)?
21. Who is allowed onto the SCTP VPN, and what can they reach once on it?

**Host**

22. What do the sysctls and nftables rules open up?
23. What privileges do the daemons hold, and what happens when one dies?

**Browser**

24. What can a connected peer make the local `RTCPeerConnection` do?
25. Is the long-lived identity a tracking vector?

## Threat model

Four adversaries are worth separating, because the guarantees differ sharply
between them:

|                                                | Can read your traffic | Can modify/inject | Present at handshake |
| ---------------------------------------------- | --------------------- | ----------------- | -------------------- |
| **Passive off-path**                           | no                    | no                | —                    |
| **Passive on-path** (ISP, wifi, transit)       | yes                   | no                | maybe                |
| **Active on-path**                             | yes                   | yes               | maybe                |
| **The relay operator** (`turn.evan-brass.net`) | yes                   | yes               | yes                  |

Throughout, "the deter path" means a browser talking to the `dtls-proxy` via
`Conn.to_deter()` / `src/deter.js`, and "the peer-to-peer path" means two
browsers each using their own `Cert` and exchanging ids out of band.

**The two paths have completely different security properties.** Most of what
follows is about why.

## Identity and authentication

### The peer-to-peer path: identity is the fingerprint

`Cert.generate()` calls `RTCPeerConnection.generateCertificate()`, so the
private key is a non-extractable browser key, and `id.js` treats the SHA-256
fingerprint of the resulting certificate as a 256-bit number. `conn.js` writes
that id into `a=fingerprint:` on the synthesised remote offer, and the browser
refuses to complete DTLS unless the peer's certificate hashes to it.

This is sound, and it is the strongest thing in the system:

- SHA-256 is preimage/collision resistant, so the fingerprint is a real
  commitment to the key.
- The private key never leaves the browser (not even to JavaScript —
  `RTCCertificate` exposes no key export).
- No CA, no chain, no expiry semantics to get wrong: the only check is the one
  that matters.

The security therefore reduces entirely to **how you learned the peer's id**. An
id delivered over an authenticated channel gives end-to-end authentication that
no relay operator can break. An id delivered over an unauthenticated channel
gives nothing — an attacker substitutes their own id and you get a perfectly
encrypted connection to the attacker. The library cannot help with this; it is
the signalling problem, relocated rather than solved.

Note also that `docs/how-it-works.md` still describes ufrag munging as the
mechanism. Per `CLAUDE.md`, that path is going away in Chrome, which pushes
browser peers further toward needing a signalling channel anyway.

### The deter path: the private key is public

`src/deter.js` builds a DER certificate byte-for-byte in the browser so that
every client derives the same certificate, and therefore the same fingerprint,
and therefore the same id — no annual redistribution of fingerprints. The commit
that introduced it says so plainly:

> Use a leaked private key instead of annually redistributing certificate
> fingerprints.

The certificate embeds a fixed P-256 public key (`deter.js:77-80`), which is
exactly the public half of `var/lib/swbrd/key.pem`, the key `dtls-proxy` serves
with (`crates/dtls-proxy/src/linux.rs:85`).

It is worth being precise about _how_ public the private key is, because the
construction gives it away more thoroughly than "leaked" suggests. The signature
is written as

```js
let v = await sha256(tbs);
v *= 0x8c30...dd94n;   // C1
v += 0xac3a...6a3bn;   // C2
v %= n;                 // s
```

with `r` a hardcoded constant. That affine shape is not a forgery or a
placeholder — it is genuine ECDSA with a **fixed nonce**: `s = k⁻¹·h + k⁻¹·r·d`,
so `C1 = k⁻¹` and `C2 = k⁻¹·r·d`. Both `k` and the private scalar `d` fall
straight out of the published constants:

```
k = C1⁻¹ mod n           # verified: (k·G).x == r
d = C2 · k · r⁻¹ mod n   # verified: d·G == the public key in deter.js and key.pem
```

I ran this; it reproduces `key.pem`'s public key exactly. So the private key is
not merely leaked somewhere obscure — it is a three-line computation from
`src/deter.js`, which is served to every browser that loads the library.
Fixed-nonce ECDSA also means anyone who collects two of the certs (January and
July, say) recovers `d` from the signatures alone, without reading the source.

**Consequences.** On the deter path:

- The DTLS handshake authenticates nothing. Anyone can stand up a `dtls-proxy`
  with the same key and be indistinguishable from the real one.
- The fingerprint check the browser performs is satisfied by every such
  impostor, because they all present the same certificate.
- There is no "compromise" event to worry about — the key is public from day
  one, so certificate rotation (`scripts/cert-rotate.js`) rotates the _address_,
  not the trust. It exists to keep the deterministic address moving, not to
  limit key exposure.

None of this is a bug — it is the design, and given the goal (reach a well-known
service at a derivable address with no prior key distribution) it is a
reasonable trade. But it does mean **the deter path must never be described as
end-to-end secure**, and any application-level secret sent over it needs its own
authentication on top. **(F1)**

### ICE credentials authenticate nothing

The ICE password is the compile-time constant `the/ice/password/constant`, in
`conn.js:187` and `crates/ice-dissolve/src/main.rs:25`. `ice-dissolve` answers
any Binding request matched by the nftables pattern with a correct
MESSAGE-INTEGRITY over that constant, without checking the _incoming_ request's
integrity or its USERNAME beyond the `dissolve:` prefix the firewall matched.

So ICE, in this system, is pure connectivity discovery. It provides:

- no proof that the far end is who you want (that is DTLS's job, and on the
  deter path DTLS doesn't do it either),
- no consent-to-receive guarantee — the property that normally stops a WebRTC
  endpoint from being aimed at an uninvolved third party, since the third party
  can't produce valid check responses. Anyone can, here.

Practically this means an attacker who can inject packets can steer ICE
nomination freely, and that STUN-level checks give the DTLS layer nothing to
build on. Everything rests on DTLS. **(F2)**

### The TURN credentials authenticate nothing either

`README.md` publishes `user` / `password`; `turnserver` hardcodes
`USER_KEY = md5('user:none:password')` and the realm is the literal string
`none`. Anyone can therefore compute a valid MESSAGE-INTEGRITY from public
values — the credentials gate nothing, and are not meant to. What they cannot
compute is the nonce, which is now a real one
([F6](#state-creation-without-return-routability-f6--fixed)): the 401 challenge
round trip is no longer skippable, so the relay is open to anyone _at a real
address_. See [Denial of service](#denial-of-service) for why that round trip
mattered more than the missing secret.

`Method::AddPermission` returns success without recording anything, and
`Method::Send` is handled _before_ the integrity check in `handle_turn`
(`crates/turnserver/src/linux.rs:854`). There is no permission enforcement
anywhere. This is a deliberately open relay. **(F3)**

## Handshaking inside TURNS

The question: DTLS negotiates ECDHE, so the session keys are forward-secret. If
the handshake runs inside a TURNS connection (real WebPKI certificate for
`turn.evan-brass.net`, terminated by nginx per `etc/nginx/nginx.conf`), what
authentication do you actually get?

Work it through by adversary, on the deter path:

**Passive off-path.** Nothing to say; they see nothing.

**Passive on-path.** They see a TLS 1.x connection to `turn.evan-brass.net:443`.
The inner DTLS handshake is inside that tunnel, so they cannot even observe it.
Even if it were exposed, ECDHE means recording it buys them nothing later — the
public certificate key is a _signing_ key, and recovering it (already done, see
above) does not recover session keys. **Forward secrecy is real and it holds.**

**Active on-path.** This is where it splits:

- _Without_ TURNS, an active attacker owns the connection outright. They present
  the same deter certificate — which they can, since they have the key —
  complete the handshake as the server, and MITM everything. The fingerprint
  check passes. There is no detection.
- _With_ TURNS, they can't. They cannot terminate TLS for `turn.evan-brass.net`
  without a fraudulently issued WebPKI certificate. The DTLS handshake is
  protected because it is inside a channel that _is_ authenticated.

**The relay operator.** Unchanged either way: they terminate the TLS, and on the
deter path they are also the DTLS endpoint. They see plaintext.

So the honest summary of the TURNS-wrapped deter path is:

> You get exactly the authentication that the WebPKI gives you for
> `turn.evan-brass.net`, and nothing more. The DTLS layer contributes
> confidentiality against everyone except the relay operator, plus forward
> secrecy against later passive compromise. It contributes zero authentication
> of the peer, because every peer holds the same public key.

Two things follow that are easy to get wrong:

1. **The security is hop-by-hop, not end-to-end.** It is TLS-to-a-server, with a
   DTLS-shaped decoration inside. If you would not be comfortable with "I have a
   TLS connection to turn.evan-brass.net and its operator can read everything",
   you are not comfortable with this.
2. **It depends on the transport actually being TURNS.** `defaults.iceServers`
   in `conn.js:8-13` lists plain `turn:` URLs alongside `turns:`, and ICE picks
   whichever pair wins — usually the plain UDP one, since it is faster. So the
   protective TLS wrapper is _not_ what a default `Conn.to_deter()` gets; you
   would need `iceTransportPolicy: 'relay'` plus a TURNS-only `iceServers` list
   to force it, the way `with_candidates_dissolved` does for its own (unrelated)
   reasons. As written, the common case is an unauthenticated handshake over
   plain UDP. **(F4)**

On the **peer-to-peer path** none of this applies: the peers hold their own
private keys, the relay does not, and the relay therefore cannot MITM regardless
of transport. TURNS adds metadata privacy against on-path observers and nothing
else. That path is genuinely end-to-end secure, conditional on out-of-band id
exchange.

## Migrating off the TURN path

The question: the handshake completed inside TURNS; ICE then nominates a direct
(or plain-UDP relayed) pair. What breaks?

**For the session's cryptography: nothing.** This is the good news and it is
worth stating clearly. DTLS keys were established under the TLS tunnel's
protection. Once established, the record layer's AEAD protects every subsequent
record no matter what path carries it. An attacker on the _new_ path sees
ciphertext they cannot decrypt (they weren't present for the key exchange),
cannot forge (AES-128-GCM tags), and cannot splice in records from elsewhere
(sequence numbers and epoch are in the AAD). Migration after the handshake does
not degrade confidentiality or integrity.

This is a genuinely nice property of the design: you can pay for an
authenticated channel exactly once, during the handshake, and then run over a
cheap unauthenticated path forever. It is close to the right shape.

**What an attacker on the new path can still do** is drop, delay, and reorder —
ordinary availability attacks, unavoidable at that layer. Plus one thing that is
specific to this codebase:

### The mobility watermark is not synchronised (F5)

`crates/dtls-proxy/src/keys.rs` implements client mobility: a record arriving on
the TUN from an unexpected source address is authenticated against the
connection's re-derived client-write keys, and if it verifies, the connection's
socket is re-`connect`ed to the new address. The design is right — an off-path
attacker cannot forge a GCM tag, so they cannot move the connection.

The anti-replay guard is documented as:

> the record number must strictly exceed `highest_seq`, so a former on-path
> relay can't replay a stale-but-authentic record to drag the connection back.

But `highest_read_seq` is initialised to `0` (`linux.rs:161`) and is **only ever
advanced inside the mobility branch** (`linux.rs:330`). Records that arrive
normally, on the connected socket, go straight into OpenSSL's BIO; they never
touch this counter. OpenSSL maintains its own replay window, but that window is
not visible to `check_record`.

So on a connection that has been running normally and is at, say, record 100
000, `highest_read_seq` is still `0`. An attacker who has captured **any single
ciphertext record** from that connection — one packet, from any point on the
path at any time, no key material needed — can replay it from their own address.
`seq = 5 > 0` passes, the tag verifies (it is a genuine record), and the socket
is re-pointed at the attacker.

Impact:

- All server→client traffic is redirected to the attacker until the client's
  next packet arrives and re-points it back (which it will, since the real
  sequence number is far higher). The result is flapping, not permanent capture.
- The attacker receives ciphertext they cannot read, so this is not a
  confidentiality break. It is a connection-wedging DoS plus a traffic-analysis
  foothold, achievable from a single captured packet and repeatable
  indefinitely.
- It requires the attacker to have seen one record, so it is an on-path (or
  formerly-on-path) capability — exactly the "former relay" case the comment
  says it is defending against.

Directions for a fix, roughly in order of preference:

- Seed `highest_read_seq` from the connection's live read sequence when the keys
  are derived, rather than from `0`. This is the direct fix but needs the
  sequence out of OpenSSL, which DTLS 1.2 does not expose cleanly.
- Snoop the record header on the socket path (a `MSG_PEEK` before handing the
  datagram to the BIO, or a custom BIO in `ffi.rs`) and keep `highest_read_seq`
  current for every record, not just roamed ones. More code, but it makes the
  watermark mean what the comment says it means.
- Accept a roamed record only if its sequence is within a forward window of the
  last one seen, so a stale capture is out of range even without an exact
  counter.
- Cheapest partial mitigation: require two authenticated records with increasing
  sequence numbers from the new address before committing the re-point. A single
  captured packet no longer suffices; a captured _pair_ still does.

Separately, and more minor: the mobility path re-points on an authenticated
record without any confirmation that the new address is reachable. That's
inherent to the design and probably fine, but it means one spoofed packet costs
one path change.

## Denial of service

### State creation without return routability (F6 — fixed)

`dtls-proxy` does this correctly and it is worth crediting: `cookie.rs`
implements stateless DTLS cookies HMAC'd over both source and destination
address, and — unusually — handles the fragmented ClientHello case that defeats
`DTLSv1_listen`. No `Ssl` object exists until a cookie has round-tripped.
Spoofed sources cannot create state.

`turnserver` used not to. The 401/nonce challenge that would provide the same
round trip was neutered: `realm` and `nonce` were both the constant `"none"` and
the key is `md5('user:none:password')` with the credentials in the README. An
attacker composed a valid authenticated Allocate offline and spoofed the source
address. The server then:

- allocated a slab entry, a relayed transport address, and **a file descriptor**
  (`connected_udp`),
- registered it with the poller,
- started sending heartbeat Indications to the spoofed victim once a minute for
  ~6 minutes (`linux.rs:595-628`).

Two problems. Resource-wise, one spoofed packet bought an fd and ~5 minutes of
state, with no per-source cap; the pool is
`--relay-net 2a01:4ff:1f0:7e46:0:1::/96` × ports `10000-65535`, so
`RelayRange::capacity()` is astronomically larger than the process's fd limit.
Exhaustion was bounded by `RLIMIT_NOFILE`, not by anything the code checked.
Reflection-wise, it was a small but real amplifier: one packet in, five
heartbeats out to an address the attacker chose.

**The fix**, in `crates/turnserver/src/nonce.rs`, is the one STUN already
specifies — a real nonce, unguessable, address-bound and time-bounded, so that
Allocate requires a genuine round trip:

```text
ts    u32 big-endian, seconds since the process started
tag   HMAC-SHA256(secret, ts || client_ip || client_port)[..12]
nonce hex(ts) || hex(tag)                                  // 32 ASCII chars
```

- The secret is 32 random bytes generated once per process, the same trade
  `dtls-proxy` makes for its cookies: a restart costs live clients one extra
  challenge round trip and nothing else.
- The tag covers the client's IP **and port**, so a nonce fetched honestly by an
  attacker is not replayable with a spoofed source.
- Nonces are valid for 600s. Requests carrying credentials with a forged,
  expired or foreign nonce get **438 Stale Nonce** with a fresh nonce attached;
  requests with no usable credentials get the 401 challenge. `handle_turn`
  checks on every authenticated request, so the connected-UDP and TCP paths are
  covered as well as the wildcard Allocate.
- The timestamp is relative to process start (`Instant`), not wall clock, so
  there is no clock-skew or `SystemTime` exposure. It is only ever compared
  against the same process's own clock.

This is compatible with keeping the credentials public — it is the round trip,
not the secret, that is load-bearing. It does **not** close F3: the relay is
still open to anyone willing to complete a round trip, `Send` is still handled
before the integrity check, and there are still no rate limits.

One wrinkle worth knowing before touching this code: `Method::UseChannel`
answers **438** too, which is now overloaded, and it answers with a bare
ERROR-CODE — no REALM, no NONCE. Both halves are deliberate. libwebrtc treats
any other error to ChannelBind as fatal for the entry and tears down the peer's
Send/Data indication path a few seconds after it came up (400 was tried, and
breaks a relayed pair ~15s in). A 438 tells Chrome not to retransmit with the
nonce it used, and since the response carries no replacement it simply drops the
request — leaving the nonce it is using for everything else alone. So the
omission is what makes this a no-op rather than a retry loop; adding the
attributes for symmetry with the stale-nonce arm would let it ask forever. Any
change there needs an e2e that holds a relayed pair open for a minute, not just
one that reaches `connected`.

### The relay is open (F3, continued)

With published credentials, no permission enforcement, and `Method::Send`
handled before the integrity check, anyone can allocate and relay arbitrary UDP
payloads to arbitrary IPv6 destinations, sourced from the server's relay prefix.
There is no rate limit, no destination filter, and no per-client bandwidth cap
anywhere in the daemon.

This is not primarily an amplification vector (roughly 1:1) — it is a laundering
vector. The VPS becomes the apparent origin of whatever traffic someone wants to
send, which is an abuse-desk and reputation problem more than a bandwidth one.
If the relay is meant to stay open, the mitigations that preserve that are a
global and per-allocation packet-rate cap, and a destination denylist for
bogons/loopback/link-local/multicast and any prefix you don't want to be seen
sourcing traffic toward.

### Reflectors (F7)

Three unauthenticated request→response paths that will answer a spoofed source:

| Path                   | Trigger                                           | Response                                                                          | Factor |
| ---------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------- | ------ |
| `ice-dissolve`         | any nftables-matched Binding request (~36 B)      | Binding response with XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY + FINGERPRINT (76 B) | ~2×    |
| `turnserver` TUN       | UDP to an in-pool but unallocated relayed address | ICMPv6 Port Unreachable quoting the packet                                        | ~1×    |
| `common::read_network` | any non-UDP, non-error-ICMP packet on a TUN       | ICMPv6 Host Unreachable from the router address                                   | ~1×    |

The 401/438 challenge `turnserver` now sends (see
[F6](#state-creation-without-return-routability-f6--fixed)) belongs in the same
band: ~72 bytes answering a ~28-byte unauthenticated Allocate, so ~2.5×. That is
not a regression — the old constant-nonce challenge was the same size — but it
is why the nonce is 32 characters with a 12-byte truncated tag rather than a
full digest. Every byte of it is amplification.

None is a serious amplifier on its own — 2× is far below what makes a reflector
attractive. But all three are stateless, unmetered, and answer spoofed sources,
so they are free capacity for someone assembling a distributed reflection
attack. Userspace-generated ICMP also bypasses the kernel's
`net.ipv4.icmp_ratelimit` / `net.ipv6.icmp.ratelimit`, so the usual safety net
is absent. A token bucket per destination prefix on each of these would cost
very little.

### Panic-to-abort with no restart (F8)

`.cargo/config.toml` sets `overflow-checks = true` and `panic = "abort"` for
**both** release and dev. Combined with `Restart=no` in
`etc/systemd/system/turnserver.service` (and no `Restart=` at all in
`dtls-proxy.service`), any panic anywhere in a daemon is a permanent outage
until someone intervenes manually.

Given a packet parser reached directly from the internet, that is a large blast
radius for a single arithmetic slip. Nothing I traced is currently reachable —
the indexing that worried me, `&buffer[48..48 + plen]` in the turnserver TUN
path (`linux.rs:514`, `linux.rs:552`), derives `plen` from the UDP length
header, which `read_network` checks only against the IPv6 length header, also
attacker-supplied. Both are bounded in practice because the kernel validates
payload length against the actual frame before it reaches the TUN. That is a
correct assumption today; it is an _implicit_ one, and `builder.offload(true)`
(which enables the virtio-net header path, where a read can deliver more than
one MTU's worth) is exactly the kind of thing that could quietly invalidate it.

Two independent hardening steps, both cheap:

- Add `Restart=always` with a `RestartSec` backoff to the units. Cookies are
  keyed per-process (`dtls-proxy/src/linux.rs:248` notes a restart costs
  in-flight handshakes one extra round trip), so restarting is genuinely cheap —
  the code already anticipates it.
- Bound `plen` by the number of bytes actually read rather than by the header,
  and use `get()` rather than direct slice indexing on any length that came off
  the wire.

### Unbounded connection growth in dtls-proxy (F9)

Cookies stop spoofed-source floods, but a single attacker with one real address
can still open unlimited connections, because the connection id is the
_destination_ address+port and the deter prefix offers 2⁴⁷ of them. Each costs
an fd, an `Ssl`, and a slab entry. Reaping is idle-based (5 minutes) and only
runs when `streams.len() > next_cleanup`, which grows as `streams.len() + 10` —
so it is amortised, but there is no cap. The ceiling is `RLIMIT_NOFILE`, reached
from one host at whatever rate it can complete cookie round trips. A
per-source-address connection cap would close this without affecting legitimate
use, since legitimate clients open one.

## Server-side and host concerns

**`route_localnet = 1`.** `etc/sysctl.d/transparent.conf` sets
`net.ipv4.conf.all.route_localnet = 1` to make `IP_TRANSPARENT`→localhost work.
This disables the kernel's martian-source protection for `127.0.0.0/8` on every
interface, and the standard compensating control — an input rule dropping
externally-arriving packets destined to `127.0.0.0/8` — is not present in
`etc/nftables.conf`. The practical exposure is limited (the loopback upstreams
in `nginx.conf` are reachable via the public address anyway, and the daemons'
plaintext endpoint is IPv6 `[2a01:4ff:1f0:7e46::1]:9899`, not loopback), but the
setting is a well-known footgun and the guard rule is one line:

```
ip daddr 127.0.0.0/8 iif != lo drop
```

**Plaintext endpoint injection.** `dtls-proxy` treats any TUN packet sourced
from `endpoint` as plaintext to encrypt and forward into the matching DTLS
connection (`linux.rs:339-346`). Anything able to source packets as the endpoint
address onto that TUN can inject into any live connection. That requires local
compromise or a routing mistake today, so it is an assumption rather than a hole
— but it is an assumption worth writing down, because it is the sort of thing a
later routing change can silently break.

**The VPN is open to the internet.** `crates/swbrd` admits any SCTP association
that completes the DataChannel handshake and assigns it an address from the
`/96`. Since that handshake runs over the deter certificate, whose key is
public, **anyone can join**. Once on, a peer is source-pinned (`main.rs:322`
rejects packets whose source is not the peer's own assigned address, which
correctly prevents peers from spoofing each other) but the _destination_ is
unfiltered: `network.send(&data)` hands the packet to the host's routing table
whatever the destination. So a peer can reach other peers, the host itself, and
— if the subnet is globally routed — the internet at large. There is no
authorisation step of any kind. Fine for a demo on a machine you are willing to
lose; not fine for anything else, and the fix is an allowlist of permitted peer
ids checked at `SCTP_COMM_UP`, plus a destination filter before `network.send`.

**Privileges.** All four daemons run as user `swbrd` with `CAP_NET_ADMIN` only,
no root — good, and worth keeping. `CAP_NET_ADMIN` is still enough to
reconfigure host networking if a daemon is compromised; `CAP_NET_RAW` plus a
tighter set, or a `SystemCallFilter`, would narrow it further.

## Browser-side concerns

**A connected peer controls your ICE.** `conn.js:157-169` feeds anything the
peer sends over the data channel into `setRemoteDescription` /
`addIceCandidate`. A malicious peer can therefore point your browser's
connectivity checks at arbitrary addresses. This is inherent to WebRTC and
normally bounded by ICE consent (the target must answer checks) and by the
browser's pacing — but the consent bound is weaker here than usual, because the
ICE password is a public constant and `ice-dissolve` will answer on anyone's
behalf. The volume a browser will emit is small, so this is a nuisance rather
than a weapon; it is listed because it is the mechanism by which a peer you have
_already_ accepted gains reach beyond the connection.

**The id is a supercookie.** `Cert.load()` persists a certificate in IndexedDB
keyed by `import.meta.url`, and its fingerprint is a stable, high-entropy,
cross-session identifier that is transmitted to every peer you connect to and
visible to the relay operator. It survives everything short of clearing site
data, and it rotates roughly annually (the cert is deleted within 2 days of
expiry, `cert.js:64`). Any application using this should treat the id as
personally identifying and offer a way to discard it. Applications wanting
unlinkability should generate a fresh `Cert` per context rather than sharing the
module-level default.

**XSS reaches the identity.** The certificate's key is non-extractable, so
script injection cannot exfiltrate it — but it can _use_ it, which for an
identity system is nearly as bad, and it can read the id. Standard same-origin
hygiene applies with more than usual force.

## Findings

|        | Finding                                                                                                                                                                                 | Severity                                                      | Notes                                                           |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------- |
| **F1** | Deter certificate's private key is recoverable from `src/deter.js` in three lines (fixed-nonce ECDSA); the deter path has no peer authentication                                        | By design — must be documented, not fixed                     | [details](#the-deter-path-the-private-key-is-public)            |
| **F2** | ICE password is a public constant; `ice-dissolve` answers any Binding request. No consent-to-receive guarantee                                                                          | By design                                                     | [details](#ice-credentials-authenticate-nothing)                |
| **F3** | Open relay: published credentials, permissions never enforced, `Send` handled before the integrity check, no rate limits                                                                | High (abuse/reputation)                                       | [details](#the-turn-credentials-authenticate-nothing-either)    |
| **F4** | `defaults.iceServers` mixes `turn:` and `turns:`, so the default deter handshake usually runs over plain UDP with no authentication anywhere                                            | High                                                          | [details](#handshaking-inside-turns)                            |
| **F5** | `highest_read_seq` starts at 0 and only advances on mobility events, so one captured ciphertext record lets an on-path attacker repeatedly hijack the connection's downstream direction | Medium                                                        | [details](#the-mobility-watermark-is-not-synchronised-f5)       |
| **F6** | `turnserver` created fd-backed state from spoofed sources — the nonce was the constant `"none"`, so there was no return-routability round trip                                          | ~~Medium~~ fixed: address-bound HMAC nonce, 401/438 challenge | [details](#state-creation-without-return-routability-f6--fixed) |
| **F7** | Three unmetered reflectors (`ice-dissolve` ~2×, two ICMP paths ~1×), bypassing kernel ICMP rate limits                                                                                  | Low                                                           | [details](#reflectors-f7)                                       |
| **F8** | `panic = "abort"` + `overflow-checks` + `Restart=no`: any panic is a permanent outage; wire-derived lengths index slices directly                                                       | Low today, high blast radius                                  | [details](#panic-to-abort-with-no-restart-f8)                   |
| **F9** | `dtls-proxy` has no per-source connection cap; ceiling is `RLIMIT_NOFILE`                                                                                                               | Low                                                           | [details](#unbounded-connection-growth-in-dtls-proxy-f9)        |
| —      | `route_localnet = 1` without a compensating input drop rule                                                                                                                             | Low                                                           | [details](#server-side-and-host-concerns)                       |
| —      | The SCTP VPN admits anyone and does not filter destinations                                                                                                                             | High if deployed beyond a demo                                | [details](#server-side-and-host-concerns)                       |

### The one-paragraph version

The peer-to-peer path is sound: fingerprint-as-identity with browser-held keys
is a good design, and its security reduces cleanly to out-of-band id exchange.
The deter path is unauthenticated by construction and should be treated as "TLS
to turn.evan-brass.net" and nothing more — wrapping the handshake in TURNS
genuinely does buy real protection against active attackers, and migrating off
the TURN path afterwards genuinely does keep it, but neither helps unless the
handshake actually took the TURNS path in the first place (**F4**), and neither
changes what the relay operator can see. On the server side, `dtls-proxy`'s
cookie handling is careful work; `turnserver`'s missing return-routability round
trip (**F6**) has since been fixed with a real address-bound nonce, which leaves
the mobility watermark bug (**F5**) as the concrete thing still worth fixing.
