# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Infrastructure for **reduced-signaling, peer-to-peer WebRTC** connections, deployed at
`turn.evan-brass.net`. It has two halves:

- A browser **JavaScript library** (`src/`, `index.html`) that subclasses `RTCPeerConnection` /
  `RTCCertificate` so peers can connect using deterministic addressing.
- A set of **Linux server daemons** (`crates/`) — a custom STUN/TURN server, a DTLS proxy, an ICE
  responder, and an SCTP/DataChannel VPN — that operate on raw IPv6 packets via TUN interfaces.

The central idea: a peer's identity **is** the SHA-256 fingerprint of its DTLS certificate, treated as
a 256-bit number. From that id, both peers derive the same ICE ufrag, a shared constant ICE password
(`the/ice/password/constant`), and who plays DTLS server (the "polite"/smaller-id peer). See
`docs/how-it-works.md`.

**Caveat — the fully signaling-free path no longer works in browsers.** It depended on munging the ICE
ufrag/password in the SDP. Chrome has announced it will remove ICE credential munging, which invalidates
that capability for browser peers. Treat "no signaling server needed" as historical/aspirational for
browser contexts; don't describe the browser library as signaling-free in new docs or code comments.

## Edit locally, build/test on the Linux VM

**Edit files here on macOS** (this working copy), but **run all builds and tests on the Linux VM** — the
daemons are Linux-only (see below) and the toolchain there is set up for them.

```sh
ssh 192.168.64.3
cd share/src/swbrd/        # same tree as this repo (~/share/src/swbrd), shared with the Mac
```

On the VM, **use the user's rustup toolchain, not the system Rust.** The system `/usr/bin/cargo` is
outdated (1.85) and too old for this workspace; `~/.cargo/bin` has a current rustup toolchain. Make sure
`~/.cargo/bin` is first on `PATH` (e.g. `PATH="$HOME/.cargo/bin:$PATH" cargo ...` or `~/.cargo/bin/cargo`).

This is a Cargo workspace (edition 2024, `resolver = "3"`). All the daemons are **Linux-only**: on
non-Linux their `main()` just prints a joke and exits, and the real logic lives in each crate's
`linux.rs`, gated by `#[cfg(target_os = "linux")]`. That's the main reason builds/tests belong on the VM.

```sh
# on the VM, with ~/.cargo/bin on PATH:
cargo build                       # whole workspace
cargo test -p stun                # RFC 5769 STUN test vectors (no_std crate)
cargo test -p common              # packet/checksum + socket tests
cargo test                        # everything
./build.sh                        # cross-compile release binaries to opt/amd64 + deploy artifacts
```

`build.sh` cross-compiles to `x86_64-unknown-linux-gnu` (needs `crossbuild-essential-amd64`; linker
set in `.cargo/config.toml`), installs into `opt/amd64/bin`, and also `deno compile`s
`scripts/cert-rotate.js`. Binaries are meant to land in `/opt/` on the server and run under the systemd
units in `etc/systemd/`.

Release **and** dev profiles set `overflow-checks = true` and `panic = "abort"` (`.cargo/config.toml`).

### Style

Hard tabs throughout (`Rustfmt.toml`, `deno.json`). **Do not run `cargo fmt` broadly** — the repo is
not rustfmt-clean; match surrounding style by hand.

## Crate map

- **`common`** — shared server plumbing. IPv6/UDP/ICMPv6 packet structs, checksum helpers, and
  `read_network` / `write_network_udp` / `write_network_icmp` for talking to a TUN device. Handles
  virtio-net **checksum offloading** (the `VNET` header, `partial_checksum`/`full_checksum`) and DCEP
  DataChannel parsing. `socket.rs` (Linux) wraps connected UDP sockets, `IP_TRANSPARENT`, PMTU, and
  pktinfo. Almost everything is built on `zerocopy` for zero-copy packet parsing.
- **`stun`** — `#![no_std]` STUN/TURN message parsing and encoding, with HMAC message-integrity,
  fingerprint (CRC), and XOR-mapped address types. Feature-gated (`std`, `rand`, `sha1`, `crc`,
  `bytes`); tested against RFC 5769 vectors.
- **`sctp`** — thin Linux SCTP socket API wrappers (socket options, notifications, `sendmsg`/`recvmsg`
  control messages).
- **`turnserver`** — custom STUN/TURN server. Built around per-allocation **connected UDP sockets** and
  a TUN interface, with `IP_TRANSPARENT`, heartbeat-driven allocation expiry, and ICMP generation.
  Fixed credentials: `USER_KEY` is `md5('user:none:password')`.
- **`dtls-proxy`** — DTLS proxy that uses the **destination IP+port as the connection id**. Uses OpenSSL
  with a custom dgram BIO over connected `IP_TRANSPARENT` sockets, stateless DTLS cookies (`cookie.rs`),
  and hot cert reload on `SIGHUP`.
- **`ice-dissolve`** — stateless responder that answers ICE Binding requests off a TUN interface
  (matched/marked by nftables) without keeping any per-connection state.
- **`swbrd`** — SCTP-over-DataChannel VPN that maps SCTP associations onto an IPv6 subnet via a TUN
  interface.

## Browser library (`src/`)

Plain ES modules, no build step; `index.html` maps the bare specifier `swbrd/` to `./src/` via importmap.

- `id.js` — `Id`: a peer id as a 256-bit BigInt (SHA-256 fingerprint), base-36 encoded in ICE ufrags.
- `cert.js` — `Cert extends RTCCertificate`: generates/loads a cert and computes its `id`. `Conn` only
  works with this subclass, so `Conn.generateCertificate()` is deliberately disabled.
- `conn.js` — `Conn extends RTCPeerConnection`: perfect-negotiation wrapper. Manual signaling
  (`createOffer`/`createAnswer`/`setLocal/RemoteDescription`) is intentionally disabled; SDP is munged
  internally. `defaults.iceServers` points at `turn.evan-brass.net`.
- `deter.js` — `Deter`: deterministic ICE candidate derivation (address/port from id + time).
- `scripts/cert-rotate.js` — Deno; rotates the deterministic cert twice a year (see the ASCII timeline
  in the file). Two `dtls-proxy` instances (January/July certs) run simultaneously to cover clock skew.

## Deployment topology (`etc/`)

Not runnable locally, but essential context for how the daemons fit together:

- **`nftables.conf`** — marks/diverts packets: `IP_TRANSPARENT` socket diversion, and pattern-matching
  ICE Binding requests to route them to `ice-dissolve`.
- **`nginx.conf`** — a `stream {}` block that ALPN/SNI-multiplexes port 443/5349 between `turns`, HTTP,
  and SSH, with `proxy_bind ... transparent` to preserve client addresses.
- **`sysctl.d/`** — enables SCTP-over-UDP (port 9899), TCP syncookies, `route_localnet`, and disables
  `udp_early_demux` (so ICE-dissolve diversion still works against connected sockets).
- **`systemd/`** — one unit per daemon (all run as user `swbrd` with `CAP_NET_ADMIN`), plus
  `.netdev`/`.network` files for the TUN interfaces and cert-rotation timer units.

## Working notes

Design docs and rationale for in-progress/finished features live in `slop/` (`dtls-cookies.md`,
`icmp-plan.md`, `turn-heartbeats.md`, `turn-icmp.md`) and `docs/` (`how-it-works.md`, `ciphersuites.md`).
`firefox-issues/` holds browser-bug repros.
