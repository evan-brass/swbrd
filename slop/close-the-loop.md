1. I'd like you to decide what the best way is for you to close the loop.
2. In the future I want to be able to set a task that may require writing both browser and server code together.
3. When I deploy I would do something like this:
	1. ssh into my debian vm and build: `ssh 192.168.64.3; cd share/src/swbrd; ./build.sh`.  You could do better by building individual binaries
	2. The built artifacts are now in ./opt/amd64/bin/{cert-rotate,dtls-proxy,ice-dissolve,swbrd,turnserver}
	3. ssh into the VPS and stop the service: `ssh turn` or `ssh turn.evan-brass.net` then `sudo systemctl stop {dtls-proxy,turnserver,ice-dissolve}`
	4. Upload the artifacts to the VPS: `scp ./opt/amd64/bin/dtls-proxy root@turn.evan-brass.net:/opt/`
	5. Restart the service and watch the logs: `sudo systemctl start dtls-proxy; sudo journalctl -fu dtls-proxy`
	6. Make sure the local file server is running `file-server` and then load a test html file in the browser `http://localhost:8000/`.  If you can puppet a browser then this is where you'd do that.
	7. When troubleshooting, I look through logs, use `sudo tcpdump`, `sudo perf`, etc. to understand what the program is doing.  These are the kinds of capabilities which I want you to utilize when completing future tasks.

I don't know whether the way to handle this is scripts or ansible or whatever you want.  At the end of it I'd like to be able to assign you tasks such as the following:

- "Write a deno library that binds to an SCTP socket and accepts incoming connections, then wrap those connections in a datachannel aware wrapper that can create outgoing channels, accept incoming channels, and correctly handles sending text/binary messages"
- "Build a multiplayer top-down shooter where the client is a static html file, and the server is written in Rust.  Use a one-to-many socket, and utilize reliable/unreliable and SendAll/unicast messages to convey player/world/match state as players join/leave and rounds."
- "Add support in dtls-proxy for the fixed audio that Conn negotiates when the audio flag is set.  This means negotiating srtp and then decrypting / encrypting audio for that destination.  Then have dtls-proxy open an ExternalMedia channel in the asterisk server running on turn.evan-brass.net.  You'll need to adjust the SDP in conn.js to have fixed values which match the values asterisk expects for an RTP payload type of opus and telephone events.  The end to end test should support using conn's unsignalled browser->server path and to place a phone call through asterisk's dialplan over WebRTC."

---

# What got built

Two scripts, a `tests/` tree, and a skill. No ansible, no Makefile, no new dependencies.

## `scripts/dev.sh`

`check` `test` `build` `deploy` `rollback` `logs` `watch` `capture` `perf` `status` `serve` `e2e`
`vm` `vps`. Run it with no arguments for the list. Notes on the choices:

- `build` uses `cargo build -p <crate> --target x86_64-unknown-linux-gnu` instead of
  `cargo install --path`. `cargo install` builds in a throwaway target dir, so it never reuses
  anything; against the shared `target/` a one-crate rebuild is ~0.2s warm, 7s cold. `build.sh` is
  untouched and is still the full release path.
- `deploy` backs up `/opt/<unit>` to `.prev`, installs (not copies — `install` unlinks first, so a
  running binary can't give ETXTBSY), restarts, waits 3s, and restores `.prev` if the unit isn't
  active. Exercised deliberately with a broken binary: it detected, rolled back, and exited 1.
- Everything on the VPS goes through `ssh turn` as `evan` + `sudo -n`. `root@turn.evan-brass.net`
  fails host key verification from this Mac.
- `logs`/`e2e` take a `--grep`; the alias `app` drops the `mio::poll` trace flood and keeps systemd
  lines, anything above TRACE, and TRACE from our own crates.
- `capture` decodes the pcap **on the server**. With `-i any` the link type is LINUX_SLL2, which
  stores an ifindex, and a reader on the Mac resolves those against its own interface table — `eth0`
  came out as `gif0`, `dtls-proxy` as `stf0`. Decoded on the server it reads as a routing trace:
  `eth0 In` → `ice-dissolve Out` for ICE binding requests, `eth0 In` → `dtls-proxy Out` for DTLS.

## `scripts/e2e.js`

Deno, no dependencies. Launches Chrome (Canary is the only one installed here) with
`--headless=new`, a throwaway profile, and fake media devices; drives it over the DevTools protocol
using the built-in WebSocket; streams the page's console through with a `[page]` prefix; and exits
0/1 on the verdict the page logs as `SWBRD-RESULT {json}`. `--units=a,b` appends each unit's journal
for exactly the test's window, so client and server end up in one transcript. `--headful` and
`--keep-open` for watching it happen; claude-in-chrome against the same URLs for poking at it.

## `tests/`

The `type="_module"` blocks out of `index.html`, one page each, sharing `harness.js` (`pass`/`fail`/
`deadline`/`expect_open`/`log_everything`) and `config.js` (deployment constants, overridable by
query parameter). `index.html` is now an index of them.

Verified against the live deployment: `vpn.html` PASS 0.9s, `p2p.html` PASS (and `?relay=1` to force
it through `turnserver` instead of a host pair), `audio.html` PASS, `icmp.html` PASS (a probe — the
real assertion is in the turnserver journal, the browser can't see ICMP). `relay.html` FAILs, which
is the expected outcome for the ICE-credential-munging path.

Two things worth knowing:

- **`Deter`'s default base is `fd01::/96`**, which is only routable from inside the VPN. Nothing in
  `src/` ever supplied the global prefix, so the pages pass `2a01:4ff:1f0:7e46:0:4::` from
  `tests/config.js`. The library default is unchanged.
- **`Conn`'s default `sctp_port` of 5000 has nothing listening behind it.** Anything that wants the
  VPN needs 5001. `audio.html` failed for exactly this reason before it was pointed at 5001 — the
  audio m-section itself negotiates fine (`mid=audio sendrecv`), there is just no RTP coming back
  yet, which is what the Asterisk work has to change. `audio.html` reports the inbound RTP packet
  count so that will show up as a number going from 0 to nonzero.
