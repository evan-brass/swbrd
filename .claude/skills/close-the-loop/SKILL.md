---
name: close-the-loop
description: Build, deploy, and verify swbrd changes end to end — cross compile a daemon on the Debian VM, deploy it to turn.evan-brass.net, drive a real browser against it, and correlate with journalctl/tcpdump/perf. Use for any task that touches crates/ or src/ and needs to be seen working, not just compiled.
---

# Closing the loop on swbrd

`./scripts/dev.sh` is the whole cycle. Every subcommand exits non-zero on
failure, so they compose.

```sh
./scripts/dev.sh check                              # cargo check on the VM (seconds)
./scripts/dev.sh test stun common                   # cargo test on the VM
./scripts/dev.sh build dtls-proxy                   # cross compile for the VPS
./scripts/dev.sh deploy dtls-proxy turnserver       # build + upload + restart + verify
./scripts/dev.sh e2e tests/vpn.html --units=dtls-proxy,swbrd --grep=app
./scripts/dev.sh logs turnserver -10min app
./scripts/dev.sh capture 'ip6 and net 2a01:4ff:1f0:7e46:0:4::/96' 20
./scripts/dev.sh perf dtls-proxy 15
./scripts/dev.sh status
```

Run `./scripts/dev.sh` with no arguments for the full list.

## The shape of a change

1. Edit here on the Mac. The Debian VM sees the same files over virtiofs, so
   nothing is copied. Keep code clean by running `cargo fmt`, `cargo clippy`,
   and `deno fmt` if the change touches html/js/markdown.
2. `check` / `test` — the offline signal. The daemons are Linux-only; they do
   not build on the Mac.
3. `deploy <unit>` — stops the unit, backs up `/opt/<unit>` to
   `/opt/<unit>.prev`, installs, restarts, and waits 3s. If the unit isn't
   active it restores `.prev` and exits 1, so a bad binary never leaves the
   server dead. `rollback <unit>` does it by hand.
4. `e2e <page>` — the browser half (below).
5. When something is wrong: `logs`, then `capture`, then `perf`.

There is no confirmation prompt on deploy. The VPS is a live-ish test box with
no users.

## The browser half

`scripts/e2e.js` launches Chrome headless, loads a page from `tests/`, streams
its console through, and turns the page's verdict into an exit code. Pages
report by logging `SWBRD-RESULT {json}` — see `tests/harness.js`, which also
gives you `pass()`, `fail()`, `deadline()`, `expect_open()`,
`expect_connected()` and `log_everything()`.

- `--units=a,b` prints each unit's journal for exactly the test's time window
  afterwards, so client and server sit in one transcript.
- `--grep=app` cuts the `mio::poll` trace flood and keeps systemd lines,
  anything above TRACE, and TRACE from our own crates. Any other value is passed
  to `journalctl --grep` verbatim.
- `--headful` shows the window; `--keep-open` leaves it running; `--verbose`
  adds Chrome's stderr.
- Page deadlines are set below the runner's 30s default so the _page's_ message
  wins, not `no result within 30000ms`.

For poking at something interactively — a rendered game, a live audio call — use
the **claude-in-chrome** MCP against the same URLs (`./scripts/dev.sh serve`,
then `http://localhost:8000/tests/…`). Same pages; only the driver differs.

Writing a new scenario: copy `tests/vpn.html`, import from `./harness.js` and
`./config.js`, call `deadline(...)` first and `pass()`/`fail()` at the end. Add
it to the list in `index.html`.

## Address plan

Everything is keyed off `2a01:4ff:1f0:7e46::/64` (`turn.evan-brass.net`, also
`5.78.133.88`).

| prefix / port     | what                                                                                                                                                                                                     |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `…:7e46::1`       | the host itself; also the SCTP-over-UDP endpoint for `dtls-proxy` on UDP **9899**                                                                                                                        |
| `…:7e46:0:1::/96` | `turnserver` relay addresses, ports 10000–65535                                                                                                                                                          |
| `…:7e46:0:4::/96` | `dtls-proxy` — the destination IP+port _is_ the connection                                                                                                                                               |
| `…:7e46:0:5::/96` | `swbrd` VPN; the low 32 bits are the SCTP association id                                                                                                                                                 |
| `fd01::/96`       | also routed to `dtls-proxy`, but only reachable from inside the VPN. `Deter`'s default base — a browser on the internet must be given the `…:0:4::` prefix instead, which is what `tests/config.js` does |
| sctp-port 5000    | `Conn`'s default; nothing listens on it today                                                                                                                                                            |
| sctp-port 5001    | the `swbrd` VPN daemon                                                                                                                                                                                   |

Each daemon owns a TUN interface of the same name, so `capture` output reads as
a routing trace: `eth0 In` → `ice-dissolve Out` is nftables diverting an ICE
Binding request; `eth0 In` → `dtls-proxy Out` is a DTLS record. Fixed TURN
credentials: `user` / `password` (`USER_KEY = md5('user:none:password')`).

## Things that will bite

- **Use the rustup toolchain on the VM.** `dev.sh` already puts `~/.cargo/bin`
  first; the system `/usr/bin/cargo` is 1.85 and too old for this workspace.
- **`root@turn.evan-brass.net` doesn't work** — its host key isn't accepted
  here. Everything goes through `ssh turn` as `evan` plus passwordless
  `sudo -n`.
- **Don't decode a `-i any` pcap locally.** LINUX_SLL2 stores an ifindex, and a
  reader on the Mac resolves it against _its own_ interface table — `eth0` shows
  up as `gif0`. `dev.sh capture` decodes on the server for this reason; the pcap
  it leaves in the scratch dir is for Wireshark.
- **`tests/relay.html` is expected to fail eventually.** It depends on ICE
  credential munging, which Chrome has announced it is removing.
