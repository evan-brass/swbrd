# Rainboots

A retro, privacy-focused chat client, and the server it talks to.

**Rainboots** is the front end: one HTML file, a service worker, and a
stylesheet you can throw away. **Puddle** is the back end: a switchboard
extension that keeps a roster, passes messages around a room, and introduces
people to each other. The two are separable on purpose — pick whichever boots
you like, splash in whichever puddles you like.

```
rainboots/
  puddle.js       the extension
  puddle_test.js  deno test -A rainboots/puddle_test.js
  www/            the front end; serve it from anywhere
  etc/            the directory entry the daemon needs
```

## A puddle is a domain

There are no accounts and no rooms. You add `chat.example.net` to your server
list, and Rainboots opens a `Conn.to_domain` connection to it — a WebPKI-checked
TLS TURN connection, then a DTLS session that survives being moved onto faster
network paths. The room is the host. You are in as many rooms as you have
domains, all at once.

## Who you are

Your identity is a WebRTC certificate this browser generated and keeps in
IndexedDB, and your peer id is the base36 rendering of its SHA-256 fingerprint.
The daemon takes that fingerprint off the finished DTLS handshake and hands it
to the puddle before the puddle sees a byte of your data, so a peer id is
something you prove rather than something you assert.

It is the same id in every puddle. That is what makes a DM findable no matter
where you met somebody — and equally what lets two puddles work out that you are
the same person. There is no way to have the first property without the second,
and pretending otherwise would be the dishonest option.

## Nicks

Nicks follow the IRC pattern: ask the puddle for one, secure it with a password,
and you can take it back from another browser or after your certificate rotates.

```
/nick rainy hunter2
```

**A nick is decoration.** The puddle hands them out, and a hostile one can hand
yours to somebody else. So the client renders every nick — in the roster, in
messages, in a DM, in the incoming-DM popup — as a `<peer-nick>` whose tooltip
is the peer id behind it, and styles them to look informal rather than official.
The id is the part that cannot be forged.

Registered nicks and PBKDF2 hashes of their passwords are the only thing a
puddle stores. Nothing said in the room is written down, or even remembered:
join late and you have missed what you missed.

## DMs

A DM does not go through the puddle. The puddle only relays ICE candidates, and
only ones the sender really sent — a `signal` carries the sender's peer id, and
is dropped if that does not match the fingerprint authenticated on the channel
it arrived on. Without that check an open relay would be a tool for introducing
people to somebody other than who they asked for.

Once the candidates are across, the two browsers hold a `Conn.with_candidates`
connection whose certificates _are_ the peer ids. A puddle can refuse to
introduce you; it cannot get between you afterwards.

- **Relay only by default.** `iceTransportPolicy: 'relay'`, so the only address
  either end learns belongs to a TURN server.
- **Use unrelayed** changes the config and restarts ICE. It is deliberately
  one-sided: revealing your own address is your call and needs nobody's
  agreement.
- It is also one-way. Chrome accepts a change back to `relay` —
  `setConfiguration` succeeds and `getConfiguration()` agrees — but keeps the
  non-relay pair it has already selected, so an ICE restart changes nothing and
  the traffic keeps flowing over the address you just tried to stop revealing.
  Rather than ship a button that quietly does nothing, the control spends
  itself; close the DM and dial again for relay-only.
- The DM panel shows the selected candidate pair. A local candidate that is not
  a relay is marked, with a tooltip saying the other peer can see that address.
  A relay candidate gets no reassurance in return — a stateless relay can encode
  an IPv4 address into the IPv6 it hands out, so "relay" is not a promise that
  nothing leaked.
- Declining costs one message: end your candidates without ever sending one and
  the caller's `Conn` closes on the spot instead of waiting out its timeout.
- Declining also puts that peer on a one minute cooldown. The refusal reaches
  them immediately, but the candidates their ICE agent had already gathered are
  still in flight, and without the cooldown each straggler would arrive looking
  like a stranger getting in touch and raise a fresh popup — saying no once would
  cost you one dialog per candidate. Dialling them yourself ends the cooldown
  early, since that is as clear a change of mind as there is.

### Chrome only

`Conn.with_candidates` puts the real ICE credentials inside the candidate rather
than in the SDP, and only Chrome will pair that. So DMs are disabled where they
could not work: no dm button in the roster, a note in the sidebar saying why,
and anyone who calls you is refused immediately — the same end-of-candidates a
person clicking reject sends, so the caller's `Conn` closes in milliseconds
instead of waiting out its timeout.

The caller is told the connection was declined, and cannot tell that from a
person turning them down, because the refusal channel is a null candidate and
carries no reason. That is why the panel says "declined" rather than "they
declined". Making it precise means either a `reason` on the signal message, or —
better — peers announcing what they can do when they join, so the dm button
never appears for somebody who could not answer it. Neither exists yet.

This is a "not yet" rather than a "never": `Conn.with_candidates_dissolved` gets
Firefox connecting through a TURN server that intercepts the connectivity
checks. It needs both ends to agree on which mode they are using, which is a
puddle protocol this does not have.

## Skins

Point the skin setting at any stylesheet on the web and it is worn on top of the
built-in one. It is cached for offline use, and the page never reads its bytes —
the service worker fetches it `no-cors` and stores the opaque response, which is
all a `<link>` needs — so a skin host needs no CORS headers. It does need to
serve `text/css`; cross-origin stylesheets are MIME-checked.

Writing one is meant to be easy. There is not a single class or id in the
markup: every element has a descriptive name, and everything that varies is an
attribute.

```css
:root { --paper: #000; --ink: #0f0; --accent: #0f0; }   /* the whole look */

peer-nick[anon]                  { opacity: .6 }
puddle-entry[state="connecting"] { font-style: italic }
local-candidate[exposed]         { color: red }
chat-message[mine] peer-nick     { text-decoration: none }
dm-panel[state="connected"] dm-state::before { content: "● " }
hover-hint                       { border-radius: 6px }  /* every tooltip */
hover-hint[kind="exposure"]      { background: #400 }
```

`rainboots/www/rainboots.css` is the worked example, and it is all element
selectors too.

One thing to know before writing a rule about a button: a tooltip's trigger is a
`<button>` too (see below), so `peer-entry button` matches the nick as well as
the dm button. The built-in stylesheet uses `peer-entry > button` for exactly
that reason, and a skin should too.

## Tooltips

Hover text is a real popover rather than a `title` attribute: an `interestfor`
interest invoker pointing at a `popover="hint"`. That buys the things a native
tooltip cannot do — Escape dismisses it, the pointer can move onto it to read a
long one, the ARIA description is wired up without naming it, and it reaches the
keyboard, since interest fires on focus as well as hover. Being an ordinary
element, it is also something a skin can style.

`interestfor` is only honoured on `<button>` and `<a>`, which is why a nick and
an exposed candidate render a button inside themselves. The trigger doubles as
the popover's implicit anchor, so neither end needs an `anchor-name`.

No polyfills, and that is a decision rather than an oversight: this app
precaches itself and fetches nothing at runtime, so pulling interestfor, popover
and anchor-positioning polyfills off a CDN to draw a tooltip would trade away
the thing it is. Chrome 142 and up get the popover; anything older falls back to
`title`, which is exactly what this replaced.

## Unread and sound

Each puddle and each DM carries its own unread count, and the sum sits in the
page title as `(3) rainboots` — so a backgrounded tab still tells you. A
message only counts as read if you could actually have read it: the right view,
in front, in a window that has focus. Joins, parts and nick changes never count,
because a badge you cannot clear by reading anything is just a badge. An
unanswered DM invitation counts too: it is the most attention-worthy thing here
and its popup is invisible from another tab.

The sounds are synthesized, not shipped. Rainboots precaches itself and has to
work offline, so every audio file would be another thing to cache, version and
get wrong; these are a couple of oscillators and an envelope apiece, which costs
nothing and happens to be the palette a chat client from 1997 had. One blip for
a message you have not seen, two for a DM, three rising notes for an invitation,
and a falling pair when somebody declines you.

A page may not make noise before you have interacted with it, so the audio
context is built on your first click or keypress; sounds before that are
silently skipped rather than queued. There is an off switch in settings.

## Updates

The service worker precaches every file the app is built out of — including the
swbrd client modules it imports from outside its own directory — and serves them
from cache forever, without ever checking the network again. **Changing
`VERSION` in `www/sw.js` is the only way an update happens.** A puddle you
connect to cannot change the client you connect with, and neither can whoever is
hosting the copy you installed.

The skin is the deliberate exception: it is yours, so it refreshes when you ask
it to.

The flip side is that editing `www/` while a worker is installed changes nothing
you can see. Tick **Update on reload** in DevTools → Application → Service
Workers while you are working on it, or unregister the worker; bumping `VERSION`
is the release mechanism, not the development loop.

## Running it

Front end — any static host, over HTTPS or localhost (a service worker needs a
secure context). `src/` must sit two levels above `www/` so the import map
resolves:

```
./scripts/dev.sh serve
# http://localhost:8000/rainboots/www/
```

Back end:

```
deno run --allow-read --allow-write --allow-net rainboots/puddle.js \
  --socket /run/swbrd/ext/puddle.sock --state /var/lib/swbrd/puddle/nicks.json
```

and an entry in `/etc/swbrd/directory.d/` pointing `rainboots.v1` at that socket
— `rainboots/etc/directory.d/20-puddle.toml` is the one to copy. On the live box
that is all done by the `swbrd-ext-puddle` package:

```
./scripts/dev.sh deploy ext-puddle
```

## Tests

```
deno test -A rainboots/puddle_test.js          # the extension, no server needed
./scripts/dev.sh e2e tests/refuse.html         # declining a DM, no server needed
./scripts/dev.sh e2e tests/rainboots.html --units=dtls-proxy,swbrd-ext-puddle
```
