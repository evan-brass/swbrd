// The elements Rainboots is built out of.
//
// Every one of these is a real custom element with a descriptive name, and none
// of them has a shadow root.  That is the point: a shadow root would wall your
// stylesheet out of the very thing you are trying to restyle.  Everything lives
// in the light DOM, there are no class or id hooks to guess at, and anything
// that varies is an attribute you can select on:
//
//   puddle-entry[state="connecting"] { opacity: .5 }
//   local-candidate[exposed] { color: red }
//   peer-nick[anon] { font-style: italic }
//
// The plain-looking tags -- message-log, chat-message, peer-roster and friends
// -- are undefined on purpose.  They are structure and selector anchors, not
// behavior, and an undefined hyphenated tag is a perfectly ordinary HTMLElement.

import { short } from './client.js';
import { DM_SUPPORTED } from './dms.js';

// Filled in by app.js.  Nick lookups cross puddles, and an element has no
// business knowing how many of them there are.
let directory = {
	identities: () => [],
	nick_of: () => null,
	me: () => '',
};

export function set_directory(next) {
	directory = next;
}

export function el(tag, props = {}, ...children) {
	const node = document.createElement(tag);
	for (const [key, value] of Object.entries(props)) {
		if (value === null || value === undefined || value === false) continue;
		if (key === 'onclick' || key === 'onsubmit' || key === 'oninput') {
			node.addEventListener(key.slice(2), value);
		} else if (value === true) {
			node.setAttribute(key, '');
		} else {
			node.setAttribute(key, value);
		}
	}
	node.append(...children.filter((c) => c !== null && c !== undefined));
	return node;
}

// Hover hints: interest invokers pointing at a popover="hint".
//
// Hovering, focusing, or long-pressing the trigger opens the popover, and the
// browser does the parts a `title` attribute never could -- Escape dismisses it,
// the pointer can move onto it to read a long one, and the ARIA description is
// wired up without us naming it.  It is also, unlike a native tooltip,
// something a skin can style.
//
// No polyfill, deliberately.  Rainboots precaches itself and fetches nothing at
// runtime, so pulling interestfor, popover and anchor-positioning polyfills off
// a CDN to draw a tooltip would trade away the thing this app is.  Chrome 142
// and up get the popover; anything older falls back to `title`, which is
// exactly what this replaced.
const HAS_INTEREST = Object.prototype.hasOwnProperty.call(
	HTMLButtonElement.prototype,
	'interestForElement',
);

let hints = 0;

// Attach a hint to `trigger` and return the nodes to insert.
//
// `interestfor` is only honoured on <button> and <a>, so a trigger has to be
// one.  That is no loss: it makes every hint reachable from the keyboard, which
// a `title` on a <span> never was.  The trigger is also the popover's implicit
// anchor, so neither end needs an anchor-name.
export function hint(trigger, text, kind = null) {
	if (!HAS_INTEREST) {
		trigger.title = text;
		return [trigger];
	}
	const id = `hint-${++hints}`;
	trigger.setAttribute('interestfor', id);
	return [trigger, el('hover-hint', { id, popover: 'hint', kind }, text)];
}

const clock = (at) =>
	new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

// Keep a log pinned to the bottom, but only if the reader had not scrolled up
// to read something.
function append_pinned(log, node) {
	const pinned = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
	log.append(node);
	if (pinned) log.scrollTop = log.scrollHeight;
}

// --------------------------------------------------------------- <peer-nick>

// The one element that matters for honesty.  A puddle invents nicks and can
// hand yours to somebody else, so every nick anywhere in this app is one of
// these, and every one of them carries the peer id in its tooltip.  There is no
// other way to render a name.
class PeerNick extends HTMLElement {
	static observedAttributes = ['peer', 'nick'];

	connectedCallback() {
		this.#render();
	}
	attributeChangedCallback() {
		this.#render();
	}

	#render() {
		const peer = this.getAttribute('peer') ?? '';
		const nick = this.getAttribute('nick');
		this.toggleAttribute('anon', !nick);
		this.replaceChildren(...hint(
			el('button', { type: 'button' }, nick || short(peer)),
			nick ? `${nick} is currently ${peer}` : peer,
			'identity',
		));
	}
}

export function nick_el(peer, nick) {
	return el('peer-nick', { peer, nick: nick ?? null });
}

// ------------------------------------------------------------ <puddle-entry>

// One puddle in the sidebar: its name, how many people are in it, and whether
// we are actually in it.
class PuddleEntry extends HTMLElement {
	#client = null;
	#unread = 0;
	#on = () => this.render();

	set unread(count) {
		this.#unread = count;
		this.render();
	}
	get unread() {
		return this.#unread;
	}

	set client(client) {
		this.#client?.removeEventListener('state', this.#on);
		this.#client?.removeEventListener('roster', this.#on);
		this.#client = client;
		this.#client.addEventListener('state', this.#on);
		this.#client.addEventListener('roster', this.#on);
		this.setAttribute('domain', client.domain);
		this.render();
	}
	get client() {
		return this.#client;
	}

	render() {
		const client = this.#client;
		if (!client) return;
		this.setAttribute('state', client.state);
		this.toggleAttribute('unread', this.#unread > 0);
		this.replaceChildren(
			el('puddle-domain', {}, client.domain),
			el(
				'peer-count',
				{},
				client.connected ? String(client.users.size) : client.state,
			),
			...(this.#unread ? [el('unread-count', {}, String(this.#unread))] : []),
		);
	}
}

// ------------------------------------------------------------- <puddle-pane>

// A puddle is a room.  The domain is the room's name; there are no others.
class PuddlePane extends HTMLElement {
	#client = null;
	#log = null;
	#roster = null;
	#header = null;

	set client(client) {
		this.#client = client;
		this.setAttribute('domain', client.domain);
		this.#build();

		client.addEventListener('state', () => this.#render_header());
		client.addEventListener('roster', () => {
			this.#render_header();
			this.#render_roster();
		});
		client.addEventListener('msg', ({ detail }) => this.#message(detail));
		client.addEventListener(
			'notice',
			({ detail }) => this.notice(detail.text, detail.at),
		);
	}
	get client() {
		return this.#client;
	}

	#build() {
		this.#log = el('message-log', { tabindex: '0' });
		this.#roster = el('peer-roster');
		this.#header = el('pane-header');

		const input = el('input', {
			type: 'text',
			name: 'text',
			autocomplete: 'off',
			placeholder: `say something in ${this.#client.domain}`,
		});
		const composer = el(
			'message-composer',
			{},
			el(
				'form',
				{
					onsubmit: (e) => {
						e.preventDefault();
						if (this.#client.say(input.value)) input.value = '';
					},
				},
				input,
				el('button', { type: 'submit' }, 'say'),
			),
		);

		this.replaceChildren(this.#header, this.#log, this.#roster, composer);
		this.#render_header();
		this.#render_roster();
	}

	#render_header() {
		const client = this.#client;
		this.setAttribute('state', client.state);
		this.#header.replaceChildren(
			el('puddle-domain', {}, client.domain),
			el(
				'puddle-state',
				{},
				client.connected
					? `${client.users.size} here`
					: client.trouble ?? client.state,
			),
			el(
				'my-nick',
				{},
				client.me ? nick_el(client.me, client.nick) : 'not here yet',
			),
		);
	}

	#render_roster() {
		const client = this.#client;
		const rows = Array.from(client.users, ([id, nick]) => ({ id, nick }))
			.sort((a, b) =>
				(a.nick ?? '￿' + a.id).localeCompare(b.nick ?? '￿' + b.id)
			);
		this.#roster.replaceChildren(...rows.map(({ id, nick }) =>
			el(
				'peer-entry',
				{ peer: id, you: id === client.me },
				nick_el(id, nick),
				// No dm button where a DM could never connect; the sidebar
				// carries the one explanation instead of every roster row.
				...(id === client.me || !DM_SUPPORTED ? [] : hint(
					el('button', {
						type: 'button',
						onclick: () =>
							this.dispatchEvent(
								new CustomEvent('dm', { detail: id, bubbles: true }),
							),
					}, 'dm'),
					`Open a direct connection to ${id}. Relayed, so neither of you learns where the other is.`,
				)),
			)
		));
	}

	#message({ from, nick, text, at }) {
		append_pinned(
			this.#log,
			el(
				'chat-message',
				{ peer: from, mine: from === this.#client.me },
				el('message-when', {}, clock(at)),
				nick_el(from, nick),
				el('message-text', {}, text),
			),
		);
	}

	notice(text, at = Date.now()) {
		append_pinned(
			this.#log,
			el('system-notice', {}, el('message-when', {}, clock(at)), text),
		);
	}
}

// ----------------------------------------------------------------- <dm-panel>

class DmPanel extends HTMLElement {
	#dm = null;
	#log = null;
	#header = null;
	#transport = null;
	#input = null;
	#drawn = 0;

	set dm(dm) {
		this.#dm = dm;
		this.setAttribute('peer', dm.peer);
		this.#build();
		// The transport row carries the relay/unrelayed button, which has to
		// follow the choice immediately -- waiting for ICE to settle on a new
		// pair would leave it showing the option you just took.
		dm.addEventListener('state', () => {
			this.#render_header();
			this.#render_transport();
		});
		dm.addEventListener('pair', () => this.#render_transport());
		dm.addEventListener('message', () => this.#render_log());
	}
	get dm() {
		return this.#dm;
	}

	#build() {
		this.#log = el('message-log', { tabindex: '0' });
		this.#header = el('panel-header');
		this.#transport = el('dm-transport');
		this.#input = el('input', {
			type: 'text',
			name: 'text',
			autocomplete: 'off',
			placeholder: 'private message',
		});

		const composer = el(
			'message-composer',
			{},
			el(
				'form',
				{
					onsubmit: (e) => {
						e.preventDefault();
						if (this.#dm.send(this.#input.value)) this.#input.value = '';
					},
				},
				this.#input,
				el('button', { type: 'submit' }, 'send'),
			),
		);

		this.replaceChildren(this.#header, this.#transport, this.#log, composer);
		this.#render_header();
		this.#render_transport();
		this.#render_log();
	}

	#render_header() {
		const dm = this.#dm;
		this.setAttribute('state', dm.state);
		this.toggleAttribute('relayed', dm.relayed);
		this.#input.disabled = dm.state !== 'connected';

		// The same person may be in several puddles under several nicks, and
		// none of those nicks is more real than another.  Show them all.
		const identities = directory.identities(dm.peer);
		this.#header.replaceChildren(
			el('dm-peer', {}, nick_el(dm.peer, directory.nick_of(dm.peer))),
			el(
				'peer-identities',
				{},
				...(identities.length
					? identities.map(({ nick, domain }) =>
						el(
							'peer-identity',
							{ domain },
							`${nick ?? short(dm.peer)}@${domain}`,
						)
					)
					: [
						el(
							'peer-identity',
							{ unknown: true },
							'not in any puddle you are in',
						),
					]),
			),
			el('dm-state', {}, describe_state(dm.state)),
			el('button', {
				type: 'button',
				onclick: () =>
					this.dispatchEvent(
						new CustomEvent('close-dm', { detail: dm.peer, bubbles: true }),
					),
			}, 'close'),
		);
	}

	#render_transport() {
		const dm = this.#dm;
		const kids = [];

		if (dm.pair) {
			const { local, remote } = dm.pair;
			// A local candidate that is not a relay means our address is in the
			// packets they receive.  Say so.
			//
			// A relay candidate gets no reassurance in return, deliberately: a
			// stateless relay can encode an IPv4 address into the IPv6 it hands
			// out, so "relay" is not a promise that nothing leaked.
			const exposed = local && local.type !== 'relay';
			// Only the exposed case gets a hint.  A relay candidate is left
			// unannotated on purpose: a stateless relay can encode an IPv4
			// address into the IPv6 it hands out, so anything reassuring here
			// would be a claim this app cannot make.
			const local_el = exposed
				? el(
					'local-candidate',
					{ type: local?.type ?? 'unknown', exposed: true },
					...hint(
						el('button', { type: 'button' }, format(local)),
						'Not a relayed candidate: the other peer can see this address of yours.',
						'exposure',
					),
				)
				: el(
					'local-candidate',
					{ type: local?.type ?? 'unknown' },
					format(local),
				);
			kids.push(
				el(
					'candidate-pair',
					{},
					local_el,
					el('pair-arrow', {}, '↔'),
					el('remote-candidate', {
						type: remote?.type ?? 'unknown',
					}, format(remote)),
				),
			);
		} else {
			kids.push(el('candidate-pair', { empty: true }, 'no pair selected'));
		}

		if (dm.relayed) {
			kids.push(...hint(
				el(
					'button',
					{ type: 'button', onclick: () => dm.unrelay() },
					'Use unrelayed',
				),
				'Gather your own addresses too, so a direct path can win. Faster and cheaper — and the other peer will see where you are.',
			));
		} else {
			// Deliberately not a way back: Chrome keeps the pair it has already
			// selected, so re-tightening the policy would look like it worked
			// and change nothing.  See DM#unrelay.
			//
			// aria-disabled rather than disabled, because the whole job of this
			// control is now to explain itself, and a disabled button receives
			// no hover or focus to explain itself with.
			kids.push(...hint(
				el(
					'button',
					{ type: 'button', spent: true, 'aria-disabled': 'true' },
					'unrelayed',
				),
				'Already unrelayed. Chrome keeps the pair it has selected, so this cannot be undone here — close this DM and open it again for a relay-only connection.',
				'exposure',
			));
		}

		this.#transport.replaceChildren(...kids);
	}

	#render_log() {
		const dm = this.#dm;
		for (const message of dm.messages.slice(this.#drawn)) {
			append_pinned(
				this.#log,
				el(
					'chat-message',
					{ mine: message.mine },
					el('message-when', {}, clock(message.at)),
					message.mine
						? nick_el(directory.me(), directory.nick_of(directory.me()))
						: nick_el(dm.peer, directory.nick_of(dm.peer)),
					el('message-text', {}, message.text),
				),
			);
		}
		this.#drawn = dm.messages.length;
	}
}

function format(candidate) {
	if (!candidate) return '?';
	return `${candidate.type} ${candidate.address}:${candidate.port}/${candidate.protocol}`;
}

function describe_state(state) {
	return {
		invited: 'waiting for you',
		dialing: 'connecting…',
		connected: 'connected',
		// Not "they declined": a refusal also arrives from a browser that
		// cannot do DMs at all, and claiming the person chose to turn you down
		// would be putting words in their mouth.
		declined: 'declined',
		failed: 'could not connect',
		closed: 'closed',
	}[state] ?? state;
}

// ---------------------------------------------------------------- <dm-invite>

// Someone we have never spoken to sent us a candidate.  Nothing has been
// answered yet -- their candidates are held, not applied -- so declining costs
// them one message and tells them nothing except that we said no.
class DmInvite extends HTMLElement {
	#dm = null;

	set dm(dm) {
		this.#dm = dm;
		this.setAttribute('peer', dm.peer);
		this.toggleAttribute('open', true);
		this.replaceChildren(
			el('invite-title', {}, 'incoming dm'),
			nick_el(dm.peer, directory.nick_of(dm.peer)),
			el(
				'peer-identities',
				{},
				...directory.identities(dm.peer).map(({ nick, domain }) =>
					el('peer-identity', { domain }, `${nick ?? short(dm.peer)}@${domain}`)
				),
			),
			el(
				'invite-actions',
				{},
				el('button', {
					type: 'button',
					onclick: () =>
						this.dispatchEvent(
							new CustomEvent('accept', { detail: dm.peer, bubbles: true }),
						),
				}, 'accept'),
				el('button', {
					type: 'button',
					onclick: () =>
						this.dispatchEvent(
							new CustomEvent('reject', { detail: dm.peer, bubbles: true }),
						),
				}, 'reject'),
			),
		);
	}
	get dm() {
		return this.#dm;
	}
}

customElements.define('peer-nick', PeerNick);
customElements.define('puddle-entry', PuddleEntry);
customElements.define('puddle-pane', PuddlePane);
customElements.define('dm-panel', DmPanel);
customElements.define('dm-invite', DmInvite);
