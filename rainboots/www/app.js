// Rainboots: pick your boots, splash in whichever puddles you like.
//
// This file is the wiring.  It owns one PuddleClient per domain in the server
// list -- all of them connected at once -- one global DM registry keyed by peer
// id, and the handful of forms that let you change any of that.

import { cert } from 'swbrd/cert.js';
import { PuddleClient, short } from './client.js';
import { DirectMessages, DM_SUPPORTED } from './dms.js';
import { el, nick_el, set_directory } from './elements.js';
import { set_enabled, sounds } from './sounds.js';
import { store } from './store.js';

const me = String(cert.id);

const root = document.querySelector('rainboots-app');
const header = el('app-header');
const sidebar = el('app-sidebar');
const puddle_list = el('puddle-list');
const dm_list = el('dm-list');
const main = el('app-main');
const tray = el('invite-tray');
const settings = el('settings-panel');

const clients = new Map(); // domain -> PuddleClient
const entries = new Map(); // domain -> <puddle-entry>
const panes = new Map(); // domain -> <puddle-pane>
const dm_panels = new Map(); // peer id -> <dm-panel>
const invites = new Map(); // peer id -> <dm-invite>

let current = null; // { kind: 'puddle' | 'dm', key }

// ------------------------------------------------------------------- unread

// 'puddle:<domain>' or 'dm:<peer>' -> how many messages have arrived that you
// have not been shown.
const unread = new Map();

const view_key = (kind, id) => `${kind}:${id}`;

// A message counts as read only if you could actually have read it: the right
// view, in front, in a window that has focus.  A backgrounded tab is not
// reading, however much of it is on screen.
function watching(kind, id) {
	return current?.kind === kind && current.key === id &&
		document.visibilityState === 'visible' && document.hasFocus();
}

function mark_unread(kind, id, sound) {
	if (watching(kind, id)) return;
	const key = view_key(kind, id);
	unread.set(key, (unread.get(key) ?? 0) + 1);
	sound?.();
	refresh_unread();
}

function clear_unread(kind, id) {
	if (!unread.delete(view_key(kind, id))) return;
	refresh_unread();
}

function refresh_unread() {
	for (const [domain, entry] of entries) {
		entry.unread = unread.get(view_key('puddle', domain)) ?? 0;
	}
	render_dm_list();

	// The sum in the title, the way every chat app does it.  Pending invitations
	// count: an unanswered one is the most attention-worthy thing here, and its
	// popup is invisible from another tab.
	const total = [...unread.values()].reduce((a, b) => a + b, 0) + invites.size;
	document.title = total ? `(${total}) rainboots` : 'rainboots';
}

// Coming back to the window reads whatever you are already looking at.
for (const event of ['focus', 'visibilitychange']) {
	addEventListener(event, () => {
		if (current && watching(current.kind, current.key)) {
			clear_unread(current.kind, current.key);
		}
	});
}

// ------------------------------------------------------------------ identity

// Who a peer is, gathered across every puddle we are in.  There is no
// authoritative answer -- each puddle names people independently, and any of
// them may be lying -- so the honest thing is to show all of the answers.
function identities(peer) {
	const out = [];
	for (const client of clients.values()) {
		if (!client.knows(peer)) continue;
		out.push({ domain: client.domain, nick: client.nick_of(peer) });
	}
	return out;
}

function nick_of(peer) {
	for (const client of clients.values()) {
		const nick = client.nick_of(peer);
		if (nick) return nick;
	}
	return null;
}

set_directory({ identities, nick_of, me: () => me });

// ----------------------------------------------------------------------- DMs

// Send one signal toward `peer` through a puddle that can actually see them.
//
// Only puddles whose roster has them: a puddle drops a signal addressed to
// somebody it does not know, and spraying the attempt at every puddle we are in
// would tell each of them who we are trying to reach for no benefit.
function route(peer, candidate) {
	let sent = false;
	for (const client of clients.values()) {
		if (!client.connected || !client.knows(peer)) continue;
		if (client.signal(peer, candidate)) sent = true;
	}
	return sent;
}

const dms = new DirectMessages(route);

dms.addEventListener('invite', ({ detail: dm }) => {
	const invite = el('dm-invite');
	invite.dm = dm;
	invites.set(dm.peer, invite);
	tray.append(invite);
	// Always audible, unlike a message: there is no view you could have been
	// watching that would mean you had already seen this.
	sounds.invite();
	refresh_unread();
});

dms.addEventListener('said', ({ detail: { dm, message } }) => {
	if (message.mine) return;
	mark_unread('dm', dm.peer, sounds.dm);
});

dms.addEventListener('change', ({ detail: dm }) => {
	if (dm?.state === 'declined') sounds.declined();
	render_dm_list();
});

// ------------------------------------------------------------------- puddles

function add_client(domain) {
	if (clients.has(domain)) return clients.get(domain);

	const client = new PuddleClient(domain);
	clients.set(domain, client);

	const entry = el('puddle-entry', {
		onclick: () => select('puddle', domain),
	});
	entry.client = client;
	entries.set(domain, entry);
	puddle_list.append(entry);

	const pane = el('puddle-pane');
	pane.client = client;
	panes.set(domain, pane);
	main.append(pane);

	client.addEventListener('state', () => {
		if (client.connected) {
			// Take our name back as soon as there is somewhere to take it.
			const login = store.login(domain);
			if (login) client.claim_nick(login.nick, login.password);
		}
		render_dm_list();
	});
	client.addEventListener('roster', () => {
		render_dm_list();
		refresh_dm_headers();
	});
	client.addEventListener(
		'login',
		({ detail }) => store.set_login(domain, detail.nick, detail.password),
	);
	// A candidate for us, from anywhere, belongs to the one connection we have
	// with that person.
	client.addEventListener('signal', ({ detail }) => {
		if (detail.to !== client.me) return;
		dms.incoming(detail.from, detail.candidate);
	});
	// Only what somebody said, not the joins and parts and nick changes: a badge
	// you cannot clear by reading anything is just a badge.
	client.addEventListener('msg', ({ detail }) => {
		if (detail.from === client.me) return;
		mark_unread('puddle', domain, sounds.message);
	});

	client.start();
	if (!current) select('puddle', domain);
	return client;
}

function remove_client(domain) {
	const client = clients.get(domain);
	if (!client) return;
	client.stop();
	clients.delete(domain);
	panes.get(domain)?.remove();
	panes.delete(domain);
	entries.get(domain)?.remove();
	entries.delete(domain);
	unread.delete(view_key('puddle', domain));
	if (current?.kind === 'puddle' && current.key === domain) {
		current = null;
		const next = clients.keys().next();
		if (!next.done) select('puddle', next.value);
	}
	render_dm_list();
}

// -------------------------------------------------------------------- views

function select(kind, key) {
	current = { kind, key };
	for (const [domain, pane] of panes) {
		pane.toggleAttribute('current', kind === 'puddle' && domain === key);
	}
	for (const [peer, panel] of dm_panels) {
		panel.toggleAttribute('current', kind === 'dm' && peer === key);
	}
	for (const entry of puddle_list.children) {
		entry.toggleAttribute(
			'current',
			kind === 'puddle' && entry.getAttribute('domain') === key,
		);
	}
	for (const entry of dm_list.children) {
		entry.toggleAttribute(
			'current',
			kind === 'dm' && entry.getAttribute('peer') === key,
		);
	}
	settings.toggleAttribute('open', false);
	clear_unread(kind, key);
}

function open_dm(peer) {
	const dm = dms.open(peer);
	if (!dm) return null;
	show_dm(dm);
	if (!route_reachable(peer)) {
		panes.get(current?.key)?.notice?.(
			`${short(peer)} is not in any puddle you are in`,
		);
	}
	return dm;
}

function route_reachable(peer) {
	for (const client of clients.values()) {
		if (client.connected && client.knows(peer)) return true;
	}
	return false;
}

function show_dm(dm) {
	let panel = dm_panels.get(dm.peer);
	if (!panel) {
		panel = el('dm-panel');
		panel.dm = dm;
		dm_panels.set(dm.peer, panel);
		main.append(panel);
	}
	render_dm_list();
	select('dm', dm.peer);
}

function render_dm_list() {
	dm_list.replaceChildren(...Array.from(dms.all.values(), (dm) => {
		const count = unread.get(view_key('dm', dm.peer)) ?? 0;
		return el(
			'dm-entry',
			{
				peer: dm.peer,
				state: dm.state,
				unread: count > 0,
				current: current?.kind === 'dm' && current.key === dm.peer,
				onclick: () => show_dm(dm),
			},
			nick_el(dm.peer, nick_of(dm.peer)),
			el('dm-state', {}, dm.state),
			...(count ? [el('unread-count', {}, String(count))] : []),
		);
	}));
}

function refresh_dm_headers() {
	// Nicks are per puddle and change under us; the panels quote them.
	for (const panel of dm_panels.values()) {
		const dm = panel.dm;
		panel.dm = dm;
	}
	for (const invite of invites.values()) {
		invite.dm = invite.dm;
	}
}

// --------------------------------------------------------------- interaction

root.addEventListener('dm', ({ detail }) => open_dm(detail));

root.addEventListener('accept', ({ detail: peer }) => {
	invites.get(peer)?.remove();
	invites.delete(peer);
	const dm = dms.accept(peer);
	if (dm) show_dm(dm);
	refresh_unread();
});

root.addEventListener('reject', ({ detail: peer }) => {
	invites.get(peer)?.remove();
	invites.delete(peer);
	dms.reject(peer);
	dm_panels.get(peer)?.remove();
	dm_panels.delete(peer);
	unread.delete(view_key('dm', peer));
	refresh_unread();
});

root.addEventListener('close-dm', ({ detail: peer }) => {
	dms.forget(peer);
	dm_panels.get(peer)?.remove();
	dm_panels.delete(peer);
	unread.delete(view_key('dm', peer));
	const next = clients.keys().next();
	if (!next.done) select('puddle', next.value);
	refresh_unread();
});

// ------------------------------------------------------------------- header

function render_header() {
	header.replaceChildren(
		el('app-title', {}, 'rainboots'),
		el('my-identity', {}, 'you are ', nick_el(me, null)),
		el('button', {
			type: 'button',
			onclick: () => settings.toggleAttribute('open'),
		}, 'settings'),
	);
}

// ----------------------------------------------------------------- settings

function render_settings() {
	const domain_input = el('input', {
		type: 'text',
		name: 'domain',
		placeholder: 'puddle.example.net',
		autocomplete: 'off',
	});
	const puddle_form = el(
		'puddle-form',
		{},
		el('form-title', {}, 'puddles'),
		el(
			'form',
			{
				onsubmit: (e) => {
					e.preventDefault();
					try {
						if (store.add_puddle(domain_input.value)) {
							add_client(domain_input.value.trim().toLowerCase());
							domain_input.value = '';
						}
					} catch (err) {
						domain_input.setCustomValidity(err.message);
						domain_input.reportValidity();
						setTimeout(() => domain_input.setCustomValidity(''), 2000);
					}
				},
			},
			domain_input,
			el('button', { type: 'submit' }, 'add'),
		),
		el(
			'puddle-known',
			{},
			...store.puddles.map((domain) =>
				el(
					'puddle-known-entry',
					{ domain },
					el('puddle-domain', {}, domain),
					el('button', {
						type: 'button',
						onclick: () => {
							store.remove_puddle(domain);
							remove_client(domain);
							render_settings();
						},
					}, 'leave'),
				)
			),
		),
	);

	const which = el(
		'select',
		{ name: 'domain' },
		...store.puddles.map((domain) => el('option', { value: domain }, domain)),
	);
	const nick_input = el('input', {
		type: 'text',
		name: 'nick',
		placeholder: 'nick',
		autocomplete: 'off',
	});
	const password_input = el('input', {
		type: 'password',
		name: 'password',
		placeholder: 'password',
		autocomplete: 'off',
	});
	const nick_form = el(
		'nick-form',
		{},
		el('form-title', {}, 'nick'),
		el(
			'form-note',
			{},
			'A nick is a claim, not a credential: the puddle hands them out and could ' +
				'hand yours to someone else. The peer id under every nick is the part it ' +
				'cannot forge — hover one to see it. The password is what lets you take ' +
				'your nick back from another browser, and it is kept in this browser’s ' +
				'localStorage.',
		),
		el(
			'form',
			{
				onsubmit: (e) => {
					e.preventDefault();
					const client = clients.get(which.value);
					if (!client) return;
					client.claim_nick(nick_input.value, password_input.value);
					password_input.value = '';
				},
			},
			which,
			nick_input,
			password_input,
			el('button', { type: 'submit' }, 'claim'),
		),
	);

	const skin_input = el('input', {
		type: 'url',
		name: 'skin',
		placeholder: 'https://example.net/boots.css',
		value: store.skin,
		autocomplete: 'off',
	});
	const skin_form = el(
		'skin-form',
		{},
		el('form-title', {}, 'skin'),
		el(
			'form-note',
			{},
			'Any stylesheet on the web. It is cached for offline use without ever being ' +
				'read by this page, so it needs no CORS headers — only the right content ' +
				'type (text/css).',
		),
		el(
			'form',
			{
				onsubmit: (e) => {
					e.preventDefault();
					store.set_skin(skin_input.value);
					apply_skin(store.skin);
				},
			},
			skin_input,
			el('button', { type: 'submit' }, 'wear'),
			el('button', {
				type: 'button',
				onclick: () => refresh_skin(store.skin),
			}, 'refresh'),
			el('button', {
				type: 'button',
				onclick: () => {
					store.set_skin('');
					skin_input.value = '';
					apply_skin('');
				},
			}, 'bare feet'),
		),
	);

	const sound_toggle = el('input', { type: 'checkbox', name: 'sound' });
	sound_toggle.checked = store.sound;
	sound_toggle.addEventListener('change', () => {
		store.set_sound(sound_toggle.checked);
		set_enabled(store.sound);
		if (store.sound) sounds.message();
	});
	const sound_form = el(
		'sound-form',
		{},
		el('form-title', {}, 'sound'),
		el(
			'form-note',
			{},
			'Short blips for a message you have not seen, and a longer one for an ' +
				'incoming dm. Nothing is downloaded to play them — they are a couple ' +
				'of oscillators each, made up on the spot.',
		),
		el('label', {}, sound_toggle, ' play notification sounds'),
	);

	const identity = el(
		'identity-note',
		{},
		el('form-title', {}, 'identity'),
		el(
			'form-note',
			{},
			'You are the certificate in this browser: ',
			el('peer-id', {}, me),
			'. The same id in every puddle, which is what lets a DM find you wherever ' +
				'you met — and equally what lets two puddles work out that you are the ' +
				'same person.',
		),
	);

	settings.replaceChildren(
		puddle_form,
		nick_form,
		skin_form,
		sound_form,
		identity,
	);
}

store.addEventListener('change', () => {
	if (settings.hasAttribute('open')) render_settings();
});

// --------------------------------------------------------------------- skin

function apply_skin(url) {
	document.querySelector('link[data-skin]')?.remove();
	if (!url) return;
	const link = el('link', { rel: 'stylesheet', href: url, 'data-skin': true });
	link.addEventListener(
		'error',
		() => console.warn(`skin ${url} would not load`),
	);
	document.head.append(link);
}

// The out-of-band path: the worker re-fetches the skin and replaces its cache
// entry, then we rebuild the <link> so the page picks the new bytes up.  This
// is the only thing in Rainboots that updates without changing the worker.
async function refresh_skin(url) {
	if (!url) return;
	const worker = navigator.serviceWorker?.controller;
	if (!worker) {
		apply_skin('');
		apply_skin(url);
		return;
	}
	worker.postMessage({ op: 'refresh-skin', url });
}

// A page that listens with addEventListener rather than the onmessage setter
// has its worker messages queued until it asks for them.  Without this the
// skin-refreshed and updated notices below would never arrive.
navigator.serviceWorker?.startMessages();

navigator.serviceWorker?.addEventListener('message', ({ data }) => {
	if (data?.op === 'skin-refreshed' && data.url === store.skin) {
		apply_skin('');
		apply_skin(store.skin);
	}
	if (data?.op === 'updated') {
		tray.append(
			el(
				'update-notice',
				{ open: true },
				'a new version of rainboots is installed',
				el(
					'button',
					{ type: 'button', onclick: () => location.reload() },
					'reload',
				),
			),
		);
	}
});

// --------------------------------------------------------------------- start

root.replaceChildren(header, sidebar, main, tray, settings);
sidebar.replaceChildren(
	el('sidebar-heading', {}, 'puddles'),
	puddle_list,
	el('sidebar-heading', {}, 'dms'),
	...(DM_SUPPORTED ? [] : [
		el(
			'dm-unsupported',
			{},
			'Direct messages need Chrome. They are built out of ICE candidates ' +
				'paired in a way only Chrome allows, so one made here could never ' +
				'connect. Anyone who calls you is turned down straight away.',
		),
	]),
	dm_list,
);
render_header();
render_settings();
apply_skin(store.skin);
set_enabled(store.sound);
refresh_unread();

for (const domain of store.puddles) add_client(domain);

if ('serviceWorker' in navigator) {
	// updateViaCache 'none' so the worker script itself is the one thing that is
	// still checked against the network -- everything else is served from the
	// cache forever, and changing this file is how a release happens.
	navigator.serviceWorker.register('./sw.js', { updateViaCache: 'none' })
		.catch((e) => console.warn('no service worker:', e.message ?? e));
}
