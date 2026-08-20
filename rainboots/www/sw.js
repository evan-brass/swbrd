// The service worker.
//
// Rainboots is meant to be a thing you have, not a thing you are served.  Once
// it is installed, every file it is built out of comes from the cache and is
// never checked against the network again -- so a puddle you connect to cannot
// change the client you connect with, and neither can whoever is hosting this
// copy.  Bumping VERSION below is the only way an update happens.  That is the
// whole update mechanism, on purpose.
//
// The one exception is your skin, which is yours to change: a stylesheet from
// anywhere on the web, cached separately, refreshed when you ask for it.  The
// page never reads its bytes, so it needs no CORS -- the worker fetches it
// no-cors and stores the opaque response, which is all a <link> needs.

const VERSION = 'rainboots-v1';
const SKIN_CACHE = 'rainboots-skin';

// Resolved against this file's URL, so the app can live at any path.  src/*.js
// sits outside the worker's scope, which does not matter: scope decides which
// *documents* a worker controls, and a controlled document's subresources all
// come through here whatever their path.
const ASSETS = [
	'./',
	'./index.html',
	'./rainboots.css',
	'./app.js',
	'./client.js',
	'./dms.js',
	'./elements.js',
	'./sounds.js',
	'./store.js',
	'../../src/conn.js',
	'../../src/cert.js',
	'../../src/id.js',
	'../../src/util.js',
	'../../src/deter.js',
];

const PRECACHED = new Set(
	ASSETS.map((path) => new URL(path, self.location).href),
);
const INDEX = new URL('./index.html', self.location).href;

self.addEventListener('install', (event) => {
	event.waitUntil((async () => {
		const cache = await caches.open(VERSION);
		await cache.addAll(ASSETS);
		await self.skipWaiting();
	})());
});

self.addEventListener('activate', (event) => {
	event.waitUntil((async () => {
		const stale = (await caches.keys())
			.filter((name) => name !== VERSION && name !== SKIN_CACHE);
		for (const name of stale) await caches.delete(name);
		await self.clients.claim();

		// Only an actual update is worth interrupting for.  A first install has
		// replaced nothing -- there was no older cache to throw away -- and
		// telling a first-time visitor that a new version is ready would be
		// nonsense.
		if (!stale.length) return;
		for (const client of await self.clients.matchAll()) {
			client.postMessage({ op: 'updated', version: VERSION });
		}
	})());
});

self.addEventListener('fetch', (event) => {
	const { request } = event;
	if (request.method !== 'GET') return;

	const url = new URL(request.url);

	if (PRECACHED.has(url.href)) {
		event.respondWith(from_cache(request));
		return;
	}

	// A navigation anywhere in scope is the app: there is only one page.
	if (request.mode === 'navigate') {
		event.respondWith(from_cache(new Request(INDEX)));
		return;
	}

	// Anything else asking to be a stylesheet is a skin.
	if (request.destination === 'style') {
		event.respondWith(skin(request));
		return;
	}

	// Everything else -- there should be nothing -- is left alone.
});

// Cache only, by design.  The network fallback exists for one case: eviction
// under storage pressure, which would otherwise brick the app with no way back.
async function from_cache(request) {
	const cache = await caches.open(VERSION);
	const hit = await cache.match(request);
	if (hit) return hit;
	console.warn('rainboots: asset missing from cache, refetching', request.url);
	const response = await fetch(request);
	if (response.ok) await cache.put(request, response.clone());
	return response;
}

// The skin is cached by its own URL, so switching between two of them keeps
// both and going offline keeps whichever you are wearing.
async function skin(request) {
	const cache = await caches.open(SKIN_CACHE);
	const hit = await cache.match(request);
	if (hit) return hit;
	try {
		const response = await fetch(request);
		// An opaque response is fine to store -- cache.put accepts one, where
		// cache.addAll would reject it for not being ok -- and fine to hand to a
		// <link>, which never needed to read it either.
		await cache.put(request, response.clone());
		return response;
	} catch {
		// Offline with no copy: better a skin that does nothing than a page
		// that fails to load.
		return new Response('', { headers: { 'content-type': 'text/css' } });
	}
}

self.addEventListener('message', (event) => {
	const { op, url } = event.data ?? {};
	if (op === 'refresh-skin' && url) {
		event.waitUntil((async () => {
			let ok = false;
			try {
				const cache = await caches.open(SKIN_CACHE);
				const response = await fetch(url, { mode: 'no-cors', cache: 'reload' });
				await cache.put(url, response);
				ok = true;
			} catch (e) {
				console.warn('rainboots: could not refresh the skin', e);
			}
			event.source?.postMessage({ op: 'skin-refreshed', url, ok });
		})());
	}
	if (op === 'version') {
		event.source?.postMessage({ op: 'version', version: VERSION });
	}
});
