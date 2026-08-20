// Everything Rainboots remembers about you, which is deliberately little: which
// puddles to join, what to call yourself in each, and where your skin lives.
//
// Your identity is not here.  That is the certificate in IndexedDB that
// src/cert.js manages, and the peer id derived from it -- the same id in every
// puddle, which is what makes a DM findable no matter where you met someone,
// and equally what makes you linkable across puddles.  There is no way to have
// the first property without the second.

const KEY = 'rainboots';

const defaults = () => ({
	puddles: ['turn.evan-brass.net'],
	// domain -> { nick, password }
	logins: {},
	skin: '',
	sound: true,
});

function read() {
	try {
		const stored = JSON.parse(localStorage.getItem(KEY) ?? 'null');
		if (!stored || typeof stored != 'object') return defaults();
		return { ...defaults(), ...stored };
	} catch {
		return defaults();
	}
}

class Store extends EventTarget {
	#state = read();

	get puddles() {
		return this.#state.puddles.slice();
	}
	get skin() {
		return this.#state.skin;
	}
	get sound() {
		return this.#state.sound !== false;
	}

	login(domain) {
		return this.#state.logins[domain] ?? null;
	}

	add_puddle(domain) {
		domain = String(domain).trim().toLowerCase();
		// A puddle is a domain and nothing else: no scheme, no path, no port
		// smuggled in, because this string goes straight to Conn.to_domain.
		if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
			throw new Error(`${domain} is not a domain name`);
		}
		if (this.#state.puddles.includes(domain)) return false;
		this.#state.puddles.push(domain);
		this.#save();
		return true;
	}

	remove_puddle(domain) {
		const at = this.#state.puddles.indexOf(domain);
		if (at < 0) return false;
		this.#state.puddles.splice(at, 1);
		delete this.#state.logins[domain];
		this.#save();
		return true;
	}

	// Kept in plain localStorage, because a nick you have to retype on every
	// reload is a nick you stop using.  Anything with access to this origin can
	// read it; it protects a name, not a secret.
	set_login(domain, nick, password) {
		this.#state.logins[domain] = { nick, password };
		this.#save();
	}

	forget_login(domain) {
		delete this.#state.logins[domain];
		this.#save();
	}

	set_sound(on) {
		this.#state.sound = Boolean(on);
		this.#save();
	}

	set_skin(url) {
		this.#state.skin = String(url ?? '').trim();
		this.#save();
	}

	#save() {
		try {
			localStorage.setItem(KEY, JSON.stringify(this.#state));
		} catch (e) {
			console.warn('could not save settings:', e);
		}
		this.dispatchEvent(new CustomEvent('change'));
	}
}

export const store = new Store();
