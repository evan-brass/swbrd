#!/usr/bin/env -S deno run --allow-run --allow-net --allow-read --allow-write --allow-env
// Run a tests/*.html page in a real Chrome and turn it into an exit code.
//
//   ./scripts/dev.sh e2e tests/vpn.html
//   ./scripts/dev.sh e2e tests/vpn.html --units=dtls-proxy,swbrd --timeout=45000
//   ./scripts/dev.sh e2e 'tests/vpn.html?sctp_port=5000' --headful --keep-open
//
// We drive Chrome over the DevTools protocol using Deno's built in WebSocket, so there is nothing to
// install and nothing to keep up to date.  The page reports its verdict by logging
// `SWBRD-RESULT {json}` (see tests/harness.js); everything else it logs is streamed through as it
// happens, so a connection that hangs still shows its ICE/DTLS/SCTP state transitions.

const ROOT = new URL('../', import.meta.url).pathname;
const CHROMES = [
	Deno.env.get('CHROME'),
	'/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
	'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
	'/Applications/Chromium.app/Contents/MacOS/Chromium',
	'/usr/bin/google-chrome',
	'/usr/bin/chromium',
];

// ---------------------------------------------------------------- arguments

const opts = {
	timeout: 30_000,
	port: 8000,
	units: [],
	grep: '',
	headful: false,
	keep: false,
	json: false,
	verbose: false,
};
const positional = [];
for (const arg of Deno.args) {
	if (!arg.startsWith('--')) {
		positional.push(arg);
		continue;
	}
	const [key, value] = arg.slice(2).split(/=(.*)/s);
	switch (key) {
		case 'timeout':
			opts.timeout = Number(value);
			break;
		case 'port':
			opts.port = Number(value);
			break;
		case 'units':
			opts.units = value ? value.split(',').filter(Boolean) : [];
			break;
		case 'grep':
			opts.grep = value ?? '';
			break;
		case 'headful':
			opts.headful = true;
			break;
		case 'keep-open':
			opts.keep = true;
			break;
		case 'json':
			opts.json = true;
			break;
		case 'verbose':
			opts.verbose = true;
			break;
		default:
			die(`unknown option --${key}`);
	}
}
const page = positional[0];
if (!page) {
	die(
		'usage: e2e <page> [--units=a,b] [--grep=re] [--timeout=ms] [--port=n] [--headful] [--keep-open] [--json] [--verbose]',
	);
}
const url = /^https?:/.test(page)
	? page
	: `http://localhost:${opts.port}/${page.replace(/^\//, '')}`;

// ---------------------------------------------------------------- output

const colour = Deno.stderr.isTerminal();
const paint = (code, s) => colour ? `\x1b[${code}m${s}\x1b[0m` : s;
function log(tag, text) {
	for (const line of String(text).split('\n')) {
		console.error(`${paint('2;37', `[${tag.padEnd(6)}]`)} ${line}`);
	}
}
function die(message) {
	console.error(paint('1;31', `e2e: ${message}`));
	Deno.exit(2);
}

// ---------------------------------------------------------------- helpers

async function* read_lines(readable) {
	const decoder = new TextDecoder();
	let buffered = '';
	for await (const chunk of readable) {
		buffered += decoder.decode(chunk, { stream: true });
		let i;
		while ((i = buffered.indexOf('\n')) >= 0) {
			yield buffered.slice(0, i);
			buffered = buffered.slice(i + 1);
		}
	}
	if (buffered) yield buffered;
}

async function serving(port) {
	try {
		await fetch(`http://localhost:${port}/`, {
			signal: AbortSignal.timeout(1500),
		});
		return true;
	} catch {
		return false;
	}
}

// Chrome hands console arguments back as RemoteObjects; primitives carry a value, everything else
// only comes with a description or a shallow preview.
function fmt(obj) {
	if (!obj) return '';
	if ('value' in obj) {
		return typeof obj.value == 'string' ? obj.value : JSON.stringify(obj.value);
	}
	if (obj.unserializableValue) return obj.unserializableValue;
	if (obj.preview) return preview(obj.preview);
	return obj.description ?? obj.type;
}
function preview({ subtype, description, properties = [], overflow }) {
	const more = overflow ? ', …' : '';
	if (subtype == 'array') {
		return `[${properties.map((p) => p.value).join(', ')}${more}]`;
	}
	const head = description && description != 'Object' ? description + ' ' : '';
	return `${head}{${
		properties.map((p) => `${p.name}: ${p.value}`).join(', ')
	}${more}}`;
}

// ---------------------------------------------------------------- CDP

class CDP {
	#ws;
	#next = 0;
	#pending = new Map();
	#listeners = new Set();

	static connect(endpoint) {
		return new Promise((resolve, reject) => {
			const cdp = new CDP(new WebSocket(endpoint));
			cdp.#ws.addEventListener('open', () => resolve(cdp), { once: true });
			cdp.#ws.addEventListener(
				'error',
				() => reject(new Error(`cannot reach ${endpoint}`)),
				{
					once: true,
				},
			);
		});
	}

	constructor(ws) {
		this.#ws = ws;
		ws.addEventListener('message', ({ data }) => {
			const message = JSON.parse(data);
			if (message.id !== undefined) {
				const pending = this.#pending.get(message.id);
				if (!pending) return;
				this.#pending.delete(message.id);
				if (message.error) pending.reject(new Error(message.error.message));
				else pending.resolve(message.result);
			} else {
				for (const listener of this.#listeners) listener(message);
			}
		});
	}

	send(method, params = {}, sessionId = undefined) {
		const id = ++this.#next;
		this.#ws.send(JSON.stringify({ id, method, params, sessionId }));
		return new Promise((resolve, reject) =>
			this.#pending.set(id, { resolve, reject })
		);
	}

	on(listener) {
		this.#listeners.add(listener);
	}

	close() {
		try {
			this.#ws.close();
		} catch { /* already gone */ }
	}
}

// ---------------------------------------------------------------- run

const chrome = CHROMES.find((path) =>
	path && (() => {
		try {
			return Deno.statSync(path).isFile;
		} catch {
			return false;
		}
	})()
);
if (!chrome) die('no Chrome found; set $CHROME to the binary');

let file_server;
if (!await serving(opts.port)) {
	log('serve', `starting file-server on ${opts.port}`);
	file_server = new Deno.Command('file-server', {
		args: ['-p', String(opts.port), '--cors', '-H', 'Cache-Control: no-cache'],
		cwd: ROOT,
		stdout: 'null',
		stderr: 'null',
	}).spawn();
	for (let i = 0; i < 20 && !await serving(opts.port); i++) {
		await new Promise((r) => setTimeout(r, 250));
	}
	if (!await serving(opts.port)) {
		die(`file-server never came up on ${opts.port}`);
	}
}

const profile = await Deno.makeTempDir({ prefix: 'swbrd-e2e-' });
const chrome_args = [
	...(opts.headful ? [] : ['--headless=new']),
	'--remote-debugging-port=0',
	`--user-data-dir=${profile}`,
	'--no-first-run',
	'--no-default-browser-check',
	'--disable-background-networking',
	'--disable-sync',
	// getUserMedia without a device, a prompt, or a gesture — needed by tests/audio.html
	'--use-fake-device-for-media-stream',
	'--use-fake-ui-for-media-stream',
	'--autoplay-policy=no-user-gesture-required',
	// show real host candidates instead of mDNS names, so candidate logs are readable
	'--disable-features=WebRtcHideLocalIpsWithMdns',
	'about:blank',
];

log(
	'chrome',
	`${chrome.split('/').pop()}${opts.headful ? '' : ' --headless=new'}`,
);
const browser = new Deno.Command(chrome, {
	args: chrome_args,
	stdout: 'null',
	stderr: 'piped',
})
	.spawn();

let found_endpoint;
const endpoint = new Promise((resolve) => found_endpoint = resolve);
(async () => {
	for await (const line of read_lines(browser.stderr)) {
		const match = /DevTools listening on (ws:\/\/\S+)/.exec(line);
		if (match) found_endpoint(match[1]);
		else if (opts.verbose) log('chrome', line);
	}
})();

const started = Math.floor(Date.now() / 1000);
const began = performance.now();

let settle;
const settled = new Promise((resolve) => settle = resolve);

const cdp = await CDP.connect(
	await Promise.race([
		endpoint,
		new Promise((_, reject) =>
			setTimeout(
				() => reject(new Error('chrome never printed a devtools endpoint')),
				15_000,
			)
		),
	]),
);

cdp.on(({ method, params }) => {
	switch (method) {
		case 'Runtime.consoleAPICalled': {
			const text = params.args.map(fmt).join(' ');
			const result = /^SWBRD-RESULT (\{.*\})$/.exec(text);
			if (result) {
				try {
					return settle(JSON.parse(result[1]));
				} catch {
					return settle({ pass: false, detail: `unparseable result: ${text}` });
				}
			}
			log(params.type == 'error' ? 'error' : 'page', text);
			break;
		}
		case 'Runtime.exceptionThrown': {
			const { exceptionDetails: e } = params;
			log('error', e.exception?.description ?? e.text);
			break;
		}
		case 'Log.entryAdded':
			log('log', `${params.entry.level}: ${params.entry.text}`);
			break;
		case 'Inspector.targetCrashed':
			settle({ pass: false, detail: 'the renderer crashed' });
			break;
	}
});

const { targetId } = await cdp.send('Target.createTarget', {
	url: 'about:blank',
});
const { sessionId } = await cdp.send('Target.attachToTarget', {
	targetId,
	flatten: true,
});
// Enable before navigating so nothing logged during module evaluation is missed.
await cdp.send('Runtime.enable', {}, sessionId);
await cdp.send('Log.enable', {}, sessionId);
await cdp.send('Page.enable', {}, sessionId);

log('nav', url);
const navigation = await cdp.send('Page.navigate', { url }, sessionId);
if (navigation.errorText) {
	settle({ pass: false, detail: `navigation failed: ${navigation.errorText}` });
}

const result = await Promise.race([
	settled,
	new Promise((resolve) =>
		setTimeout(
			() =>
				resolve({ pass: false, detail: `no result within ${opts.timeout}ms` }),
			opts.timeout,
		)
	),
]);
const seconds = ((performance.now() - began) / 1000).toFixed(1);

// ---------------------------------------------------------------- the other half of the loop

for (const unit of opts.units) {
	const { stdout } = await new Deno.Command(`${ROOT}scripts/dev.sh`, {
		args: ['logs', unit, `@${started}`, opts.grep],
		stdout: 'piped',
		stderr: 'null',
	}).output();
	const text = new TextDecoder().decode(stdout).trim();
	if (!text || text.startsWith('-- No entries')) {
		log('turn', `${unit}: no journal entries during the test`);
		continue;
	}
	for (const line of text.split('\n')) log('turn', line);
}

// ---------------------------------------------------------------- teardown

if (!opts.keep) {
	cdp.close();
	try {
		browser.kill();
		await browser.status;
	} catch { /* already exited */ }
	file_server?.kill();
	await Deno.remove(profile, { recursive: true }).catch(() => {});
} else {
	log('keep', `chrome left running with ${profile}; ctrl-c when done`);
	await browser.status;
}

const name = result.name ?? page;
if (opts.json) {
	console.log(
		JSON.stringify({ ...result, name, seconds: Number(seconds), url }),
	);
} else {
	console.error(
		result.pass
			? paint('1;32', `PASS ${name} (${seconds}s)`) +
				(result.detail ? ` ${result.detail}` : '')
			: paint('1;31', `FAIL ${name} (${seconds}s)`) +
				(result.detail ? ` ${result.detail}` : ''),
	);
}
Deno.exit(result.pass ? 0 : 1);
