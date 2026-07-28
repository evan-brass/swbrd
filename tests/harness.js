// Shared plumbing for the pages in this directory.
//
// A page ends by calling pass()/fail() (or by letting deadline() fire).  That prints a
// `SWBRD-RESULT {json}` line, which scripts/e2e.js watches for, and also writes the verdict into the
// DOM so the same file is useful when you just open it in a browser.

const name = location.pathname.split('/').pop() || 'test';
let reported = false;

export const params = new URLSearchParams(location.search);

export function report(pass, detail = '') {
	if (reported) return;
	reported = true;

	const result = { name, pass: Boolean(pass), detail: String(detail ?? '') };
	globalThis.__swbrd_result = result;

	const el = document.createElement('pre');
	el.id = 'swbrd-result';
	el.style.cssText =
		'position:fixed;inset:auto 0 0 0;margin:0;padding:.75em 1em;font:600 14px/1.4 ui-monospace,monospace;' +
		`color:#fff;background:${result.pass ? '#137333' : '#a50e0e'}`;
	el.textContent = `${result.pass ? 'PASS' : 'FAIL'} ${name}${
		result.detail ? ' — ' + result.detail : ''
	}`;
	document.body.append(el);

	// Logged last: scripts/e2e.js tears the browser down as soon as it sees this, so everything the
	// page wants to leave behind has to already be in place.
	console.log('SWBRD-RESULT ' + JSON.stringify(result));

	dispatchEvent(new CustomEvent('swbrd-result', { detail: result }));
	return result;
}

export const pass = (detail) => report(true, detail);
export const fail = (detail) => report(false, detail);

// Fail the page if nothing has reported by then.  Cleared automatically once something does.
export function deadline(ms = 25_000, why = null) {
	const timer = setTimeout(
		() => fail(why ?? `nothing reported within ${ms}ms`),
		ms,
	);
	addEventListener('swbrd-result', () => clearTimeout(timer), { once: true });
	return timer;
}

addEventListener('error', ({ message }) => fail(`uncaught error: ${message}`));
addEventListener(
	'unhandledrejection',
	({ reason }) => fail(`unhandled rejection: ${reason?.message ?? reason}`),
);

// Resolve when the channel opens; reject if it closes or errors first.
export function expect_open(dc, ms = 20_000) {
	if (dc.readyState == 'open') return Promise.resolve(dc);
	return new Promise((resolve, reject) => {
		const timer = setTimeout(
			() =>
				reject(
					new Error(`'${dc.label}' never opened (readyState ${dc.readyState})`),
				),
			ms,
		);
		const done = (fn) => (arg) => {
			clearTimeout(timer);
			fn(arg);
		};
		dc.addEventListener('open', done(() => resolve(dc)), { once: true });
		dc.addEventListener(
			'close',
			done(() => reject(new Error(`'${dc.label}' closed before it opened`))),
			{ once: true },
		);
		dc.addEventListener(
			'error',
			done(({ error }) => reject(error ?? new Error('datachannel error'))),
			{ once: true },
		);
	});
}

// Resolve when the peer connection reaches 'connected'; reject on 'failed' / 'closed'.
export function expect_connected(conn, ms = 20_000) {
	if (conn.connectionState == 'connected') return Promise.resolve(conn);
	return new Promise((resolve, reject) => {
		const timer = setTimeout(
			() =>
				reject(new Error(`connectionState stuck at '${conn.connectionState}'`)),
			ms,
		);
		conn.addEventListener('connectionstatechange', () => {
			if (conn.connectionState == 'connected') {
				clearTimeout(timer);
				resolve(conn);
			} else if (
				conn.connectionState == 'failed' || conn.connectionState == 'closed'
			) {
				clearTimeout(timer);
				reject(new Error(`connectionState went to '${conn.connectionState}'`));
			}
		});
	});
}

// A short description of what ICE actually picked, for the pass detail line.
export function selected(conn) {
	const pair = conn.sctp?.transport?.iceTransport?.getSelectedCandidatePair?.();
	if (!pair?.remote) return '';
	return `via ${pair.remote.address}:${pair.remote.port} (${pair.remote.type})`;
}

// Every state transition of every connection, prefixed with a key so two peers stay distinguishable.
// Lifted out of index.html — this is the running commentary you want when a connection hangs.
export function log_everything(conns) {
	for (const key in conns) {
		watch(key, conns[key]).catch((e) => console.warn(key, 'logger gave up', e));
	}
}

// Events are summarised rather than dumped: a raw RTCPeerConnectionIceErrorEvent is a wall of text,
// and `701 Server returned error <turns:…:443>` is the part you actually wanted.
const describe = {
	icecandidate: ({ candidate }) =>
		candidate?.candidate ?? '(end of candidates)',
	candidate: ({ candidate }) => candidate?.candidate ?? '(end of candidates)',
	icecandidateerror: ({ errorCode, errorText, url }) =>
		`${errorCode} ${errorText} <${url}>`,
	datachannel: ({ channel }) => `label='${channel.label}' id=${channel.id}`,
	track: ({ track }) => `${track.kind} ${track.id}`,
	negotiationneeded: () => '',
	message: ({ data }) =>
		typeof data == 'string'
			? data.length > 200 ? data.slice(0, 200) + '…' : data
			: `${data.byteLength} bytes`,
	open: () => '',
	close: () => '',
};

function candidate_pair(pair) {
	if (!pair) return '(none)';
	return `${pair.local?.candidate ?? '?'}  ->  ${
		pair.remote?.candidate ?? '?'
	}`;
}

async function watch(key, conn) {
	function ondc({ channel }) {
		['message', 'open', 'close'].forEach((e) =>
			channel.addEventListener(
				e,
				(ev) => console.log(key, `dc[${channel.label}]`, e, describe[e](ev)),
			)
		);
	}
	if (conn.dc) ondc({ channel: conn.dc });

	[
		'connectionState',
		'iceConnectionState',
		'iceGatheringState',
		'signalingState',
	].forEach((p) =>
		conn.addEventListener(
			p.toLowerCase() + 'change',
			({ target: { [p]: val } }) => console.log(key, p, val),
		)
	);

	[
		'icecandidate',
		'candidate',
		'datachannel',
		'icecandidateerror',
		'negotiationneeded',
		'track',
	].forEach((e) =>
		conn.addEventListener(e, (ev) => {
			console.log(key, e, describe[e](ev));
			if (e == 'datachannel') ondc(ev);
		})
	);

	while (!conn.sctp) {
		if (conn.connectionState == 'closed') return;
		await new Promise((res) =>
			conn.addEventListener('signalingstatechange', res, { once: true })
		);
	}
	conn.sctp.addEventListener(
		'statechange',
		({ target: { state } }) => console.log(key, 'sctp state', state),
	);
	conn.sctp.transport.addEventListener(
		'error',
		({ error }) => console.log(key, 'dtls error', error),
	);
	conn.sctp.transport.iceTransport.addEventListener(
		'gatheringstatechange',
		({ target: { gatheringState } }) =>
			console.log(key, 'ice gatheringState', gatheringState),
	);
	conn.sctp.transport.iceTransport.addEventListener(
		'statechange',
		({ target: { state } }) => console.log(key, 'ice state', state),
	);
	conn.sctp.transport.iceTransport.addEventListener(
		'selectedcandidatepairchange',
		({ target }) =>
			console.log(
				key,
				'ice selected',
				candidate_pair(target.getSelectedCandidatePair()),
			),
	);
}
