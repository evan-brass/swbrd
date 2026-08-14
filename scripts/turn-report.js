#!/usr/bin/env -S deno run --allow-run=ssh --allow-read=reports --allow-write=reports --allow-net=registry.npmjs.org
// Snapshot who's using turn.evan-brass.net and how much they're moving, without the
// `netstat -WnutS` + paste-each-IP-into-bgp.he.net routine.
//
//   ./scripts/turn-report.js                 # append one snapshot to reports/turn-report.jsonl
//   ./scripts/turn-report.js --no-geoip       # skip the local GeoLite2 lookups
//   ./scripts/turn-report.js --quiet          # only errors on stderr, no summary
//
// Run this from the repo root (the default --out/--geoip-dir paths, and the --allow-read/write
// permissions above, are relative to it -- same assumption scripts/e2e.js makes about serving
// from ROOT).
//
// Pulls one bundle of read-only diagnostics over `ssh turn 'sudo -n sh -s'`:
//   - `ss` sessions on :3478 (real client IP, since every client gets its own connected socket --
//     see etc/nftables.conf's turn_acct table for why byte accounting doesn't need conntrack)
//   - the turn_acct per-client counters and santa's abuse-list sizes, both via `nft -j list`
//   - aggregate rx/tx on the turnserver TUN device
//   - systemd health for the four daemons
// then resolves country/ASN for each client IP against local MaxMind GeoLite2 databases (never
// sent off-box -- ip-api.com's free tier 403s requests from the VPS itself anyway) and appends one
// JSON object to the report file.

import { Reader } from 'npm:mmdb-lib@2.2.1';
import { Buffer } from 'node:buffer';

// ---------------------------------------------------------------- output

const colour = Deno.stderr.isTerminal();
const paint = (code, s) => colour ? `\x1b[${code}m${s}\x1b[0m` : s;
function say(s) {
	if (!opts.quiet) console.error(paint('1;34', '==>'), s);
}
function warn(s) {
	console.error(paint('1;33', '!!!'), s);
}
function die(message) {
	console.error(paint('1;31', `turn-report: ${message}`));
	Deno.exit(1);
}

// ---------------------------------------------------------------- arguments

const opts = {
	out: 'reports/turn-report.jsonl',
	geoipDir: 'reports/geoip',
	geoip: true,
	quiet: false,
};
for (const arg of Deno.args) {
	if (!arg.startsWith('--')) die(`unexpected argument: ${arg}`);
	const [key, value] = arg.slice(2).split(/=(.*)/s);
	switch (key) {
		case 'out':
			opts.out = value;
			break;
		case 'geoip-dir':
			opts.geoipDir = value;
			break;
		case 'no-geoip':
			opts.geoip = false;
			break;
		case 'quiet':
			opts.quiet = true;
			break;
		default:
			die(`unknown option --${key}`);
	}
}

// ---------------------------------------------------------------- collection

const REMOTE_SCRIPT = `set -e
echo ===SESSIONS===
ss -tunH 'sport = :3478'
echo ===ACCT===
/usr/sbin/nft -j list table inet turn_acct
echo ===ABUSE===
/usr/sbin/nft -j list table inet santa
echo ===LINK===
ip -s -j link show turnserver
echo ===HEALTH===
systemctl show turnserver dtls-proxy ice-dissolve swbrd -p ActiveState,SubState,NRestarts,MemoryCurrent,CPUUsageNSec,TasksCurrent
`;

say('collecting from turn');
const proc = new Deno.Command('ssh', {
	args: ['turn', 'sudo -n sh -s'],
	stdin: 'piped',
	stdout: 'piped',
	stderr: 'piped',
}).spawn();
{
	const w = proc.stdin.getWriter();
	await w.write(new TextEncoder().encode(REMOTE_SCRIPT));
	await w.close();
}
const { code, stdout, stderr } = await proc.output();
if (code !== 0) {
	die(
		`ssh turn failed (${code}): ${new TextDecoder().decode(stderr).trim()}\n` +
			`(if this is "No such file or directory" on turn_acct, deploy it first: ./scripts/dev.sh nft)`,
	);
}

// Split into raw text chunks per marker, blank lines intact -- systemctl show below uses blank
// lines as its own per-unit block separator, so stripping them here would merge every unit's
// properties into one (with later units silently overwriting earlier ones' values).
const sections = {};
{
	const parts = new TextDecoder().decode(stdout).split(/^===(\w+)===\n/m);
	for (let i = 1; i < parts.length; i += 2) {
		sections[parts[i]] = parts[i + 1] ?? '';
	}
}

// ---------------------------------------------------------------- parsing

// "1.2.3.4:5678" or "[::ffff:1.2.3.4]:5678" or "[2001:db8::1]:5678" -> {ip, port}
function parseAddrPort(token) {
	const bracketed = token.match(/^\[(.+)\]:(\d+)$/);
	const [addr, port] = bracketed ? [bracketed[1], bracketed[2]] : [
		token.slice(0, token.lastIndexOf(':')),
		token.slice(token.lastIndexOf(':') + 1),
	];
	return { ip: normalizeIp(addr), port: Number(port) };
}

// Fold IPv4-mapped IPv6 (::ffff:1.2.3.4) down to plain IPv4 so a client isn't split across two
// map entries depending on which record happened to show the mapped form.
function normalizeIp(ip) {
	const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
	return m ? m[1] : ip;
}

function parseSessions(text) {
	const out = [];
	for (const line of text.split('\n')) {
		if (line.trim().length === 0) continue;
		// Netid State Recv-Q Send-Q Local:Port Peer:Port [...]
		const cols = line.trim().split(/\s+/);
		if (cols.length < 6) {
			warn(`unrecognized ss line, skipping: ${line}`);
			continue;
		}
		const [proto, state, , , , peer] = cols;
		out.push({ proto, state, ...parseAddrPort(peer) });
	}
	return out;
}

function nftSets(text) {
	const doc = JSON.parse(text);
	const sets = new Map();
	for (const item of doc.nftables ?? []) {
		if (item.set) sets.set(item.set.name, item.set.elem ?? []);
	}
	return sets;
}

function counterFor(elem) {
	if (typeof elem === 'string') return { val: elem, packets: 0, bytes: 0 };
	const e = elem.elem;
	return {
		val: e.val,
		packets: e.counter?.packets ?? 0,
		bytes: e.counter?.bytes ?? 0,
	};
}

function linkStats(text) {
	const [link] = JSON.parse(text);
	const s = link?.stats64 ?? {};
	return {
		rx_bytes: s.rx?.bytes ?? 0,
		rx_packets: s.rx?.packets ?? 0,
		tx_bytes: s.tx?.bytes ?? 0,
		tx_packets: s.tx?.packets ?? 0,
	};
}

// systemctl show prints one blank-line-separated key=value block per unit, in argv order --
// it doesn't label which block belongs to which unit.
function parseHealth(text, units) {
	const blocks = text.split(/\n\s*\n/).filter((b) => b.trim());
	const health = {};
	units.forEach((unit, i) => {
		const props = {};
		for (const line of (blocks[i] ?? '').split('\n')) {
			const eq = line.indexOf('=');
			if (eq < 0) continue;
			const key = line.slice(0, eq);
			const raw = line.slice(eq + 1);
			props[key] = raw === '' || raw === '[not set]'
				? null
				: (/^\d+$/.test(raw) ? Number(raw) : raw);
		}
		health[unit] = {
			active_state: props.ActiveState ?? null,
			sub_state: props.SubState ?? null,
			n_restarts: props.NRestarts ?? null,
			memory_bytes: props.MemoryCurrent ?? null,
			cpu_ns: props.CPUUsageNSec ?? null,
			tasks: props.TasksCurrent ?? null,
		};
	});
	return health;
}

const sessions = parseSessions(sections.SESSIONS ?? '');
const acctSets = nftSets(sections.ACCT ?? '{}');
const abuseSets = nftSets(sections.ABUSE ?? '{}');
const turnserverLink = linkStats(sections.LINK ?? '[]');
const health = parseHealth(sections.HEALTH ?? '', [
	'turnserver',
	'dtls-proxy',
	'ice-dissolve',
	'swbrd',
]);

// ---------------------------------------------------------------- reconcile by client IP

const clients = new Map();
function client(ip) {
	let c = clients.get(ip);
	if (!c) {
		c = {
			ip,
			sessions: [],
			bytes_in: 0,
			packets_in: 0,
			bytes_out: 0,
			packets_out: 0,
			abuse: { naughty_listed: false, rst_meter_hits: null },
			geo: null,
		};
		clients.set(ip, c);
	}
	return c;
}

for (const s of sessions) {
	client(s.ip).sessions.push({
		proto: s.proto,
		peer_port: s.port,
		state: s.state,
	});
}
for (const name of ['in4', 'in6']) {
	for (const raw of acctSets.get(name) ?? []) {
		const { val, packets, bytes } = counterFor(raw);
		Object.assign(client(normalizeIp(val)), {
			bytes_in: bytes,
			packets_in: packets,
		});
	}
}
for (const name of ['out4', 'out6']) {
	for (const raw of acctSets.get(name) ?? []) {
		const { val, packets, bytes } = counterFor(raw);
		Object.assign(client(normalizeIp(val)), {
			bytes_out: bytes,
			packets_out: packets,
		});
	}
}
// santa's naughty_list/rst_meter are box-wide RST-flood tracking, not TURN-specific (nginx's own
// proxy churn trips it too -- see the comment in etc/nftables.conf). Only annotate IPs that are
// already TURN clients from ss/turn_acct above; don't let unrelated RST-flood sources masquerade
// as clients here.
for (const raw of abuseSets.get('naughty_list') ?? []) {
	const ip = normalizeIp(counterFor(raw).val);
	if (clients.has(ip)) clients.get(ip).abuse.naughty_listed = true;
}
for (const raw of abuseSets.get('rst_meter') ?? []) {
	const { val, packets } = counterFor(raw);
	const ip = normalizeIp(val);
	if (clients.has(ip)) clients.get(ip).abuse.rst_meter_hits = packets;
}

// ---------------------------------------------------------------- geoip (local, offline)

let geoipStatus = 'disabled';
if (opts.geoip) {
	const countryPath = `${opts.geoipDir}/GeoLite2-Country.mmdb`;
	const asnPath = `${opts.geoipDir}/GeoLite2-ASN.mmdb`;
	try {
		const countryReader = new Reader(
			Buffer.from(Deno.readFileSync(countryPath)),
		);
		const asnReader = new Reader(Buffer.from(Deno.readFileSync(asnPath)));
		for (const c of clients.values()) {
			try {
				const geo = countryReader.get(c.ip);
				const asn = asnReader.get(c.ip);
				const country = geo?.country ?? geo?.registered_country;
				c.geo = {
					country: country?.iso_code ?? null,
					country_name: country?.names?.en ?? null,
					asn: asn?.autonomous_system_number ?? null,
					asn_name: asn?.autonomous_system_organization ?? null,
				};
			} catch {
				// leave c.geo null for this one IP; not fatal
			}
		}
		geoipStatus = 'ok';
	} catch (e) {
		warn(
			`geoip unavailable (${e.message}) -- place GeoLite2-{Country,ASN}.mmdb in ` +
				`${opts.geoipDir}/, or pass --no-geoip to silence this`,
		);
		geoipStatus = 'unavailable';
	}
}

// ---------------------------------------------------------------- report

const report = {
	version: 1,
	ts: new Date().toISOString(),
	clients: [...clients.values()].sort((a, b) =>
		(b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)
	),
	aggregate: {
		turnserver_link: turnserverLink,
		abuse: {
			naughty_list_size: (abuseSets.get('naughty_list') ?? []).length,
			rst_meter_size: (abuseSets.get('rst_meter') ?? []).length,
		},
	},
	health,
	meta: { geoip: geoipStatus, errors: [] },
};

await Deno.mkdir(opts.out.replace(/\/[^/]+$/, ''), { recursive: true });
await Deno.writeTextFile(opts.out, JSON.stringify(report) + '\n', {
	append: true,
	create: true,
});

say(`appended to ${opts.out}`);
if (!opts.quiet) {
	console.error(
		paint('1;32', ' ok'),
		`${report.clients.length} client(s), ` +
			`${
				(turnserverLink.rx_bytes + turnserverLink.tx_bytes).toLocaleString()
			} bytes on the tun link, ` +
			`geoip=${geoipStatus}`,
	);
}
