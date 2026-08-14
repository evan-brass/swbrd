#!/usr/bin/env -S deno run --allow-read=reports,scripts --allow-write=reports
// Bake reports/turn-report.jsonl into a self-contained HTML dashboard, ready to hand to the
// Artifact tool (or open directly -- it has no external dependencies).
//
//   ./scripts/turn-dashboard.js                 # writes reports/index.html
//   ./scripts/turn-dashboard.js --limit=500      # cap how many snapshots get embedded
//
// The template (scripts/turn-dashboard.template.html) is the actual page: this script only
// substitutes the report data into it. Edit the template for layout/design changes; re-run this
// after every scripts/turn-report.js run to refresh the dashboard.

const opts = { limit: 200, out: 'reports/index.html' };
for (const arg of Deno.args) {
	const [key, value] = arg.replace(/^--/, '').split(/=(.*)/s);
	if (key === 'limit') opts.limit = Number(value);
	else if (key === 'out') opts.out = value;
	else {
		console.error(`turn-dashboard: unknown option --${key}`);
		Deno.exit(1);
	}
}

const jsonlPath = 'reports/turn-report.jsonl';
let text;
try {
	text = await Deno.readTextFile(jsonlPath);
} catch {
	console.error(
		`turn-dashboard: ${jsonlPath} not found -- run ./scripts/turn-report.js first`,
	);
	Deno.exit(1);
}

const snapshots = text
	.split('\n')
	.filter((l) => l.trim().length > 0)
	.map((l) => JSON.parse(l));

if (snapshots.length === 0) {
	console.error(
		`turn-dashboard: ${jsonlPath} has no snapshots yet -- run ./scripts/turn-report.js first`,
	);
	Deno.exit(1);
}

const windowed = snapshots.slice(-opts.limit);

const templatePath = new URL('turn-dashboard.template.html', import.meta.url);
const template = await Deno.readTextFile(templatePath);

// JSON can't be dropped verbatim into a <script> tag -- "</script" inside a string would close it
// early. Escaping the one dangerous substring is the standard fix.
const dataJson = JSON.stringify(windowed).replace(/<\/script/gi, '<\\/script');

const html = template
	.replace('__REPORT_DATA__', () => dataJson)
	.replace('__GENERATED_AT__', () => new Date().toISOString());

await Deno.mkdir(opts.out.replace(/\/[^/]+$/, ''), { recursive: true });
await Deno.writeTextFile(opts.out, html);

console.error(
	`turn-dashboard: wrote ${opts.out} (${windowed.length} of ${snapshots.length} snapshot(s))`,
);
