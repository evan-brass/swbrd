#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * Our deterministic certificate is rotated twice per year and each cert is valid for 1 year however we only use it for <10 months.
 * Every client knows exactly which certificate they will use: The newest valid certificate that is at least 24hr old.
 * To compensate for clock skew and long running connections, we keep two instances of the dtls-proxy.  One running the January certificate and one running the July certificate.
 * We need to reconstruct the ssl config with the new certificate once it has been rotated.  I'm planning on using a signal here, maybe SIGHUP or SIGUSR1.
 *
 * 2026                                            2027                                            2028
 * Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec J
 * |->------------------Jan 2026--------------<....|->------------------Jan 2027--------------<....|->------------------Jan 2028--------------<....|
 * -------------------<....|->------------------Jul 2026--------------<....|->------------------Jul 2027--------------<....|->------------------Jul
 * (->-) is when all clients should have switched to the next certificate since they pick the the latest certificate that is at least 24hr old
 * (-< ) is when we should send SIGHUP to load the next certificate.
 * (...) is when clients won't be able to connect to this DTLS process because the new certificate is not yet valid (Not Before)
 */

import { Deter } from '../src/deter.js';

const [month_name] = Deno.args;
if (!['January', 'July'].includes(month_name)) {
	throw new Error(
		'Missing month: You must specify whether to rotate the "January" or "July" certificate.',
	);
}

const month = {
	January: 0,
	July: 6,
}[month_name];

const timestamp = Date.now();
const current_year = new Date().getUTCFullYear();
const year = {
	January: timestamp < Date.UTC(current_year, 10)
		? current_year
		: current_year + 1,
	July: timestamp < Date.UTC(current_year, 4) ? current_year - 1 : current_year,
}[month_name];

const cert = await Deter.generate({
	year,
	month,
});

await Deno.writeFile(month_name + '.der', cert);
