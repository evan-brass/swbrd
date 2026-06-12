#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * Our deterministic certificate is rotated twice per year and each cert is valid for 1 year however we only use it for <10 months.
 * Every client knows exactly which certificate they will use: The newest valid certificate that is at least 24hr old.
 * To compensate for clock skew and long running connections, we keep two instances of the dtls-proxy.  One running the January certificate and one running the July certificate.
 * We need to reconstruct the ssl config with the new certificate once it has been rotated.  I'm planning on using a signal here, maybe SIGHUP or SIGUSR1.
 *
 * 2026                                            2027                                            2028
 * Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec
 * |--->-----------------CERT1-x-----------^---....|
 *                         |--->-----------------CERT2-x-----------^---....|
 *                                                 |--->-----------------CERT3-x-----------^---....|
 *                                                                         |--->-----------------CERT4-x-----------^---....|
 *                                                                                                 |--->-----------------CERT5-x-----------^---....|
 * (->-) is when all clients should have switched to the next certificate
 * (-x-) is when we send SIGUSR1 to tell dtls-proxy to no longer accept new connections
 * (-^-) is when we should rotate the certificate from CERTx to CERTx+2
 * (...) is when we should
 */

import { certificate, sha256 } from '../src/deter.js';

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

const cert = await certificate({
	year,
	month,
});

const fingerprint = await sha256(cert);
const low16 = (fingerprint & 0xffffn).toString(16);

const cert_path = `cert-${low16}.der`;
await Deno.writeFile(cert_path, cert);
await Deno.link(cert_path, month_name + '.der');
