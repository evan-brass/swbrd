// Where the tests expect the deployment to be.  Everything here is overridable with a query
// parameter, so a page can be pointed at a different prefix or port without editing anything:
//
//   tests/vpn.html?base=2a01:4ff:1f0:7e46:0:4::&sctp_port=5001

import { params } from './harness.js';

export function parse_v6(str) {
	const [head, tail = ''] = str.split('::');
	const h = head ? head.split(':') : [];
	const t = tail ? tail.split(':') : [];
	const groups = str.includes('::')
		? [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t]
		: h;
	if (groups.length != 8) throw new Error(`not a full IPv6 address: ${str}`);
	return Uint16Array.from(groups, (g) => parseInt(g, 16));
}

// The /96 that systemd-networkd routes to the dtls-proxy TUN (etc/systemd/network/dtls-proxy.network).
// Deter's own default is fd01::/96, which is only reachable from inside the VPN — a browser out on
// the internet has to aim at the globally routed prefix instead.
export const DETER_BASE = parse_v6(
	params.get('base') ?? '2a01:4ff:1f0:7e46:0:4::',
);

// 5000 is Conn's default (plain DTLS proxy); 5001 is what the swbrd VPN daemon listens on
// (etc/systemd/system/swbrd.service).
export const SCTP_PORT = Number(params.get('sctp_port') ?? 5001);

// The turnserver's relay prefix, used by the ICMP probe.
export const RELAY_ADDR = params.get('relay') ?? '2a01:4ff:1f0:7e46:1::';
