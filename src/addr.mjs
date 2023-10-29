import { Sig, Conn } from "./conn.mjs";
import { Id } from "./id.mjs";
import { Dns } from "./dns.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');
const doh_address = 'https://1.1.1.1/dns-query';

/**
 * Use DNS over HTTPS (DoH) to find the Id for an address that doesn't contain a username.  We query the TXT entries for hostname
 * looking for any that start with "swbrd=".  We attempt to create an Id from these, returning the first Id that succeeds.
 * @param {string} hostname - The domain name to query
 * @param {number} query_bufflen - The size of buffer we'll allocate to encode the DNS Message
 * @return {Promise<Id | undefined>}
 */
async function query_username(hostname, query_bufflen = 512) {
	const labels = hostname.split('.');
	if (labels.indexOf('') !== -1) return; // Error: Internal Null label
	labels.push('');

	const buffer = new Uint8Array(query_bufflen);
	const dns_header = `\0\0\x01\0\0\x01\0\0\0\0\0\0`;
	encoder.encodeInto(dns_header, buffer);
	let offset = 12;
	for (const label of labels) {
		const {read, written} = encoder.encodeInto(label, buffer.subarray(offset + 1));
		if (read < label.length) return; // Error: Buffer too small for this question
		if (written >= 64) return; // Error: Label too large
		buffer[offset] = written;
		offset += 1 + written;
	}
	const question_tail = `\0\x10\0\x01`;
	const {read, written} = encoder.encodeInto(question_tail, buffer.subarray(offset));
	if (read < question_tail) return; // Error: Buffer too small for this question
	const dns_message = buffer.subarray(0, offset + written);
	console.log(dns_message);

	const res = await fetch(doh_address, {
		method: 'post',
		headers: {
			'Content-Type': 'application/dns-message',
			'Accept': 'application/dns-message'
		},
		body: dns_message
	});
	const ans = new DataView(await res.arrayBuffer());
	const ansb = new Uint8Array(ans.buffer, ans.byteOffset, ans.byteLength);

	if (ans.byteLength < 12) return; // Error: Response too short
	const res_flags = ans.getUint16(2);
	if (res_flags & 0b0_0000_0_1_0_0_000_1111) return; // Error: Truncated or Error response code
	if ((res_flags & 0b1_0000_0_0_0_0_000_0000) === 0) return; // Error: Not an answer
	offset = dns_message.byteLength;
	const AnC = ans.getUint16(6);
	for (let i = 0; i < AnC; ++i) {
		if (offset + 12 > ans.byteLength) return; // Error: Malformed Answer - Past the end of the response
		if (ans.getUint16(offset) !== (0b11_000000_00000000 + 12)) return; // Error: Answer doesn't respond to our question
		const len = ans.getUint16(offset + 10);
		let txt_off = offset + 12;
		offset = offset + 12 + len;
		if (offset > ansb.byteLength) return; // Error: Malformed TXT - Past the end of the response
		
		for (let txt_len = ansb[txt_off]; txt_off < offset; txt_off += txt_len, txt_len = ansb[txt_off]) {
			const txt = decoder.decode(ansb.subarray(txt_off + 1, txt_off + 1 + txt_len));
			if (!txt.startsWith('swbrd=')) continue; // Not one of our TXT entries

			const id = Id.parse(txt.slice(6));
			if (id) return id;
		}
	}
}

const default_ports = {
	udp: 3478,
	tcp: 3478,
	tls: 5349
};

export class Addr {
	#http;
	#https;
	protocol;
	constructor(arg) {
		this.#http = new URL(arg);
		this.protocol = this.#http.protocol;
		this.#http.protocol = 'http';
		this.#https = new URL(arg);
		this.#https.protocol = 'https';
	}
	get port() {
		return this.#http.port || this.#https.port || default_ports[this.protocol] || 4666;
	}
	async id() {
		const username = this.#http.username || await query_username(this.#http.hostname);
		if (!username) return;
		return new Id(username);
	}
	connect() {

	}
}
