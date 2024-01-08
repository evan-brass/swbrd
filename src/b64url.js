const swap = new Map([
	['+', '-'],
	['/', '_'],
	['=', '']
].map(a => [a, a.toReversed()]).flat());
export function to_url(b64) {
	return b64.replace(/[+/=]/g, s => swap.get(s));
}
export function from_url(urlb64, do_pad = true) {
	let ret = urlb64.replace(/[-_]/g, s => swap.get(s));
	while (do_pad && ret.length % 4 != 0) ret += '=';
	return ret;
}
export function btoa_url(b) {
	return to_url(btoa(b));
}
export function atob_url(s) {
	return atob(from_url(s));
}

export function buftobinstr(buffer) {
	if (buffer instanceof ArrayBuffer) {
		buffer = new Uint8Array(buffer);
	}
	else if (ArrayBuffer.isView(buffer)) {
		buffer = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
	}

	return String.fromCharCode(...buffer);
}
export function binstrtobuf(binstr) {
	const ret = new Uint8Array(binstr.length);
	for (let i = 0; i < binstr.length; ++i) {
		ret[i] = binstr.charCodeAt(i);
	}
	return ret;
}
