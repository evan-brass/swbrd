export const encoder = new TextEncoder();
export const decoder = new TextDecoder('utf-8', { fatal: true });
export const decoder_lossy = new TextDecoder('utf-8', { fatal: false });
export const is_firefox =
	typeof self.RTCPeerConnection?.prototype?.getIdentityAssertion == 'function';

export async function write(writer, value) {
	while (writer.desiredSize < 0) await writer.ready;
	if (!writer.desiredSize) return;
	await writer.write(value);
}

export function state(transitions = {}) {
	return new Promise((res) => {
		for (const [e, target] of Object.entries(transitions)) {
			if (!(target instanceof EventTarget)) throw new Error('??');
			target.addEventListener(e, res, { once: true });
		}
	});
}

// Like parseInt, but chunks the string into chunks that are smaller than MAX_SAFE_INTEGER (in that radix) and returns a BigInt instead of a Number.
export function parseBigInt(s, radix = 10) {
	const { length } = Number.MAX_SAFE_INTEGER.toString(radix);
	const splitter = new RegExp(`[0-9a-z]{1,${length - 1}}`, 'gi');
	let res = 0n;
	for (const { 0: chunk, index } of s.matchAll(splitter)) {
		const n = parseInt(chunk, radix);
		// How right shifted is this chunk within the total string?
		const exp = s.length - index - chunk.length;
		res += BigInt(n) * (BigInt(radix) ** BigInt(exp));
	}
	return res;
}
