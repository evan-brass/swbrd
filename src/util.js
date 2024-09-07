export const encoder = new TextEncoder();
export const decoder = new TextDecoder('utf-8', {fatal: true});
export const decoder_lossy = new TextDecoder('utf-8', {fatal: false});
export const is_firefox = typeof self.RTCPeerConnection?.prototype?.getIdentityAssertion == 'function';

export async function write(writer, value) {
	while (writer.desiredSize < 0) await writer.ready;
	if (!writer.desiredSize) return;
	await writer.write(value);
}
