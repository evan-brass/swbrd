export const encoder = new TextEncoder();
export const decoder = new TextDecoder('utf-8', {fatal: true});
export const decoder_lossy = new TextDecoder('utf-8', {fatal: false});

export async function write(writer, value) {
	while (writer.desiredSize < 0) await writer.ready;
	if (!writer.desiredSize) return;
	await writer.write(value);
}

export function mapped(ip) {
	return ip instanceof Uint8Array ? new Uint16Array([
		0, 0, 0, 0, 0, 0xffff, (ip[0] << 8) + ip[1], (ip[2] << 8) + ip[3]
	]) : ip;
}
