export async function write(writer, frame) {
	while (writer.desiredSize < 0) await writer.ready;
	if (writer.desiredSize == null || writer.desiredSize == 0) return;
	await writer.write(frame);
}

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export function mapped(ip) {
	return ip instanceof Uint8Array ? new Uint16Array([
		0, 0, 0, 0, 0, 0xffff, (ip[0] << 8) + ip[1], (ip[2] << 8) + ip[3]
	]) : ip;
}
