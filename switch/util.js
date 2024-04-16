export async function write(writer, frame) {
	while (writer.desiredSize < 0) await writer.ready;
	if (writer.desiredSize == null || writer.desiredSize == 0) return;
	await writer.write(frame);
}

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
