export const allocations = new Map();

export const hostname = '::ffff:169.254.255.255';
const min_port = 49152, max_port = 65535;
let port = min_port;

export function allocate(value) {
	const max_allocations = max_port - min_port;
	if (allocations.size >= max_allocations) return;
	while (allocations.has(port)) {
		port += 1;
		if (port > max_port) port = min_port;
	}
	allocations.set(port, value);
	return { hostname, port };
}
