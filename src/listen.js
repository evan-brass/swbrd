import { default_ice_pwd } from './const.js';
import { encoder, state } from './util.js';
import { AttrType, Class, MAGIC_COOKIE, Method, Stun } from './stun.js';

export async function* listen(conn, {
	ice_pwd = default_ice_pwd,
	ice_ufrag = String(conn.cert),
} = {}) {
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(ice_pwd),
		{
			name: 'HMAC',
			hash: 'SHA-1',
		},
		true,
		['sign', 'verify'],
	);

	for (;;) {
		if (conn.dc.readyState == 'closed') break;
		const { data } = await state({
			'close': conn.dc,
			'message': conn.dc,
		});
		if (!(data instanceof ArrayBuffer)) continue;

		// Parse the Binary message as STUN
		if (data.byteLength < Stun.minByteLength) continue;
		const test = new Stun(data);
		if (test.byteLength != data.byteLength) continue;
		if (test.class != Class.Req) continue;
		if (test.method != Method.Binding) continue;
		if (test.cookie != MAGIC_COOKIE) continue;

		// Parse the attributes
		const [
			[username, priority, iceControlled, iceControlling, _useCandidate],
			[integrity],
			[peer],
			uknown,
		] = test.parse([
			[AttrType.Username, 'text'],
			[AttrType.Priority, 'u32'],
			[AttrType.IceControlled, 'u64'],
			[AttrType.IceControlling, 'u64'],
			[AttrType.UseCandidate, 'bool'],
		], [
			[AttrType.Integrity, 20],
		], [
			[AttrType.Peer, 'addr'],
		]);
		if (uknown.length) continue;
		if (
			!username || !priority ||
			(typeof iceControlled == typeof iceControlling) ||
			(typeof iceControlled != 'bigint' && typeof iceControlling != 'bigint') ||
			!integrity || !peer
		) continue;
		const { ip: address, port } = peer;

		// Parse username
		const [dst_ufrag, usernameFragment] = username.split(':');
		if (dst_ufrag != ice_ufrag || !usernameFragment) continue;

		// Check ICE pwd
		if (!await test.verify(key)) continue;

		// Done, construct an ICE candidate and yield it
		yield {
			priority,
			address,
			port,
			usernameFragment,
		};
	}
}
