use sha2::{Digest, Sha256};
use std::{
	array::from_fn,
	net::{IpAddr, SocketAddr},
	sync::LazyLock,
	time::{Duration, Instant},
};
use stun::Parsed;

static NONCE_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| rand::random());
static STARTUP: LazyLock<Instant> = LazyLock::new(|| Instant::now());

// We don't use HMAC here, just a hash.
fn expected_tag(ts: u32, client: &SocketAddr) -> u64 {
	let mut hash = Sha256::new();
	hash.update(ts.to_ne_bytes());
	match client.ip() {
		IpAddr::V4(v4) => hash.update(v4.octets()),
		IpAddr::V6(v6) => hash.update(v6.octets()),
	}
	hash.update(client.port().to_ne_bytes());
	hash.update(*NONCE_KEY);
	let exp = hash.finalize();
	// First 8 bytes of the hash
	u64::from_ne_bytes(from_fn(|i| exp[i]))
}
// Anticipated durations: 1min for allocation requests, 30+min for established allocations.
// Our refresh lifetime is currently 4min, so you get a 1min nonce under which you conduct your allocation handshake.  Then your first refresh/perm/channel-bind/etc. gets a nonce-expired but you won't get another until your allocation is 30+ min old.  Technically, clients could reuse that long nonce to create new allocations, but only from the same client IP+Port (max 4 allocations: :3478/udp, :3478:tcp, :5349/tls, :443/tls, however if our turnserver binds to multiple ip addresses then it would be 4-per ip address.  Currently, we only bind 1v4 and 1v6, the tls varieties have a local ip of ::1/127.0.0.1 which is why they could create 4 allocations instead of just 2)
pub fn issue_nonce(client: &SocketAddr, dur: Duration) -> [u8; 24] {
	use std::io::Write;
	let ts = (STARTUP.elapsed() + dur).as_secs() as u32;
	let tag = expected_tag(ts, client);

	let mut ret = [0u8; 24];
	write!(&mut ret[..], "{ts:08x}{tag:016x}").unwrap();
	ret
}
pub fn verify_nonce(nonce: &Parsed<&[u8; 24]>, client: &SocketAddr) -> bool {
	let Parsed::Valid(nonce) = nonce else {
		return false;
	};
	let Ok(nonce) = str::from_utf8(*nonce) else {
		return false;
	};
	let Some((ts, tag)) = nonce.split_at_checked(8) else {
		return false;
	};
	let Ok(ts) = u32::from_str_radix(ts, 16) else {
		return false;
	};
	if STARTUP.elapsed() > Duration::from_secs(ts as u64) {
		return false;
	}
	let Ok(tag) = u64::from_str_radix(tag, 16) else {
		return false;
	};
	expected_tag(ts, client) == tag
}
