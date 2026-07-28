//! Stateless TURN nonces: return routability for `Allocate`.
//!
//! The credentials this server accepts are public by design (`USER_KEY` is
//! `md5('user:none:password')` and the README publishes it), so a valid
//! authenticated Allocate can be composed offline.  What stops a spoofed source
//! from buying an fd and five minutes of heartbeats is the *round trip*, not the
//! secret — which is exactly what the 401 challenge is for, provided the nonce
//! is unguessable and bound to the client.
//!
//! Same shape as the DTLS cookies in `dtls-proxy` (`cookie.rs`): an HMAC keyed
//! on a per-process secret over the addresses that must not be portable.  The
//! difference is the timestamp, carried in the clear alongside the tag so a
//! nonce can age out without the server remembering it.
//!
//! ```text
//! ts    u32 big-endian, seconds since this process started
//! tag   HMAC-SHA256(secret, ts || client_ip || client_port)[..12]
//! nonce hex(ts) || hex(tag)                            // 8 + 24 = 32 chars
//! ```
//!
//! Deliberately short: the 401 carrying it answers unauthenticated requests from
//! spoofed sources, so every byte of nonce is amplification (see F7 in
//! `docs/security.md`).  96 bits of tag is far more than an attacker gets to
//! guess against inside one lifetime.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
	net::SocketAddrV6,
	time::{Duration, Instant},
};
use stun::Parsed;

/// How long an issued nonce stays valid.  Matches coturn's default; the client
/// cost of getting it wrong is one 438 round trip.
const LIFETIME: Duration = Duration::from_secs(600);

/// Bytes of HMAC output kept.
const TAG_LEN: usize = 12;

/// Length of the encoded nonce: `hex(u32) + hex(tag)`.  A multiple of 4, so the
/// attribute needs no padding.
pub const LEN: usize = 8 + 2 * TAG_LEN;

pub struct Nonces {
	secret: [u8; 32],
	start: Instant,
}

impl Nonces {
	/// Fresh secret per process.  A restart just costs outstanding clients one
	/// extra challenge round trip, the same trade `dtls-proxy` makes for its
	/// cookies.
	pub fn generate() -> Self {
		use rand::Rng;
		let mut secret = [0; 32];
		rand::rng().fill_bytes(&mut secret);
		Self {
			secret,
			start: Instant::now(),
		}
	}

	/// Seconds since process start, saturating rather than wrapping.
	fn now(&self) -> u32 {
		self.start.elapsed().as_secs().min(u32::MAX as u64) as u32
	}

	/// HMAC primed with everything the nonce commits to.  Both the client
	/// address *and* port: a nonce issued to one client must not be replayable
	/// with a spoofed source, which is the whole point.
	fn tag(&self, ts: u32, client: SocketAddrV6) -> Hmac<Sha256> {
		let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
			.expect("HMAC accepts a key of any length");
		mac.update(&ts.to_be_bytes());
		mac.update(&client.ip().octets());
		mac.update(&client.port().to_be_bytes());
		mac
	}

	/// A nonce for `client`, valid for [`LIFETIME`] from now.
	pub fn issue(&self, client: SocketAddrV6) -> [u8; LEN] {
		self.issue_at(self.now(), client)
	}

	fn issue_at(&self, ts: u32, client: SocketAddrV6) -> [u8; LEN] {
		let full = self.tag(ts, client).finalize().into_bytes();
		let mut out = [0; LEN];
		hex_encode(&ts.to_be_bytes(), &mut out[..8]);
		hex_encode(&full[..TAG_LEN], &mut out[8..]);
		out
	}

	/// Was `nonce` issued by us, to this client, recently enough?
	pub fn check(&self, nonce: Parsed<&str>, client: SocketAddrV6) -> bool {
		self.check_at(self.now(), nonce, client)
	}

	fn check_at(&self, now: u32, nonce: Parsed<&str>, client: SocketAddrV6) -> bool {
		let Parsed::Valid(nonce) = nonce else {
			return false;
		};
		// Decode before hashing: length and alphabet are cheap to reject, and
		// nothing here indexes with a wire-derived length.
		let Some(nonce) = (nonce.len() == LEN).then(|| nonce.as_bytes()) else {
			return false;
		};
		let Some(ts) = hex_decode::<4>(&nonce[..8]) else {
			return false;
		};
		let Some(tag) = hex_decode::<TAG_LEN>(&nonce[8..]) else {
			return false;
		};
		// Reject the future too: a nonce we could not have issued yet is either
		// forged or from before a restart.
		let ts = u32::from_be_bytes(ts);
		let Some(age) = now.checked_sub(ts) else {
			return false;
		};
		if u64::from(age) > LIFETIME.as_secs() {
			return false;
		}
		// Constant time, and truncation-aware.
		self.tag(ts, client).verify_truncated_left(&tag).is_ok()
	}
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(src: &[u8], dst: &mut [u8]) {
	debug_assert_eq!(dst.len(), 2 * src.len());
	for (b, out) in src.iter().zip(dst.chunks_exact_mut(2)) {
		out[0] = HEX[usize::from(b >> 4)];
		out[1] = HEX[usize::from(b & 0xf)];
	}
}

/// Lowercase hex only — it's the only thing we ever issue.
fn hex_decode<const N: usize>(src: &[u8]) -> Option<[u8; N]> {
	if src.len() != 2 * N {
		return None;
	}
	let mut out = [0; N];
	for (b, hex) in out.iter_mut().zip(src.chunks_exact(2)) {
		*b = unhex(hex[0])? << 4 | unhex(hex[1])?;
	}
	Some(out)
}

fn unhex(c: u8) -> Option<u8> {
	match c {
		b'0'..=b'9' => Some(c - b'0'),
		b'a'..=b'f' => Some(c - b'a' + 10),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{net::Ipv6Addr, str::from_utf8};

	fn client(port: u16) -> SocketAddrV6 {
		SocketAddrV6::new("2001:db8::1".parse().unwrap(), port, 0, 0)
	}

	/// `check_at` takes a `Parsed`, which is what the caller has; issuing gives
	/// bytes.  Bridge the two the way `handle_turn` does.
	fn valid(nonce: &[u8; LEN]) -> Parsed<&str> {
		Parsed::Valid(from_utf8(nonce).unwrap())
	}

	#[test]
	fn round_trip() {
		let n = Nonces::generate();
		let nonce = n.issue(client(3478));
		assert!(nonce.iter().all(|c| c.is_ascii_alphanumeric()));
		assert!(n.check(valid(&nonce), client(3478)));
	}

	#[test]
	fn binds_client_address() {
		let n = Nonces::generate();
		let nonce = n.issue_at(0, client(3478));

		assert!(n.check_at(0, valid(&nonce), client(3478)));
		// Different port: NAT rebinding costs a round trip, spoofing costs the
		// whole allocation.
		assert!(!n.check_at(0, valid(&nonce), client(3479)));
		// Different address.
		let other = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3478, 0, 0);
		assert!(!n.check_at(0, valid(&nonce), other));
	}

	#[test]
	fn secret_is_per_process() {
		let a = Nonces::generate();
		let b = Nonces::generate();
		let nonce = a.issue_at(0, client(3478));
		assert!(a.check_at(0, valid(&nonce), client(3478)));
		assert!(!b.check_at(0, valid(&nonce), client(3478)));
	}

	#[test]
	fn expires() {
		let n = Nonces::generate();
		let life = LIFETIME.as_secs() as u32;
		let nonce = n.issue_at(1000, client(3478));

		assert!(n.check_at(1000, valid(&nonce), client(3478)));
		assert!(n.check_at(1000 + life, valid(&nonce), client(3478)));
		assert!(!n.check_at(1001 + life, valid(&nonce), client(3478)));
		// From the future: not something we could have issued.
		assert!(!n.check_at(999, valid(&nonce), client(3478)));
	}

	#[test]
	fn junk_rejected() {
		let n = Nonces::generate();
		let good = n.issue_at(0, client(3478));

		assert!(!n.check_at(0, Parsed::NotPresent, client(3478)));
		assert!(!n.check_at(0, Parsed::Invalid, client(3478)));
		assert!(!n.check_at(0, Parsed::Valid(""), client(3478)));
		assert!(!n.check_at(0, Parsed::Valid("none"), client(3478)));
		// Right length, wrong alphabet.
		assert!(!n.check_at(0, Parsed::Valid(&"z".repeat(LEN)), client(3478)));
		// Uppercase hex: we never issue it, so we never accept it.  (An all-digit
		// tag is uppercase-invariant; nothing to test in that one-in-a-million
		// case.)
		let upper = from_utf8(&good).unwrap().to_uppercase();
		if good.iter().any(u8::is_ascii_alphabetic) {
			assert!(!n.check_at(0, Parsed::Valid(&upper), client(3478)));
		}
		// Truncated and extended.
		let s = from_utf8(&good).unwrap();
		assert!(!n.check_at(0, Parsed::Valid(&s[..LEN - 1]), client(3478)));
		assert!(!n.check_at(0, Parsed::Valid(&format!("{s}0")), client(3478)));
		// A flipped tag bit under an otherwise valid timestamp.
		let mut bad = good;
		bad[LEN - 1] ^= 1;
		assert!(!n.check_at(0, valid(&bad), client(3478)));
	}
}
