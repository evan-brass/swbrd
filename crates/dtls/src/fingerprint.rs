//! The peer's identity.
//!
//! WebRTC certificates are self-signed and there is no PKI behind them, so the
//! SHA-256 fingerprint of the peer's certificate is not a *step* toward an
//! identity — it is the identity, whole.  The browser half of the switchboard
//! already thinks of it that way: `Id` in `src/id.js` holds the digest as a
//! 256-bit big-endian integer and renders it in base 36.
//!
//! This module is the Rust side of that same value, so a peer prints the same
//! string in a browser console and in the daemon's logs.

use openssl::{hash::MessageDigest, ssl::SslRef};

/// A SHA-256 certificate fingerprint: the peer's identity.
pub type Fingerprint = [u8; 32];

/// Longest base-36 rendering of a 256-bit integer: ceil(256 / log2(36)).
pub const BASE36_MAX: usize = 50;

const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// The peer's certificate fingerprint, or `None` if it sent no certificate.
///
/// The acceptor is configured with `FAIL_IF_NO_PEER_CERT`, so a finished
/// handshake always has one; `None` here means the handshake isn't finished.
pub fn peer_fingerprint(ssl: &SslRef) -> Option<Fingerprint> {
	let digest = ssl
		.peer_certificate()?
		.digest(MessageDigest::sha256())
		.ok()?;
	digest.as_ref().try_into().ok()
}

/// Render as base 36, matching `Id`'s `Symbol.toPrimitive` in `src/id.js`: the
/// digest read as one big-endian integer, with no leading zeros.
pub fn base36(fp: &Fingerprint) -> String {
	// Long division by 36 over the big-endian bytes, least significant digit first.
	let mut n = *fp;
	let mut digits = Vec::with_capacity(BASE36_MAX);
	loop {
		let mut rem = 0u32;
		let mut quotient_is_zero = true;
		for b in n.iter_mut() {
			let cur = (rem << 8) | *b as u32;
			let q = cur / 36;
			rem = cur % 36;
			*b = q as u8;
			quotient_is_zero &= q == 0;
		}
		digits.push(DIGITS[rem as usize]);
		if quotient_is_zero {
			break;
		}
	}
	digits.reverse();
	// Every byte pushed came out of DIGITS, so this is ASCII by construction.
	String::from_utf8(digits).expect("base36 digits are ascii")
}

/// Parse a base-36 peer id back into a fingerprint, as `Id.from` does.  Accepts
/// either case; rejects anything that isn't a base-36 integer below 2^256.
pub fn from_base36(s: &str) -> Option<Fingerprint> {
	if s.is_empty() || s.len() > BASE36_MAX {
		return None;
	}
	let mut out = [0u8; 32];
	for ch in s.bytes() {
		let digit = match ch {
			b'0'..=b'9' => ch - b'0',
			b'a'..=b'z' => ch - b'a' + 10,
			b'A'..=b'Z' => ch - b'A' + 10,
			_ => return None,
		} as u32;
		// out = out * 36 + digit, least significant byte first.
		let mut carry = digit;
		for b in out.iter_mut().rev() {
			let cur = *b as u32 * 36 + carry;
			*b = cur as u8;
			carry = cur >> 8;
		}
		// A carry out of the top byte means the value exceeded 256 bits.
		if carry != 0 {
			return None;
		}
	}
	Some(out)
}

/// The SDP `a=fingerprint` form, matching `Id`'s `fingerprint` getter:
/// lowercase hex byte pairs separated by colons, after the hash name.
pub fn sdp(fp: &Fingerprint) -> String {
	let mut out = String::with_capacity(8 + 32 * 3);
	out.push_str("sha-256 ");
	for (i, b) in fp.iter().enumerate() {
		if i > 0 {
			out.push(':');
		}
		out.push_str(&format!("{b:02x}"));
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn be(n: u128) -> Fingerprint {
		let mut fp = [0u8; 32];
		fp[16..].copy_from_slice(&n.to_be_bytes());
		fp
	}

	/// Vectors produced by the browser's own representation:
	/// `BigInt('0x' + hex).toString(36)`.
	#[test]
	fn base36_known_answers() {
		assert_eq!(base36(&[0u8; 32]), "0");
		assert_eq!(base36(&be(1)), "1");
		assert_eq!(base36(&be(35)), "z");
		assert_eq!(base36(&be(36)), "10");
		assert_eq!(base36(&be(1_295)), "zz");
		// 2^256 - 1, the largest id there is.
		assert_eq!(
			base36(&[0xff; 32]),
			"6dp5qcb22im238nr3wvp0ic7q99w035jmy2iw7i6n43d37jtof"
		);
		// A digest with a leading zero byte still renders without padding.
		let mut fp = [0xabu8; 32];
		fp[0] = 0x00;
		assert_eq!(
			base36(&fp),
			"lnskv07zwmsk66lvfsspt6gj5974l5mi756amczg556rd1gr"
		);
	}

	#[test]
	fn base36_round_trip() {
		let cases = [
			[0u8; 32],
			[0xff; 32],
			be(1),
			be(35),
			be(36),
			be(u128::MAX),
			*b"\x61\x4a\x88\x52\xde\x57\xe4\x5e\x1f\xc0\x2d\xb4\xac\xf7\x31\xcd\
			   \xdf\x34\xf6\x42\xc1\x66\x70\xc1\xa8\x98\x65\x73\x6d\x02\x3d\xfb",
		];
		for fp in cases {
			let s = base36(&fp);
			assert!(s.len() <= BASE36_MAX, "{s} is longer than BASE36_MAX");
			assert_eq!(from_base36(&s), Some(fp), "round trip failed for {s}");
			// Ids are case insensitive on the way in, like Id.from.
			assert_eq!(from_base36(&s.to_uppercase()), Some(fp));
		}
	}

	#[test]
	fn from_base36_rejects_junk() {
		assert_eq!(from_base36(""), None);
		assert_eq!(from_base36("hello world"), None);
		assert_eq!(from_base36("-1"), None);
		// 2^256 exactly: one past the largest id.
		assert_eq!(
			from_base36("6dp5qcb22im238nr3wvp0ic7q99w035jmy2iw7i6n43d37jtog"),
			None
		);
		// Longer than any 256-bit value can be.
		assert_eq!(from_base36(&"z".repeat(BASE36_MAX + 1)), None);
	}

	#[test]
	fn sdp_matches_id_fingerprint_getter() {
		let mut fp = [0u8; 32];
		fp[0] = 0x61;
		fp[1] = 0x4a;
		fp[31] = 0xfb;
		let s = sdp(&fp);
		assert!(s.starts_with("sha-256 61:4a:00:"), "{s}");
		assert!(s.ends_with(":fb"), "{s}");
		// 32 bytes as pairs, 31 separators, after "sha-256 ".
		assert_eq!(s.len(), 8 + 32 * 2 + 31);
	}
}
