//! Zerocopy wire formats for the DTLS record + handshake layers.
//!
//! Just enough DTLS to implement stateless cookies: locate the first handshake
//! fragment in a datagram, pull the cookie out of a fragment-0 ClientHello, and
//! emit a HelloVerifyRequest.  DTLS 1.3 ClientHellos use the 1.0/1.2 values in
//! their legacy version fields, so they parse the same as 1.2.

use core::mem::size_of;
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, network_endian::U16,
};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Version {
	Dtls1_0 = u16::to_be(0xfeff),
	Dtls1_2 = u16::to_be(0xfefd),
	Dtls1_3 = u16::to_be(0xfefc),
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum ContentType {
	ChangeCipherSpec = 20,
	Alert = 21,
	Handshake = 22,
	ApplicationData = 23,
}

/// TLS's 24-bit big-endian integer
#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
pub struct U24(pub [u8; 3]);
impl U24 {
	pub const fn new(v: u32) -> Self {
		let [_, a, b, c] = v.to_be_bytes();
		Self([a, b, c])
	}
	pub const fn get(&self) -> u32 {
		let [a, b, c] = self.0;
		u32::from_be_bytes([0, a, b, c])
	}
}

#[repr(C, packed)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub struct RecordHeader {
	pub content_type: ContentType,
	pub version: Version,
	pub epoch: U16,
	pub sequence: [u8; 6],
	pub length: U16,
}

#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
pub struct HandshakeHeader {
	pub typ: u8,
	pub length: U24,
	pub message_seq: U16,
	pub fragment_offset: U24,
	pub fragment_length: U24,
}
impl HandshakeHeader {
	pub const CLIENT_HELLO: u8 = 1;
	pub const HELLO_VERIFY_REQUEST: u8 = 3;
}

/// The first handshake fragment in the first DTLS record of a datagram.
///
/// Only the first record and its first fragment are considered: ClientHellos
/// always lead a flight, and refusing to search deeper keeps the parsing
/// surface that must agree with the TLS library's as small as possible.
#[derive(Debug, Clone, Copy)]
pub struct Fragment<'a> {
	pub record: RecordHeader,
	pub handshake: HandshakeHeader,
	pub body: &'a [u8],
}
impl<'a> Fragment<'a> {
	pub fn parse(datagram: &'a [u8]) -> Option<Self> {
		let (record, rest) = RecordHeader::try_read_from_prefix(datagram).ok()?;
		if !matches!(record.content_type, ContentType::Handshake) || record.epoch.get() != 0 {
			return None;
		}
		let (payload, _) = rest.split_at_checked(record.length.get() as usize)?;
		let (handshake, rest) = HandshakeHeader::read_from_prefix(payload).ok()?;
		if handshake.fragment_offset.get() + handshake.fragment_length.get()
			> handshake.length.get()
		{
			return None;
		}
		let (body, _) = rest.split_at_checked(handshake.fragment_length.get() as usize)?;
		Some(Self {
			record,
			handshake,
			body,
		})
	}

	/// Parse this fragment as the start of a ClientHello.  The cookie always
	/// lands in fragment 0 (it sits at most 2+32+1+32+1+255 bytes in), so a
	/// fragmented ClientHello's cookie can be verified from its first fragment.
	pub fn client_hello(&self) -> Option<ClientHello<'a>> {
		if self.handshake.typ != HandshakeHeader::CLIENT_HELLO
			|| self.handshake.fragment_offset.get() != 0
		{
			return None;
		}
		ClientHello::parse(self.body)
	}

	/// This fragment rebuilt as a standalone record: header bytes to prepend to
	/// [`Self::body`].  Anything else in the datagram (later fragments, later
	/// records) is dropped, so the TLS library sees exactly the verified bytes.
	pub fn truncated(&self) -> [u8; size_of::<RecordHeader>() + size_of::<HandshakeHeader>()] {
		let mut record = self.record;
		record.length = U16::new((size_of::<HandshakeHeader>() + self.body.len()) as u16);

		let mut out = [0; 25];
		out[..size_of::<RecordHeader>()].copy_from_slice(record.as_bytes());
		out[size_of::<RecordHeader>()..].copy_from_slice(self.handshake.as_bytes());
		out
	}
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes)]
struct ClientHelloPrefix {
	version: Version,
	random: [u8; 32],
	session_id_len: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientHello<'a> {
	pub version: Version,
	pub random: [u8; 32],
	pub session_id: &'a [u8],
	pub cookie: &'a [u8],
}
impl<'a> ClientHello<'a> {
	pub fn parse(fragment: &'a [u8]) -> Option<Self> {
		let (prefix, rest) = ClientHelloPrefix::try_read_from_prefix(fragment).ok()?;
		let (session_id, rest) = rest.split_at_checked(prefix.session_id_len as usize)?;
		let (&cookie_len, rest) = rest.split_first()?;
		let (cookie, _) = rest.split_at_checked(cookie_len as usize)?;
		Some(Self {
			version: prefix.version,
			random: prefix.random,
			session_id,
			cookie,
		})
	}
}

pub const COOKIE_LEN: usize = 32;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, IntoBytes)]
pub struct HelloVerifyRequest {
	pub record: RecordHeader,
	pub handshake: HandshakeHeader,
	pub server_version: Version,
	pub cookie_len: u8,
	pub cookie: [u8; COOKIE_LEN],
}
impl HelloVerifyRequest {
	pub fn new(client_hello: &Fragment, cookie: [u8; COOKIE_LEN]) -> Self {
		const BODY: usize = size_of::<Version>() + 1 + COOKIE_LEN;
		Self {
			record: RecordHeader {
				content_type: ContentType::Handshake,
				// RFC 6347 4.2.1: HelloVerifyRequest always uses DTLS 1.0
				version: Version::Dtls1_0,
				epoch: U16::new(0),
				// RFC 6347 4.2.1: echo the ClientHello's record sequence number
				sequence: client_hello.record.sequence,
				length: U16::new((size_of::<HandshakeHeader>() + BODY) as u16),
			},
			handshake: HandshakeHeader {
				typ: HandshakeHeader::HELLO_VERIFY_REQUEST,
				length: U24::new(BODY as u32),
				// RFC 6347 4.2.2: HelloVerifyRequest reuses the ClientHello's message_seq
				message_seq: client_hello.handshake.message_seq,
				fragment_offset: U24::new(0),
				fragment_length: U24::new(BODY as u32),
			},
			server_version: Version::Dtls1_0,
			cookie_len: COOKIE_LEN as u8,
			cookie,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const _: () = assert!(size_of::<RecordHeader>() == 13);
	const _: () = assert!(size_of::<HandshakeHeader>() == 12);
	const _: () = assert!(size_of::<HelloVerifyRequest>() == 13 + 12 + 2 + 1 + COOKIE_LEN);

	// A ClientHello body: DTLS 1.2, zero random, no session id, an 8-byte
	// cookie, one cipher suite, null compression, no extensions.
	fn hello_body(cookie: &[u8]) -> Vec<u8> {
		let mut body = vec![0xfe, 0xfd];
		body.extend([0x99; 32]); // random
		body.push(0); // session_id
		body.push(cookie.len() as u8);
		body.extend(cookie);
		body.extend([0, 2, 0xc0, 0x2b]); // cipher_suites
		body.extend([1, 0]); // compression_methods
		body
	}

	fn record(msg_seq: u16, frag_off: u32, frag: &[u8], total: u32) -> Vec<u8> {
		let mut out = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 1];
		out.extend(((12 + frag.len()) as u16).to_be_bytes());
		out.push(HandshakeHeader::CLIENT_HELLO);
		out.extend(&total.to_be_bytes()[1..]);
		out.extend(msg_seq.to_be_bytes());
		out.extend(&frag_off.to_be_bytes()[1..]);
		out.extend(&(frag.len() as u32).to_be_bytes()[1..]);
		out.extend(frag);
		out
	}

	#[test]
	fn parse_client_hello() {
		let body = hello_body(b"\x01\x02\x03\x04\x05\x06\x07\x08");
		let datagram = record(0, 0, &body, body.len() as u32);

		let fragment = Fragment::parse(&datagram).unwrap();
		assert_eq!({ fragment.record.version }, Version::Dtls1_2);
		assert_eq!(fragment.handshake.message_seq.get(), 0);
		let hello = fragment.client_hello().unwrap();
		assert_eq!(hello.version, Version::Dtls1_2);
		assert_eq!(hello.random, [0x99; 32]);
		assert_eq!(hello.session_id, b"");
		assert_eq!(hello.cookie, b"\x01\x02\x03\x04\x05\x06\x07\x08");
	}

	#[test]
	fn parse_fragmented() {
		let body = hello_body(&[0xaa; 32]);
		let total = (body.len() + 700) as u32; // pretend extensions follow in a later fragment

		// Fragment 0 carries the cookie
		let datagram = record(1, 0, &body, total);
		let fragment = Fragment::parse(&datagram).unwrap();
		let hello = fragment.client_hello().unwrap();
		assert_eq!(hello.cookie, [0xaa; 32]);

		// A later fragment is not a start-of-ClientHello
		let datagram = record(1, body.len() as u32, &[0; 700], total);
		let fragment = Fragment::parse(&datagram).unwrap();
		assert!(fragment.client_hello().is_none());
	}

	#[test]
	fn cookie_straddles_fragment_end() {
		let body = hello_body(&[0xaa; 32]);
		let split = 2 + 32 + 1 + 1 + 16; // mid-cookie
		let datagram = record(0, 0, &body[..split], body.len() as u32);
		let fragment = Fragment::parse(&datagram).unwrap();
		assert!(fragment.client_hello().is_none());
	}

	#[test]
	fn reject_junk() {
		// Not DTLS at all
		assert!(Fragment::parse(b"nonsense").is_none());
		// Wrong content type (alert)
		let body = hello_body(b"");
		let mut datagram = record(0, 0, &body, body.len() as u32);
		datagram[0] = 21;
		assert!(Fragment::parse(&datagram).is_none());
		// Record length beyond the datagram
		let mut datagram = record(0, 0, &body, body.len() as u32);
		datagram[11..13].copy_from_slice(&u16::to_be_bytes(2000));
		assert!(Fragment::parse(&datagram).is_none());
		// Fragment beyond the message
		let datagram = record(0, 300, &body, body.len() as u32);
		assert!(Fragment::parse(&datagram).is_none());
	}

	#[test]
	fn truncated_record() {
		let body = hello_body(&[0xaa; 32]);
		let mut datagram = record(0, 0, &body, body.len() as u32);
		datagram.extend([21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 2, 40]); // trailing alert record

		let fragment = Fragment::parse(&datagram).unwrap();
		let header = fragment.truncated();
		let rebuilt: Vec<u8> = header.iter().chain(fragment.body).copied().collect();
		// Identical to the original datagram minus the trailing record
		assert_eq!(rebuilt, datagram[..datagram.len() - 15]);
	}

	#[test]
	fn hello_verify_request() {
		let body = hello_body(b"");
		let mut datagram = record(0, 0, &body, body.len() as u32);
		datagram[5..11].copy_from_slice(&[0, 0, 0, 0, 0, 7]); // record sequence 7

		let fragment = Fragment::parse(&datagram).unwrap();
		let hvr = HelloVerifyRequest::new(&fragment, [0xcc; COOKIE_LEN]);
		let bytes = hvr.as_bytes();

		let fragment = Fragment::parse(bytes).unwrap();
		assert_eq!(
			fragment.handshake.typ,
			HandshakeHeader::HELLO_VERIFY_REQUEST
		);
		assert_eq!(fragment.record.sequence, [0, 0, 0, 0, 0, 7]);
		assert_eq!({ fragment.record.version }, Version::Dtls1_0);
		assert_eq!(fragment.handshake.length.get(), 2 + 1 + 32);
		assert_eq!(fragment.body[2], COOKIE_LEN as u8);
		assert_eq!(&fragment.body[3..], [0xcc; COOKIE_LEN]);
	}
}
