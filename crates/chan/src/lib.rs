//! The wire format between the switchboard and an extension.
//!
//! One Unix SOCK_STREAM connection carries one channel, so the connection's
//! lifetime *is* the channel's: connecting opens it, `shutdown(SHUT_WR)` is a
//! half close, and closing ends it.  That leaves this format responsible for
//! only two things -- message boundaries and the per-message metadata a
//! datachannel carries -- which is why it is twelve bytes and no negotiation.
//!
//! Stream sockets rather than SOCK_SEQPACKET because Deno cannot open a
//! seqpacket socket at all, and because byte-granular backpressure and
//! unbounded messages fall out of them for free.

use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
	network_endian::{U16, U32},
};

pub mod control;
pub mod dcep;

/// The largest payload one frame may carry.
///
/// `src/conn.js` synthesizes its SDP offer without an `a=max-message-size`
/// attribute, so browsers apply the RFC 8841 default of 64 KiB and will never
/// send us more than this in one message.  It also has to stay comfortably
/// under a channel socket's `SO_RCVBUF`: a frame is read by peeking a whole one
/// at a time, and a frame too large to sit in the receive buffer could never be
/// peeked in full.
pub const MAX_PAYLOAD: usize = 64 * 1024;

pub mod flags {
	/// This frame completes the message.
	pub const EOR: u16 = 0x0001;
	/// Send this message unordered, whatever the channel's default.
	pub const UNORDERED: u16 = 0x0002;
	/// Receive only: partial reliability abandoned this message.
	pub const ABANDON: u16 = 0x0004;
	/// The payload is a [`control`](crate::control) message, not peer data.
	///
	/// Deliberately a flag rather than a reserved ppid: ppid is chosen by the
	/// peer, so a hostile browser sending ppid 0 must not be able to forge a
	/// control message.  Nothing the daemon relays from a peer ever sets this.
	pub const CONTROL: u16 = 0x8000;
}

#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
pub struct Header {
	/// Payload bytes following this header.
	pub length: U32,
	/// SCTP payload protocol id, carried verbatim in both directions.
	pub ppid: U32,
	pub flags: U16,
	pub reserved: U16,
}
impl Header {
	pub const LEN: usize = size_of::<Self>();

	pub fn new(ppid: u32, flags: u16, length: usize) -> Self {
		Self {
			length: U32::new(length as u32),
			ppid: U32::new(ppid),
			flags: U16::new(flags),
			reserved: U16::ZERO,
		}
	}

	pub fn has(&self, flag: u16) -> bool {
		self.flags.get() & flag != 0
	}
}

/// A frame that claimed a payload larger than [`MAX_PAYLOAD`].  Fatal for the
/// channel: we can never peek a whole one, so there is no way to make progress.
#[derive(Debug, PartialEq, Eq)]
pub struct Oversize(pub u32);

impl std::fmt::Display for Oversize {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"frame claims {} bytes, over the {MAX_PAYLOAD} limit",
			self.0
		)
	}
}
impl std::error::Error for Oversize {}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
	pub header: Header,
	pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
	/// Read one whole frame off the front of `buf`.
	///
	/// `Ok(None)` means the frame is real but not all here yet -- the caller
	/// peeked rather than consumed, so the right response is to wait for more
	/// and peek again, not to buffer what has arrived.
	pub fn parse(buf: &'a [u8]) -> Result<Option<Frame<'a>>, Oversize> {
		let Ok((header, rest)) = Header::read_from_prefix(buf) else {
			return Ok(None);
		};
		let length = header.length.get();
		if length as usize > MAX_PAYLOAD {
			return Err(Oversize(length));
		}
		let Some(payload) = rest.get(..length as usize) else {
			return Ok(None);
		};
		Ok(Some(Frame { header, payload }))
	}

	/// Bytes this frame occupies on the wire, which is what the caller consumes
	/// once it has been handed on.
	pub fn wire_len(&self) -> usize {
		Header::LEN + self.payload.len()
	}
}

/// Write a frame into `out`, which the caller then sends as one unit.
pub fn encode(out: &mut Vec<u8>, ppid: u32, flags: u16, payload: &[u8]) {
	out.clear();
	out.extend_from_slice(Header::new(ppid, flags, payload.len()).as_bytes());
	out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_trip() {
		let mut buf = Vec::new();
		encode(&mut buf, 51, flags::EOR | flags::UNORDERED, b"hello");
		assert_eq!(buf.len(), Header::LEN + 5);

		let frame = Frame::parse(&buf).unwrap().expect("a whole frame");
		assert_eq!(frame.payload, b"hello");
		assert_eq!(frame.header.ppid.get(), 51);
		assert!(frame.header.has(flags::EOR));
		assert!(frame.header.has(flags::UNORDERED));
		assert!(!frame.header.has(flags::CONTROL));
		assert_eq!(frame.wire_len(), buf.len());
	}

	#[test]
	fn empty_payload_is_a_frame() {
		let mut buf = Vec::new();
		encode(&mut buf, 57, flags::EOR, b"");
		let frame = Frame::parse(&buf).unwrap().expect("a whole frame");
		assert_eq!(frame.payload, b"");
		assert_eq!(frame.wire_len(), Header::LEN);
	}

	/// A short read is not an error: peek again rather than buffering.
	#[test]
	fn partial_frames_are_incomplete_not_invalid() {
		let mut buf = Vec::new();
		encode(&mut buf, 53, flags::EOR, b"0123456789");
		for cut in 0..buf.len() {
			assert_eq!(Frame::parse(&buf[..cut]), Ok(None), "cut at {cut}");
		}
		assert!(Frame::parse(&buf).unwrap().is_some());
	}

	/// Only the first frame is returned; the rest stays for the next call.
	#[test]
	fn parses_one_frame_at_a_time() {
		let mut first = Vec::new();
		encode(&mut first, 51, flags::EOR, b"one");
		let mut second = Vec::new();
		encode(&mut second, 53, flags::EOR, b"two");
		let both = [first.clone(), second].concat();

		let frame = Frame::parse(&both).unwrap().unwrap();
		assert_eq!(frame.payload, b"one");
		assert_eq!(frame.wire_len(), first.len());

		let frame = Frame::parse(&both[frame.wire_len()..]).unwrap().unwrap();
		assert_eq!(frame.payload, b"two");
	}

	/// An extension that claims an enormous payload has to be refused rather
	/// than waited on: we could never peek a frame that big.
	#[test]
	fn oversize_is_rejected() {
		let mut buf = Vec::new();
		buf.extend_from_slice(Header::new(51, flags::EOR, MAX_PAYLOAD + 1).as_bytes());
		assert_eq!(Frame::parse(&buf), Err(Oversize(MAX_PAYLOAD as u32 + 1)));

		// The largest legal frame is still accepted.
		let mut ok = Vec::new();
		encode(&mut ok, 51, flags::EOR, &vec![0u8; MAX_PAYLOAD]);
		assert!(Frame::parse(&ok).unwrap().is_some());
	}
}

#[cfg(test)]
mod interop {
	use super::*;

	/// Byte-for-byte vectors, cross-checked against `src/chan.js` by
	/// `scripts/chan-interop.js`.  If either side changes shape, one of the two
	/// stops matching these.
	#[test]
	fn wire_vectors() {
		let mut buf = Vec::new();

		encode(&mut buf, 51, flags::EOR, b"hi");
		assert_eq!(
			buf,
			[0, 0, 0, 2, 0, 0, 0, 51, 0, 1, 0, 0, b'h', b'i'],
			"string message"
		);

		encode(&mut buf, 53, flags::EOR | flags::UNORDERED, &[0xde, 0xad]);
		assert_eq!(
			buf,
			[0, 0, 0, 2, 0, 0, 0, 53, 0, 3, 0, 0, 0xde, 0xad],
			"unordered binary message"
		);

		encode(&mut buf, 0, flags::CONTROL | flags::EOR, b"{}");
		assert_eq!(
			buf,
			[0, 0, 0, 2, 0, 0, 0, 0, 0x80, 1, 0, 0, b'{', b'}'],
			"control message"
		);

		encode(&mut buf, 57, flags::EOR, b"");
		assert_eq!(
			buf,
			[0, 0, 0, 0, 0, 0, 0, 57, 0, 1, 0, 0],
			"empty binary message"
		);
	}
}
