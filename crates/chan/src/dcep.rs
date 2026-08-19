//! DCEP (RFC 8832): how a browser asks for a datachannel.
//!
//! Only two messages matter here.  The peer sends `DATA_CHANNEL_OPEN` naming a
//! label and a protocol; we answer `DATA_CHANNEL_ACK` once an extension has
//! taken the channel, or reset the stream if none will.

/// DCEP rides on its own payload protocol id.
pub const PPID: u32 = 50;

pub const DATA_CHANNEL_ACK: u8 = 0x02;
pub const DATA_CHANNEL_OPEN: u8 = 0x03;

/// The one-byte ack, which is the whole message.
pub const ACK: [u8; 1] = [DATA_CHANNEL_ACK];

/// The reliability half of a DCEP channel type, with the unordered bit removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
	/// Retransmit until it arrives.
	Reliable,
	/// Give up after this many retransmissions.
	Rexmit(u32),
	/// Give up after this many milliseconds.
	Timed(u32),
}

/// A DCEP channel type byte, split into the two things it actually encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelType {
	pub reliability: Reliability,
	pub ordered: bool,
}

impl ChannelType {
	/// The high bit means unordered; the low bits pick the reliability policy.
	pub fn parse(channel_type: u8, parameter: u32) -> Option<Self> {
		let reliability = match channel_type & 0x7f {
			0x00 => Reliability::Reliable,
			0x01 => Reliability::Rexmit(parameter),
			0x02 => Reliability::Timed(parameter),
			_ => return None,
		};
		Some(Self {
			reliability,
			ordered: channel_type & 0x80 == 0,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn every_channel_type_in_rfc8832() {
		let cases = [
			(0x00, Reliability::Reliable, true),
			(0x01, Reliability::Rexmit(7), true),
			(0x02, Reliability::Timed(7), true),
			(0x80, Reliability::Reliable, false),
			(0x81, Reliability::Rexmit(7), false),
			(0x82, Reliability::Timed(7), false),
		];
		for (byte, reliability, ordered) in cases {
			assert_eq!(
				ChannelType::parse(byte, 7),
				Some(ChannelType {
					reliability,
					ordered
				}),
				"channel type {byte:#04x}",
			);
		}
	}

	/// The reliability parameter is meaningless for a reliable channel, and the
	/// browser is entitled to send anything there.
	#[test]
	fn reliable_ignores_its_parameter() {
		assert_eq!(
			ChannelType::parse(0x00, 12345).unwrap().reliability,
			Reliability::Reliable
		);
	}

	#[test]
	fn unknown_channel_types_are_refused() {
		for byte in [0x03, 0x04, 0x7f, 0x83, 0xff] {
			assert_eq!(ChannelType::parse(byte, 0), None, "{byte:#04x}");
		}
	}
}
