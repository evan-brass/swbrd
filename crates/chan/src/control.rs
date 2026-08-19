//! Control messages: the frames carrying [`flags::CONTROL`](crate::flags::CONTROL).
//!
//! JSON rather than a packed format, because these are sent once per channel
//! rather than per message, and because an extension written in Deno gets
//! `JSON.parse` for free where CBOR would cost it a dependency.

use serde::{Deserialize, Serialize};

use crate::dcep;

/// Tagged by `op`, so an extension can match on one field and unknown
/// operations stay forward compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Control {
	/// Daemon to extension, always the first frame on a channel.
	Open(Open),
	/// Extension to daemon: refuse this channel.  Silence means acceptance, so
	/// this only exists to give a reason.
	Reject { reason: Option<String> },
	/// Extension to daemon on the dial socket: open a channel toward a peer.
	Dial(Dial),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open {
	/// The peer's certificate fingerprint, lowercase hex.  Its identity.
	pub fp: String,
	/// The same fingerprint as the base36 id the browser prints.
	pub id: String,
	pub label: String,
	pub protocol: String,
	pub stream: u16,
	pub ordered: bool,
	pub reliability: Reliability,
	pub priority: u16,
	pub initiator: Initiator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dial {
	/// Base36 id of the peer to open a channel toward.
	pub id: String,
	pub label: String,
	pub protocol: String,
	#[serde(default)]
	pub ordered: bool,
	#[serde(default)]
	pub reliability: Reliability,
	#[serde(default)]
	pub priority: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Initiator {
	/// The browser asked for this channel.
	Peer,
	/// We did.
	Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Reliability {
	#[default]
	Reliable,
	/// Abandon after `value` retransmissions.
	Rexmit { value: u32 },
	/// Abandon after `value` milliseconds.
	Timed { value: u32 },
}

impl From<dcep::Reliability> for Reliability {
	fn from(r: dcep::Reliability) -> Self {
		match r {
			dcep::Reliability::Reliable => Self::Reliable,
			dcep::Reliability::Rexmit(value) => Self::Rexmit { value },
			dcep::Reliability::Timed(value) => Self::Timed { value },
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn round_trip(control: &Control) -> Control {
		let json = serde_json::to_string(control).unwrap();
		serde_json::from_str(&json).unwrap()
	}

	#[test]
	fn open_round_trips() {
		let open = Control::Open(Open {
			fp: "ab".repeat(32),
			id: "4dv781cf88phj16xeqr4l2r0po19nycigjj2v5ss8m2l2y5t05".into(),
			label: "chat".into(),
			protocol: "chat.v1".into(),
			stream: 2,
			ordered: true,
			reliability: Reliability::Timed { value: 3000 },
			priority: 512,
			initiator: Initiator::Peer,
		});
		assert_eq!(round_trip(&open), open);
	}

	/// The shape an extension actually matches on.
	#[test]
	fn open_is_tagged_by_op() {
		let json = serde_json::to_string(&Control::Reject { reason: None }).unwrap();
		let value: serde_json::Value = serde_json::from_str(&json).unwrap();
		assert_eq!(value["op"], "reject");
	}

	/// Labels come from the browser, so they carry whatever the peer chose --
	/// quotes, newlines and non-ASCII included.  This is exactly why the control
	/// plane is JSON and not hand-rolled string concatenation.
	#[test]
	fn hostile_labels_survive() {
		for label in [
			"quote\"inside",
			"newline\nhere",
			"back\\slash",
			"emoji 🎛️ and ünïcode",
			"null\u{0}byte",
		] {
			let open = Control::Open(Open {
				fp: String::new(),
				id: String::new(),
				label: label.into(),
				protocol: String::new(),
				stream: 0,
				ordered: false,
				reliability: Reliability::Reliable,
				priority: 0,
				initiator: Initiator::Peer,
			});
			let Control::Open(back) = round_trip(&open) else {
				panic!("not an open");
			};
			assert_eq!(back.label, label);
		}
	}

	#[test]
	fn dial_defaults_are_optional() {
		let dial: Control =
			serde_json::from_str(r#"{"op":"dial","id":"abc","label":"l","protocol":"p"}"#).unwrap();
		let Control::Dial(dial) = dial else {
			panic!("not a dial");
		};
		assert_eq!(dial.reliability, Reliability::Reliable);
		assert_eq!(dial.priority, 0);
	}

	#[test]
	fn dcep_reliability_maps_across() {
		assert_eq!(
			Reliability::from(dcep::Reliability::Rexmit(3)),
			Reliability::Rexmit { value: 3 }
		);
		assert_eq!(
			Reliability::from(dcep::Reliability::Timed(50)),
			Reliability::Timed { value: 50 }
		);
		assert_eq!(
			Reliability::from(dcep::Reliability::Reliable),
			Reliability::Reliable
		);
	}
}
