//! Everything the poller can deliver an event for.
//!
//! A trunk has two sources (its DTLS socket and its SCTP circuit) and a channel
//! has one, but channels are unbounded in number, so they cannot simply be more
//! flags on a trunk.  Both are therefore [`Node`]s, and the poller is generic
//! over that.
//!
//! The intrusive links live on `Node` rather than inside the variants because
//! `intrusive-collections` needs a fixed offset from the container pointer,
//! which an enum variant cannot give it.  Only trunks are ever linked; a
//! channel's links stay untouched, and its `bound` is a copy of its trunk's so
//! the tree's key accessor is always reading something real.

use std::{
	cell::{Cell, RefCell},
	collections::HashMap,
	net::SocketAddrV6,
	os::fd::{AsRawFd, RawFd},
	rc::{Rc, Weak},
	time::Instant,
};

use common::poller::{Flag, Sourced};
use dtls::{fingerprint::Fingerprint, keys::ReadKeys};
use intrusive_collections::{KeyAdapter, LinkedListLink, RBTreeLink, intrusive_adapter};
use openssl::ssl::Ssl;
use sctp::Sctp;
use socket2::Socket;

/// A trunk's DTLS socket.
pub const DTLS: Flag = Flag::A;
/// A trunk's SCTP circuit.
pub const CIRCUIT: Flag = Flag::B;
/// A channel's connection to its extension.
pub const EXTENSION: Flag = Flag::A;

pub struct Node {
	/// The relayed address of the trunk this node belongs to: the key of the
	/// `bound` tree for a trunk, and merely informational for a channel.
	pub bound: SocketAddrV6,
	pub bound_link: RBTreeLink,
	pub timeout: Cell<Instant>,
	pub timeout_link: LinkedListLink,
	pub kind: Kind,
}

pub enum Kind {
	Trunk(Trunk),
	Channel(Channel),
}

impl Node {
	pub fn trunk(&self) -> Option<&Trunk> {
		match &self.kind {
			Kind::Trunk(trunk) => Some(trunk),
			Kind::Channel(_) => None,
		}
	}
	pub fn channel(&self) -> Option<&Channel> {
		match &self.kind {
			Kind::Channel(channel) => Some(channel),
			Kind::Trunk(_) => None,
		}
	}
}

impl Sourced for Node {
	fn fd(&self, flag: Flag) -> Option<RawFd> {
		match (&self.kind, flag) {
			(Kind::Trunk(trunk), DTLS) => Some(trunk.sock.as_raw_fd()),
			(Kind::Trunk(trunk), CIRCUIT) => trunk.circuit.borrow().as_ref().map(|c| c.as_raw_fd()),
			(Kind::Channel(channel), EXTENSION) => Some(channel.sock.as_raw_fd()),
			_ => None,
		}
	}
}

/// One peer's DTLS connection.
///
/// Field order matters: `ssl` is declared before `sock` so it drops first.  The
/// dgram BIO borrows the socket's fd with `BIO_NOCLOSE`, so freeing the `Ssl`
/// while the fd is still open is the only safe order.
pub struct Trunk {
	pub ssl: RefCell<Ssl>,
	/// Connected transparent socket (owns the fd the dgram BIO borrows).
	pub sock: Socket,
	pub established: Cell<bool>,
	/// The peer's certificate fingerprint: its identity, taken once the
	/// handshake finishes.  `None` until then.
	pub fingerprint: Cell<Option<Fingerprint>>,
	/// Read-direction (client write) keys, derived lazily once established and
	/// used to authenticate roamed records for client mobility.
	pub read_keys: Cell<Option<ReadKeys>>,
	/// Highest record number authenticated for mobility so far; a roamed record
	/// must strictly exceed it to re-point the socket (anti-replay).
	pub highest_read_seq: Cell<u64>,

	/// Our index in `subscribers`, and the low 32 bits of the address we inject
	/// this connection's plaintext from.
	pub index: u32,
	/// Where the socket currently points.  Mobility moves this.
	pub connected: Cell<SocketAddrV6>,
	/// This peer's SCTP association, once the kernel has formed one and we have
	/// attributed it back here.  One socket per association, so a wedged peer
	/// cannot fill a send buffer shared with anyone else.
	pub circuit: RefCell<Option<Sctp>>,
	/// The channels patched through this trunk, by SCTP stream id.
	pub channels: RefCell<HashMap<u16, Rc<Node>>>,
	/// Set while the circuit's readable interest is off because a channel is
	/// not draining.  Holding one stalls every channel on this trunk, which is
	/// the honest cost of SCTP having no per-stream flow control.
	pub stalled_by: Cell<Option<u16>>,
	/// When the current stall started, so a channel that never drains takes the
	/// circuit down instead of wedging it forever.
	pub stalled_since: Cell<Option<Instant>>,
	/// Streams whose channels stopped being read because the circuit's send
	/// buffer was full.  They are re-armed as soon as the circuit reports it can
	/// write again.
	pub waiting_on_circuit: RefCell<Vec<u16>>,
}

/// One datachannel, patched to one extension connection.
pub struct Channel {
	/// The connection to the extension.  Its lifetime is the channel's:
	/// connecting opened it, EOF is a half close, and closing ends it.
	pub sock: Socket,
	/// The SCTP stream this channel rides on.
	pub stream: u16,
	/// The trunk this channel belongs to.  Weak, so a channel never keeps its
	/// trunk alive.
	pub trunk: Weak<Node>,
	pub ordered: Cell<bool>,
	pub reliability: Cell<PrPolicy>,
	/// How long this channel may block its circuit before the circuit dies.
	pub stall_ms: u64,
	/// How much of the frame currently being handed over has already been
	/// written.  Not a buffer: the message itself is still sitting unconsumed in
	/// the SCTP receive queue, and re-peeking it re-encodes byte-identical
	/// bytes, so a cursor is all that is needed to finish a partial write.
	pub written: Cell<usize>,
	/// Set once the extension has been told who it is talking to.
	pub opened: Cell<bool>,
	/// Set when the extension has closed its writing half, so the stream has
	/// already been reset outbound.
	pub half_closed: Cell<bool>,
}

/// A partial-reliability policy, in the form `sctp_prinfo` wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrPolicy {
	pub policy: u16,
	pub value: u32,
}

intrusive_adapter!(pub Bound = Rc<Node>: Node { bound_link => RBTreeLink });
intrusive_adapter!(pub Timeout = Rc<Node>: Node { timeout_link => LinkedListLink });
impl<'a> KeyAdapter<'a> for Bound {
	type Key = &'a SocketAddrV6;
	fn get_key(
		&self,
		value: &'a <Self::PointerOps as intrusive_collections::PointerOps>::Value,
	) -> Self::Key {
		&value.bound
	}
}
