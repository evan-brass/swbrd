//! The exchange: patching a peer's datachannels through to extensions.
//!
//! # Backpressure
//!
//! The daemon owns no queues.  Every byte sits in a kernel socket buffer until
//! it has been handed to the next kernel socket buffer, which is achieved by
//! peeking rather than reading: look at a message with `MSG_PEEK`, try to write
//! it on, and only consume it from the source once the write has fully
//! succeeded.  If the write blocks, nothing is consumed and nothing is stored --
//! the data simply stays where it was, and the socket it is sitting in stops
//! accepting more.
//!
//! Peer to extension, that means the SCTP receive queue holds the message and
//! the peer's rwnd never opens for it.  Extension to peer, it means the Unix
//! socket's receive queue holds it and the extension's own `write` blocks.
//!
//! The cost is one extra copy per message.  In exchange there is no per-channel
//! pending buffer, and no question of which message is being held for whom.
//!
//! SCTP has no per-stream flow control, so stalling on one channel stalls the
//! whole circuit.  That is accepted deliberately: a channel that never drains
//! takes its circuit down rather than wedging it, and a channel that expects to
//! shed load says so with partial reliability, where the peer's own stack
//! abandons messages before anything backs up.

use std::{
	io::{Error, ErrorKind},
	os::fd::{AsRawFd, RawFd},
	rc::Rc,
	time::Instant,
};

use chan::{Frame, control, dcep, flags};
use common::DcepOpenHeader;
use dtls::fingerprint;
use mio::Interest;
use sctp::{
	DataNotif, Notif, SCTP_PR_SCTP_NONE, SCTP_PR_SCTP_RTX, SCTP_PR_SCTP_TTL,
	SCTP_STREAM_RESET_INCOMING, SCTP_STREAM_RESET_OUTGOING, SCTP_UNORDERED, sctp_prinfo,
	sctp_rcvinfo, sctp_reset_streams, sctp_sndinfo, write_control,
};
use socket2::{Domain, MsgHdr, SockAddr, Socket, Type};
use zerocopy::FromZeros;

use crate::{
	Server,
	node::{CIRCUIT, Channel, EXTENSION, Kind, Node, PrPolicy, Trunk},
};

/// Peek at what is waiting without consuming it.
fn peek(fd: RawFd, buf: &mut [u8]) -> Result<usize, Error> {
	let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_PEEK) };
	if n < 0 {
		return Err(Error::last_os_error());
	}
	Ok(n as usize)
}

/// Take `len` bytes off the front for real, now that they have been handed on.
fn consume(fd: RawFd, buf: &mut [u8], len: usize) -> Result<usize, Error> {
	let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, 0) };
	if n < 0 {
		return Err(Error::last_os_error());
	}
	Ok(n as usize)
}

/// What one turn of the circuit loop decided to do, computed while the receive
/// buffer is borrowed and acted on once it is not.
enum Step {
	/// The message was handed on; take it off the queue.
	Consume,
	/// A DCEP message, copied out because it is small and needs parsing.
	Dcep(u16, Vec<u8>),
	/// Nothing to read right now.
	Idle,
	/// Interrupted; go round again.
	Again,
	/// This stream has no channel, so the message goes nowhere.
	Unpatched(u16),
	/// The channel would block: leave the message where it is and stop reading
	/// the circuit until it drains.
	Stall(u16, Rc<Node>),
	/// The extension is gone.
	ChannelDead(Rc<Node>),
	/// A notification rather than data.
	Notification(&'static str),
	Fatal,
}

impl Server {
	/// Drain a peer's association: DCEP asks for channels, everything else is
	/// relayed to the channel its stream is patched to.
	pub fn drive_circuit(&mut self, node: Rc<Node>, buffer: &mut [u8]) {
		let Some(trunk) = node.trunk() else {
			return;
		};
		// Any event here means the circuit moved; channels parked waiting for
		// room to send can go back to being read.
		self.rearm_waiting(&node, trunk);
		loop {
			let mut rcvinfo = sctp_rcvinfo::new_zeroed();
			let step = {
				let circuit = trunk.circuit.borrow();
				let Some(sctp) = circuit.as_ref() else {
					return;
				};
				match sctp.recvmsg(buffer, &mut [&mut rcvinfo], libc::MSG_PEEK) {
					Err(e) if e.kind() == ErrorKind::WouldBlock => Step::Idle,
					Err(e) if e.kind() == ErrorKind::Interrupted => Step::Again,
					Err(err) => {
						tracing::debug!(index = trunk.index, %err, "circuit read failed");
						Step::Fatal
					}
					Ok(DataNotif::Notif(notif)) => Step::Notification(match notif {
						Notif::AssocChange(_) => "assoc change",
						Notif::ShutdownEvent(_) => "shutdown",
						Notif::StreamReset(_) => "stream reset",
						Notif::SendFailedEvent(_) => "send failed",
						Notif::PdapiEvent(_) => "partial delivery",
						_ => "other",
					}),
					Ok(DataNotif::Data(recv_flags, data)) => {
						let stream = rcvinfo.rcv_sid;
						let ppid = u32::from_be(rcvinfo.rcv_ppid);
						if ppid == dcep::PPID {
							Step::Dcep(stream, data.to_vec())
						} else {
							let existing = trunk.channels.borrow().get(&stream).cloned();
							match existing {
								None => Step::Unpatched(stream),
								Some(chan_node) => {
									let mut frame_flags = 0;
									if recv_flags.is_end_of_record() {
										frame_flags |= flags::EOR;
									}
									match self.send_to_extension(
										&chan_node,
										ppid,
										frame_flags,
										data,
									) {
										Ok(true) => Step::Consume,
										Ok(false) => Step::Stall(stream, chan_node),
										Err(_) => Step::ChannelDead(chan_node),
									}
								}
							}
						}
					}
				}
			};

			// The receive buffer is free again, so consuming is safe.
			let mut take = |server: &mut Self| {
				let circuit = trunk.circuit.borrow();
				if let Some(sctp) = circuit.as_ref() {
					let _ = sctp.recvmsg(buffer, &mut [], 0);
				}
				drop(circuit);
				server.touch(&node);
			};

			match step {
				Step::Consume => {
					take(self);
					// A message got all the way through, so whatever this circuit
					// was stalled on has cleared.
					if trunk.stalled_by.get().is_some() {
						self.clear_stall(&node, trunk);
					}
				}
				Step::Again => continue,
				Step::Idle => return,
				Step::Notification(kind) => {
					take(self);
					tracing::debug!(index = trunk.index, kind, "circuit notification");
				}
				Step::Dcep(stream, message) => {
					take(self);
					self.handle_dcep(&node, trunk, stream, &message);
				}
				Step::Unpatched(stream) => {
					take(self);
					tracing::debug!(
						index = trunk.index,
						stream,
						"message on an unpatched stream"
					);
					self.reset_stream(
						trunk,
						stream,
						SCTP_STREAM_RESET_INCOMING | SCTP_STREAM_RESET_OUTGOING,
					);
				}
				Step::Stall(stream, chan_node) => {
					// Nothing consumed: the message stays in the SCTP receive
					// queue, so the peer's rwnd stays shut on it.
					self.stall_circuit(&node, trunk, stream, &chan_node);
					return;
				}
				Step::ChannelDead(chan_node) => {
					take(self);
					self.close_channel(chan_node);
				}
				Step::Fatal => return self.remove_conn(node),
			}
		}
	}

	/// Put back the read interest on every channel that was parked because the
	/// circuit had no room, and drop the circuit's write interest with them.
	fn rearm_waiting(&mut self, node: &Rc<Node>, trunk: &Trunk) {
		let waiting = std::mem::take(&mut *trunk.waiting_on_circuit.borrow_mut());
		if waiting.is_empty() {
			return;
		}
		for stream in waiting {
			let channel = trunk.channels.borrow().get(&stream).cloned();
			if let Some(chan_node) = channel {
				let _ = self
					.poll
					.register(&chan_node, EXTENSION, Interest::READABLE);
			}
		}
		// Back to caring only about readability.
		let _ = self.poll.deregister(node, CIRCUIT);
		let _ = self.poll.register(node, CIRCUIT, Interest::READABLE);
	}

	/// Stop reading this circuit until `chan_node` can take what is waiting.
	fn stall_circuit(&mut self, node: &Rc<Node>, trunk: &Trunk, stream: u16, chan_node: &Rc<Node>) {
		if trunk.stalled_by.get() == Some(stream) {
			return;
		}
		let _ = self.poll.deregister(node, CIRCUIT);
		let _ = self.poll.deregister(chan_node, EXTENSION);
		let _ = self.poll.register(
			chan_node,
			EXTENSION,
			Interest::READABLE | Interest::WRITABLE,
		);
		trunk.stalled_by.set(Some(stream));
		let now = Instant::now();
		trunk.stalled_since.set(Some(now));
		let deadline = now
			+ std::time::Duration::from_millis(chan_node.channel().map_or(5_000, |c| c.stall_ms));
		self.stalls.push((deadline, Rc::downgrade(node)));
		tracing::debug!(index = trunk.index, stream, "circuit stalled on a channel");
	}

	/// The stalled channel took what it was holding up: put the circuit and the
	/// channel back on their ordinary interests.
	fn clear_stall(&mut self, node: &Rc<Node>, trunk: &Trunk) {
		let Some(stream) = trunk.stalled_by.take() else {
			return;
		};
		trunk.stalled_since.set(None);
		let channel = trunk.channels.borrow().get(&stream).cloned();
		if let Some(chan_node) = channel {
			let _ = self.poll.deregister(&chan_node, EXTENSION);
			let _ = self
				.poll
				.register(&chan_node, EXTENSION, Interest::READABLE);
		}
		let _ = self.poll.register(node, CIRCUIT, Interest::READABLE);
		tracing::debug!(index = trunk.index, stream, "circuit resumed");
	}

	/// Frame a peer message and hand it to the extension.  `Ok(false)` means it
	/// did not all fit, so the caller must not consume anything.
	///
	/// A short write is normal rather than fatal: the socket reports itself
	/// writable when it has *any* room, not room for a whole frame.  What is
	/// written is remembered as a cursor, and because the message is still
	/// sitting unconsumed in the SCTP receive queue, re-peeking it later
	/// re-encodes exactly the same bytes to resume from.  That is what keeps a
	/// retry from spinning: every writable event moves the cursor forward.
	fn send_to_extension(
		&mut self,
		chan_node: &Rc<Node>,
		ppid: u32,
		frame_flags: u16,
		data: &[u8],
	) -> Result<bool, Error> {
		let Some(channel) = chan_node.channel() else {
			return Ok(true);
		};
		chan::encode(&mut self.scratch, ppid, frame_flags, data);
		let already = channel.written.get();
		debug_assert!(
			already <= self.scratch.len(),
			"cursor past the frame it indexes"
		);
		let rest = &self.scratch[already.min(self.scratch.len())..];
		match write_some(channel.sock.as_raw_fd(), rest)? {
			None => Ok(false),
			Some(n) => {
				let total = already + n;
				if total == self.scratch.len() {
					channel.written.set(0);
					Ok(true)
				} else {
					channel.written.set(total);
					Ok(false)
				}
			}
		}
	}

	/// A DCEP message from the peer.  `DATA_CHANNEL_OPEN` is a request for a
	/// channel; the ack is the only other thing we expect to see.
	fn handle_dcep(&mut self, node: &Rc<Node>, trunk: &Trunk, stream: u16, message: &[u8]) {
		match message.first().copied() {
			Some(dcep::DATA_CHANNEL_ACK) => {
				tracing::debug!(index = trunk.index, stream, "datachannel ack");
			}
			Some(dcep::DATA_CHANNEL_OPEN) => {
				if let Err(err) = self.open_channel(node, trunk, stream, message) {
					tracing::info!(index = trunk.index, stream, %err, "refusing datachannel");
					self.reset_stream(
						trunk,
						stream,
						SCTP_STREAM_RESET_INCOMING | SCTP_STREAM_RESET_OUTGOING,
					);
				}
			}
			_ => {
				tracing::warn!(index = trunk.index, stream, "unrecognized DCEP message");
			}
		}
	}

	/// Patch a requested datachannel through to whichever extension the
	/// directory names for its protocol.
	fn open_channel(
		&mut self,
		node: &Rc<Node>,
		trunk: &Trunk,
		stream: u16,
		message: &[u8],
	) -> Result<(), Error> {
		let Some((header, label, protocol)) = DcepOpenHeader::parse(message) else {
			return Err(Error::new(ErrorKind::InvalidData, "malformed DCEP open"));
		};
		let Some(channel_type) =
			dcep::ChannelType::parse(header.channel_typ, header.reliability_parameter.get())
		else {
			return Err(Error::new(ErrorKind::InvalidData, "unknown channel type"));
		};
		let Some(fp) = trunk.fingerprint.get() else {
			return Err(Error::new(
				ErrorKind::PermissionDenied,
				"peer not identified",
			));
		};
		let id = fingerprint::base36(&fp);

		let Some(extension) = self.directory.lookup(protocol, &id) else {
			return Err(Error::new(
				ErrorKind::NotFound,
				format!("no extension serves {protocol:?}"),
			));
		};
		let extension = extension.clone();

		if trunk.channels.borrow().contains_key(&stream) {
			return Err(Error::new(
				ErrorKind::AlreadyExists,
				"stream already patched",
			));
		}

		let sock = Socket::new(Domain::UNIX, Type::STREAM, None)?;
		sock.connect(&SockAddr::unix(&extension.socket)?)?;
		sock.set_nonblocking(true)?;

		let chan_node = Rc::new(Node {
			bound: node.bound,
			bound_link: Default::default(),
			timeout: std::cell::Cell::new(Instant::now()),
			timeout_link: Default::default(),
			kind: Kind::Channel(Channel {
				sock,
				stream,
				trunk: Rc::downgrade(node),
				ordered: std::cell::Cell::new(channel_type.ordered),
				reliability: std::cell::Cell::new(pr_policy(channel_type.reliability)),
				stall_ms: extension.stall_ms,
				written: std::cell::Cell::new(0),
				opened: std::cell::Cell::new(false),
				half_closed: std::cell::Cell::new(false),
			}),
		});

		// The extension learns who it is talking to before it sees a byte of
		// their data.
		let open = control::Control::Open(control::Open {
			fp: hex(&fp),
			id,
			label: label.to_owned(),
			protocol: protocol.to_owned(),
			stream,
			ordered: channel_type.ordered,
			reliability: channel_type.reliability.into(),
			priority: extension.priority,
			initiator: control::Initiator::Peer,
		});
		let json = serde_json::to_vec(&open).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
		chan::encode(&mut self.scratch, 0, flags::CONTROL | flags::EOR, &json);
		let channel = chan_node.channel().expect("just built a channel");
		// The open frame is small and the socket is fresh, so anything less than
		// the whole thing means the extension is not in a state to serve.
		let wrote = write_some(channel.sock.as_raw_fd(), &self.scratch)?;
		if wrote != Some(self.scratch.len()) {
			return Err(Error::new(
				ErrorKind::WouldBlock,
				"extension would not take the open frame",
			));
		}
		channel.opened.set(true);

		self.poll
			.register(&chan_node, EXTENSION, Interest::READABLE)?;
		trunk.channels.borrow_mut().insert(stream, chan_node);

		// Only now is the channel real, so only now do we ack it.
		self.send_to_peer(
			trunk,
			stream,
			dcep::PPID,
			true,
			false,
			&dcep::ACK,
			PrPolicy {
				policy: SCTP_PR_SCTP_NONE,
				value: 0,
			},
		);
		tracing::info!(
			index = trunk.index,
			stream,
			extension = %extension.name,
			label,
			protocol,
			mode = ?extension.mode,
			"channel patched",
		);
		Ok(())
	}

	/// An extension has something to say, or has gone away.
	pub fn drive_channel(&mut self, chan_node: Rc<Node>, buffer: &mut [u8]) {
		let Some(channel) = chan_node.channel() else {
			return;
		};
		let Some(trunk_node) = channel.trunk.upgrade() else {
			return self.close_channel(chan_node);
		};
		let Some(trunk) = trunk_node.trunk() else {
			return;
		};

		// If this channel is what stalled the circuit, the only useful thing a
		// writable event means is "try again": push the stalled frame further
		// along.  Clearing the stall first and hoping would just re-stall on the
		// next read, which is a spin rather than progress.
		if trunk.stalled_by.get() == Some(channel.stream) {
			self.drive_circuit(trunk_node.clone(), buffer);
			if trunk.stalled_by.get().is_some() {
				// Still stuck; the socket will tell us when there is more room.
				return;
			}
		}

		let fd = channel.sock.as_raw_fd();
		loop {
			let available = match peek(fd, buffer) {
				Ok(0) => {
					// EOF: the extension closed its writing half, which is a
					// half close of the channel.
					return self.half_close(trunk, channel, &chan_node);
				}
				Ok(n) => n,
				Err(e) if e.kind() == ErrorKind::WouldBlock => return,
				Err(e) if e.kind() == ErrorKind::Interrupted => continue,
				Err(err) => {
					tracing::debug!(stream = channel.stream, %err, "channel read failed");
					return self.close_channel(chan_node);
				}
			};

			let frame = match Frame::parse(&buffer[..available]) {
				Ok(Some(frame)) => frame,
				// Not all here yet: peek again when there is more.  Nothing is
				// consumed and nothing is buffered.
				Ok(None) => return,
				Err(err) => {
					tracing::warn!(stream = channel.stream, %err, "extension sent a bad frame");
					return self.close_channel(chan_node);
				}
			};

			let wire_len = frame.wire_len();
			let ppid = frame.header.ppid.get();
			let eor = frame.header.has(flags::EOR);
			let unordered = frame.header.has(flags::UNORDERED) || !channel.ordered.get();
			// A peer must never be able to make an extension's frame look like
			// control, nor the reverse.
			if frame.header.has(flags::CONTROL) {
				let control: Result<control::Control, _> = serde_json::from_slice(frame.payload);
				match control {
					Ok(control::Control::Reject { reason }) => {
						tracing::info!(stream = channel.stream, ?reason, "extension rejected");
						return self.close_channel(chan_node);
					}
					Ok(other) => {
						tracing::warn!(stream = channel.stream, ?other, "unexpected control")
					}
					Err(err) => tracing::warn!(stream = channel.stream, %err, "bad control"),
				}
				let _ = consume(fd, buffer, wire_len);
				continue;
			}

			let sent = self.send_to_peer(
				trunk,
				channel.stream,
				ppid,
				eor,
				unordered,
				frame.payload,
				channel.reliability.get(),
			);
			if !sent {
				// The circuit's send buffer is full.  Consume nothing: the frame
				// stays in this socket's receive queue and the extension's own
				// write blocks, which is the backpressure.
				let _ = self.poll.deregister(&chan_node, EXTENSION);
				let _ = self.poll.register(
					&trunk_node,
					CIRCUIT,
					Interest::READABLE | Interest::WRITABLE,
				);
				return;
			}
			let _ = consume(fd, buffer, wire_len);
			self.touch(&trunk_node);
		}
	}

	/// Send one message to the peer.  False means the circuit would block.
	#[allow(clippy::too_many_arguments)]
	fn send_to_peer(
		&self,
		trunk: &Trunk,
		stream: u16,
		ppid: u32,
		eor: bool,
		unordered: bool,
		payload: &[u8],
		pr: PrPolicy,
	) -> bool {
		let circuit = trunk.circuit.borrow();
		let Some(sctp) = circuit.as_ref() else {
			return false;
		};
		let mut control = Vec::with_capacity(256);
		write_control(
			&mut control,
			&[
				&sctp_sndinfo {
					snd_sid: stream,
					snd_flags: if unordered { SCTP_UNORDERED } else { 0 },
					snd_ppid: ppid.to_be(),
					snd_context: 0,
					snd_assoc_id: 0,
				},
				&sctp_prinfo {
					pr_policy: pr.policy,
					pr_value: pr.value,
				},
			],
		);
		let iov = [std::io::IoSlice::new(payload)];
		let msg = MsgHdr::new().with_buffers(&iov).with_control(&control);
		let flags = if eor { libc::MSG_EOR } else { 0 };
		match sctp.sendmsg(&msg, flags) {
			Ok(_) => true,
			Err(e) if e.kind() == ErrorKind::WouldBlock => false,
			Err(err) => {
				tracing::debug!(stream, %err, "sendmsg to peer failed");
				false
			}
		}
	}

	/// Reset a stream in the given directions.
	fn reset_stream(&self, trunk: &Trunk, stream: u16, direction: u16) {
		let circuit = trunk.circuit.borrow();
		let Some(sctp) = circuit.as_ref() else {
			return;
		};
		let Ok(mut reset) = sctp_reset_streams::new_box_zeroed_with_elems(1) else {
			return;
		};
		reset.srs_flags = direction;
		reset.srs_assoc_id = 0;
		reset.srs_number_streams = 1;
		reset.srs_stream_list[0] = stream;
		if let Err(err) = sctp.set_reset_streams(&reset) {
			tracing::debug!(stream, ?err, "stream reset failed");
		}
	}

	/// The extension stopped writing: reset our outgoing half of the stream and
	/// leave the peer's half alone.
	fn half_close(&mut self, trunk: &Trunk, channel: &Channel, chan_node: &Rc<Node>) {
		if channel.half_closed.get() {
			return;
		}
		channel.half_closed.set(true);
		self.reset_stream(trunk, channel.stream, SCTP_STREAM_RESET_OUTGOING);
		let _ = self.poll.deregister(chan_node, EXTENSION);
		tracing::debug!(stream = channel.stream, "channel half closed");
	}

	/// Tear a channel down completely.
	pub fn close_channel(&mut self, chan_node: Rc<Node>) {
		let Some(channel) = chan_node.channel() else {
			return;
		};
		let _ = self.poll.deregister(&chan_node, EXTENSION);
		if let Some(trunk_node) = channel.trunk.upgrade()
			&& let Some(trunk) = trunk_node.trunk()
		{
			trunk.channels.borrow_mut().remove(&channel.stream);
			if !channel.half_closed.get() {
				self.reset_stream(
					trunk,
					channel.stream,
					SCTP_STREAM_RESET_INCOMING | SCTP_STREAM_RESET_OUTGOING,
				);
			}
			// Whatever this channel was holding up, it is not holding up now.
			if trunk.stalled_by.get() == Some(channel.stream) {
				trunk.stalled_by.set(None);
				trunk.stalled_since.set(None);
				let _ = self.poll.register(&trunk_node, CIRCUIT, Interest::READABLE);
			}
		}
		tracing::debug!(stream = channel.stream, "channel closed");
	}
}

/// Write what fits.  `None` means nothing fit right now.
fn write_some(fd: RawFd, buf: &[u8]) -> Result<Option<usize>, Error> {
	if buf.is_empty() {
		return Ok(Some(0));
	}
	let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
	if n < 0 {
		let err = Error::last_os_error();
		return match err.kind() {
			ErrorKind::WouldBlock | ErrorKind::Interrupted => Ok(None),
			_ => Err(err),
		};
	}
	Ok(Some(n as usize))
}

fn pr_policy(reliability: dcep::Reliability) -> PrPolicy {
	match reliability {
		dcep::Reliability::Reliable => PrPolicy {
			policy: SCTP_PR_SCTP_NONE,
			value: 0,
		},
		dcep::Reliability::Rexmit(value) => PrPolicy {
			policy: SCTP_PR_SCTP_RTX,
			value,
		},
		dcep::Reliability::Timed(value) => PrPolicy {
			policy: SCTP_PR_SCTP_TTL,
			value,
		},
	}
}

fn hex(bytes: &[u8]) -> String {
	use std::fmt::Write;
	bytes.iter().fold(String::new(), |mut out, b| {
		let _ = write!(out, "{b:02x}");
		out
	})
}
