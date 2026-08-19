//! A switchboard extension that echoes.
//!
//! The smallest thing that exercises the whole path: the daemon dials this
//! socket once per datachannel whose protocol the directory maps here, sends a
//! control `open` naming the peer, and then relays.  We greet the peer and send
//! back whatever they send us.
//!
//! Deliberately blocking and thread-per-channel.  An extension does not need an
//! event loop to get backpressure right -- reading slowly is the whole
//! protocol, because the daemon stops reading the peer when this socket fills.

use std::{
	io::{ErrorKind, Read, Write},
	os::unix::net::{UnixListener, UnixStream},
	path::PathBuf,
};

use chan::{Frame, control::Control, flags};
use clap::Parser;
use eyre::{Result, bail};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	/// Where to listen.  The daemon's directory entry must name the same path.
	#[arg(default_value = "/run/swbrd/ext/echo.sock")]
	socket: PathBuf,

	/// Stop reading after this many messages and never start again.
	///
	/// For exercising backpressure: the daemon should fill this socket, stop
	/// reading the peer, hold nothing itself, and eventually take the circuit
	/// down rather than stay wedged.
	#[arg(long)]
	stall_after: Option<usize>,
}

fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();
	let args = Args::try_parse()?;

	// A stale socket from a previous run would make bind fail.
	let _ = std::fs::remove_file(&args.socket);
	let listener = UnixListener::bind(&args.socket)?;
	tracing::info!(socket = %args.socket.display(), "echo extension listening");

	for conn in listener.incoming() {
		match conn {
			Ok(conn) => {
				let stall_after = args.stall_after;
				std::thread::spawn(move || {
					if let Err(err) = serve(conn, stall_after) {
						tracing::warn!(%err, "channel failed");
					}
				});
			}
			Err(err) => tracing::warn!(%err, "accept failed"),
		}
	}
	Ok(())
}

/// One connection is one channel.
fn serve(mut conn: UnixStream, stall_after: Option<usize>) -> Result<()> {
	let mut reader = Reader::default();

	// The daemon always opens with a control frame naming the peer.
	let Some((header, payload)) = reader.next(&mut conn)? else {
		bail!("channel closed before it opened");
	};
	if !header.has(flags::CONTROL) {
		bail!("channel did not begin with a control frame");
	}
	let Control::Open(open) = serde_json::from_slice(&payload)? else {
		bail!("first control frame was not an open");
	};
	tracing::info!(
		peer = %open.id,
		label = %open.label,
		protocol = %open.protocol,
		stream = open.stream,
		"channel opened",
	);

	send(
		&mut conn,
		51,
		&format!("echo ready for {}", open.id).into_bytes(),
	)?;

	let mut seen = 0usize;
	while let Some((header, payload)) = reader.next(&mut conn)? {
		if header.has(flags::CONTROL) {
			continue;
		}
		seen += 1;
		if stall_after.is_some_and(|n| seen > n) {
			tracing::warn!(peer = %open.id, seen, "stalling deliberately: no longer reading");
			// Hold the connection open but never read again.  The daemon should
			// fill this socket and then stop reading the peer.
			std::thread::park();
		}
		tracing::debug!(peer = %open.id, bytes = payload.len(), "echoing");
		send(&mut conn, header.ppid.get(), &payload)?;
	}
	tracing::info!(peer = %open.id, "channel closed");
	Ok(())
}

fn send(conn: &mut UnixStream, ppid: u32, payload: &[u8]) -> Result<()> {
	let mut out = Vec::new();
	chan::encode(&mut out, ppid, flags::EOR, payload);
	conn.write_all(&out)?;
	Ok(())
}

/// Reassembles frames out of a byte stream.
#[derive(Default)]
struct Reader {
	buf: Vec<u8>,
}

impl Reader {
	/// The next whole frame, or `None` at end of stream.
	fn next(&mut self, conn: &mut UnixStream) -> Result<Option<(chan::Header, Vec<u8>)>> {
		loop {
			if let Some(frame) = Frame::parse(&self.buf)? {
				let header = frame.header;
				let payload = frame.payload.to_vec();
				let consumed = frame.wire_len();
				self.buf.drain(..consumed);
				return Ok(Some((header, payload)));
			}
			let mut chunk = [0u8; 16 * 1024];
			match conn.read(&mut chunk) {
				Ok(0) => return Ok(None),
				Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
				Err(e) if e.kind() == ErrorKind::Interrupted => continue,
				Err(e) => return Err(e.into()),
			}
		}
	}
}
