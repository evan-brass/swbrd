use std::{
	cell::{Cell, RefCell},
	collections::HashMap,
	io::ErrorKind,
	net::{Ipv6Addr, SocketAddrV6},
	num::NonZero,
	os::fd::AsRawFd,
	rc::Rc,
	str::FromStr,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::{Duration, Instant},
};

use clap::Parser;
use common::{
	Packet, Udp,
	poller::{Poller, Static},
	read_network, write_network_icmp, write_network_udp,
};
use eyre::{Result, ensure, eyre};
use intrusive_collections::{LinkedList, LinkedListLink, RBTree, RBTreeLink};
use ipnet::Ipv6Net;
use mio::{Events, Interest, Poll};
use openssl::ssl::{SslAcceptor, SslContext, SslFiletype, SslMethod, SslVerifyMode, SslVersion};
use sctp::{
	SCTP_ENABLE_CHANGE_ASSOC_REQ, SCTP_ENABLE_RESET_ASSOC_REQ, SCTP_ENABLE_RESET_STREAM_REQ,
	SCTP_FUTURE_ASSOC, SCTP_SHUTDOWN_EVENT, SCTP_STREAM_RESET_EVENT, Sctp, sctp_assoc_value,
	sctp_event,
};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use socket3::SocketMtuExt;
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian::U32, transmute,
};

mod directory;
mod exchange;
mod node;

use crate::directory::Directory;
use crate::node::{CIRCUIT, DTLS, Kind, Node, Trunk};

use dtls::{
	cookie::{self, Verdict, Verified},
	ffi::{self, SslIo},
	fingerprint::{self, peer_fingerprint},
	keys::{check_record, export_read_keys},
};

/// IPv6 (40) + UDP (8) header overhead between a link/path MTU and the UDP
/// payload a DTLS record occupies.
const IP_UDP: u32 = 40 + 8;

/// How long a connection may sit idle before it is reaped.  Every connection
/// gets the same grace, which is what lets `timeouts` stay sorted by pushing to
/// the back.
const IDLE: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short)]
	if_name: Option<String>,

	#[arg(long, short)]
	router: Ipv6Addr,

	#[arg(long, short, default_value = "[::1]:9899")]
	endpoint: String,

	/// The SCTP port associations are accepted on.  WebRTC uses 5000 on both
	/// ends by convention, and `Conn` in the browser client defaults to it.
	#[arg(long, short, default_value_t = 5000)]
	sctp_port: u16,

	/// Where the directory lives: every `*.toml` under here, in lexical order.
	#[arg(long, short, default_value = "/etc/swbrd/directory.d")]
	directory: std::path::PathBuf,

	/// The /96 that plaintext is injected *from*: the low 32 bits carry the
	/// subscriber index, so this prefix must route back to our TUN.  It has to
	/// be distinct from the deter prefix clients aim at.
	#[arg(long, short)]
	plaintext: Ipv6Net,
}

/// An address in the plaintext prefix.  The daemon picks the source address it
/// injects plaintext from rather than reusing the client's random choice, so
/// the association the kernel forms is attributable to exactly one connection:
/// two clients that happened to pick the same deter address would otherwise
/// collapse into one association, since WebRTC uses SCTP port 5000 on both ends
/// and the SCTP layer never sees the UDP port that tells them apart.
///
/// Rewriting the source costs nothing: SCTP's CRC32c covers only the SCTP
/// packet, not an IP pseudo-header -- the same property that lets SCTP survive
/// address NAT where TCP cannot.
#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
struct PlaintextIp {
	prefix: [u8; 12],
	index: U32,
}
impl PlaintextIp {
	fn new(prefix: [u8; 12], index: u32) -> Self {
		Self {
			prefix,
			index: U32::new(index),
		}
	}
	fn addr(&self) -> Ipv6Addr {
		Ipv6Addr::from_octets(transmute!(*self))
	}
	/// The subscriber index in `addr`, or `None` if it isn't ours.
	fn index_of(prefix: [u8; 12], addr: &Ipv6Addr) -> Option<u32> {
		let this: Self = transmute!(addr.octets());
		(this.prefix == prefix).then(|| this.index.get())
	}
}

/// Pin the negotiation to AES-128-GCM over DTLS 1.2 — the single record layout
/// that [`dtls::keys::check_record`] can authenticate for client mobility.  Both
/// Chrome and Firefox offer these suites for ECDSA/RSA certs.
fn pin_suite(acceptor: &mut openssl::ssl::SslAcceptorBuilder) -> Result<()> {
	acceptor.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")?;
	acceptor.set_min_proto_version(Some(SslVersion::DTLS1_2))?;
	acceptor.set_max_proto_version(Some(SslVersion::DTLS1_2))?;
	Ok(())
}

fn load_context(cert: &str) -> Result<SslContext> {
	let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
	acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
	acceptor.set_certificate_file(cert, SslFiletype::ASN1)?;
	acceptor.check_private_key()?;
	pin_suite(&mut acceptor)?;
	// Ask for the client's certificate and insist on getting one.  WebRTC
	// certificates are self-signed and there is no PKI behind them, so chain
	// validation has nothing to say and the callback always passes -- the
	// fingerprint *is* the identity, and a peer that won't present one is of no
	// use to us.
	acceptor.set_verify_callback(
		SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
		|_preverify_ok, _ctx| true,
	);
	cookie::configure(&mut acceptor);
	Ok(acceptor.build().into_context())
}

fn load_config() -> Result<(SslContext, SslContext)> {
	let config = (load_context("January.der")?, load_context("July.der")?);
	tracing::info!("Configuration loaded");
	Ok(config)
}

struct Server {
	poll: Poller<Node>,
	bound: RBTree<node::Bound>,
	timeouts: LinkedList<node::Timeout>,
	/// Trunks by subscriber index, which is how plaintext coming back from the
	/// kernel's SCTP stack finds its way home.
	subscribers: HashMap<u32, Rc<Node>>,
	/// Handed out in sequence and never deliberately reused, so a packet for a
	/// torn-down connection can't be attributed to a fresh one.
	next_index: u32,
	/// The high 96 bits of every address we inject plaintext from.
	plaintext: [u8; 12],

	/// The TUN carrying first-contact ClientHellos and endpoint plaintext.
	network: SyncDevice,
	/// Source and destination of all plaintext.
	endpoint: SocketAddrV6,
	/// ICMP errors are issued from here.
	router: Ipv6Addr,
	/// Which extension serves which datachannel protocol.
	directory: Directory,
	/// Scratch for building one frame; the daemon holds no per-channel queues.
	scratch: Vec<u8>,
	/// Circuits currently stalled on a channel, with the instant they must
	/// either resume by or be torn down.  Stalls are rare and short, so a plain
	/// vector scanned on each reap is the right shape.
	stalls: Vec<(Instant, std::rc::Weak<Node>)>,
}
/// Reserve a subscriber index.  Indexes are handed out in sequence and never
/// deliberately reused, so plaintext for a torn-down connection cannot be
/// attributed to a fresh one.  Wrapping back onto a live connection would take
/// 2^32 intervening handshakes, but check anyway rather than hand out an index
/// that is already in use.
fn allocate_index<T>(next: &mut u32, live: &HashMap<u32, T>) -> Option<u32> {
	for _ in 0..1024 {
		let index = *next;
		*next = next.wrapping_add(1);
		// 0 is the prefix's own network address, not a subscriber.
		if index != 0 && !live.contains_key(&index) {
			return Some(index);
		}
	}
	None
}

impl Server {
	/// The address this connection's plaintext is injected from.
	fn injected(&self, node: &Node, trunk: &Trunk) -> SocketAddrV6 {
		let ip = PlaintextIp::new(self.plaintext, trunk.index).addr();
		SocketAddrV6::new(ip, node.bound.port(), 0, 0)
	}

	/// Give a connection a fresh lease and move it to the back of the timeout
	/// list, which keeps the list sorted because every lease is `IDLE` long.
	fn touch(&mut self, node: &Rc<Node>) {
		node.timeout.set(Instant::now() + IDLE);
		if node.timeout_link.is_linked() {
			// Safe: the link is in this list, and the Rc keeps it alive.
			let mut cursor = unsafe { self.timeouts.cursor_mut_from_ptr(Rc::as_ptr(node)) };
			cursor.remove();
		}
		self.timeouts.push_back(node.clone());
	}

	/// Unlink a connection from everything and let the last Rc drop it.  The
	/// poller must be told before the socket goes away: `deregister` reads the
	/// fd back out of the client to issue the `epoll_ctl`.
	fn remove_conn(&mut self, node: Rc<Node>) {
		let Some(trunk) = node.trunk() else {
			return;
		};
		// Channels first: each holds a Weak back here, and dropping the trunk
		// out from under a registered channel fd would leave the poller holding
		// a token for a socket nobody owns.
		//
		// The take is bound to a local deliberately: iterating the borrow_mut()
		// directly would hold that borrow for the whole loop, and close_channel
		// borrows the same map again.
		let channels = std::mem::take(&mut *trunk.channels.borrow_mut());
		for (_, channel) in channels {
			self.close_channel(channel);
		}
		// Tell the peer, while the socket is still up.  Without this a torn-down
		// connection just goes silent and the browser sits there believing it is
		// still connected until ICE eventually gives up.
		if trunk.established.get() {
			let _ = ffi::shutdown(&mut trunk.ssl.borrow_mut());
		}
		let _ = self.poll.deregister(&node, DTLS);
		// Must precede dropping the socket: deregister reads the fd back out.
		let _ = self.poll.deregister(&node, CIRCUIT);
		// Abort rather than shut down gracefully, so the association is gone the
		// moment we drop it.  A lingering association holds the address we
		// injected from, and the kernel would refuse a later connection that
		// reused it.
		if let Some(circuit) = trunk.circuit.borrow().as_ref() {
			let _ = circuit.set_linger(Some(Duration::ZERO));
		}
		*trunk.circuit.borrow_mut() = None;
		self.subscribers.remove(&trunk.index);
		if node.bound_link.is_linked() {
			unsafe { self.bound.cursor_mut_from_ptr(Rc::as_ptr(&node)).remove() };
		}
		if node.timeout_link.is_linked() {
			unsafe {
				self.timeouts
					.cursor_mut_from_ptr(Rc::as_ptr(&node))
					.remove()
			};
		}
		tracing::debug!(bound = ?node.bound, "connection closed");
	}

	/// Stand up a connection for a cookie-verified ClientHello: a connected
	/// transparent socket bound to the relayed address, with the caught-up
	/// handshake cut over onto it.
	fn create_client(
		&mut self,
		ctx: &SslContext,
		verified: &Verified,
		bound: SocketAddrV6,
		connected: SocketAddrV6,
	) -> Result<()> {
		let index = allocate_index(&mut self.next_index, &self.subscribers)
			.ok_or_else(|| eyre!("no free subscriber index"))?;

		let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
		sock.set_only_v6(true)?;
		#[cfg(target_os = "linux")]
		sock.set_ip_transparent_v6(true)?;
		SockRef::from(&sock).set_path_mtu_discovery(true)?;
		sock.bind(&SockAddr::from(bound))?;
		sock.connect(&SockAddr::from(connected))?;
		sock.set_nonblocking(true)?;

		let hs = cookie::promote(ctx, verified)?;

		// Unfragmented hello: the ServerHello flight is already produced, so send
		// it before cutover.  Fragmented: nothing yet — the rest arrives on the
		// socket.
		for datagram in hs.drain_output() {
			let _ = sock.send(&datagram);
		}

		let established = hs.is_finished();
		// The BIO borrows this fd; `sock` moves into the Client below and so
		// outlives the Ssl.
		let ssl = hs.into_established(sock.as_raw_fd())?;

		let node = Rc::new(Node {
			bound,
			bound_link: RBTreeLink::new(),
			timeout: Cell::new(Instant::now() + IDLE),
			timeout_link: LinkedListLink::new(),
			kind: Kind::Trunk(Trunk {
				ssl: RefCell::new(ssl),
				sock,
				established: Cell::new(established),
				fingerprint: Cell::new(None),
				read_keys: Cell::new(None),
				highest_read_seq: Cell::new(0),
				index,
				connected: Cell::new(connected),
				circuit: RefCell::new(None),
				channels: RefCell::new(HashMap::new()),
				stalled_by: Cell::new(None),
				stalled_since: Cell::new(None),
				waiting_on_circuit: RefCell::new(Vec::new()),
			}),
		});

		self.poll.register(&node, DTLS, Interest::READABLE)?;
		self.bound.insert(node.clone());
		self.subscribers.insert(index, node.clone());
		self.timeouts.push_back(node);
		tracing::debug!(?bound, ?connected, index, "connection opened");
		Ok(())
	}

	/// Drain everything the socket has for this connection: handshake steps
	/// until established, then plaintext onto the TUN.
	fn drive_connection(&mut self, node: Rc<Node>, buffer: &mut [u8]) {
		let Some(trunk) = node.trunk() else {
			return;
		};
		loop {
			let outcome = if !trunk.established.get() {
				let result = ffi::do_handshake(&mut trunk.ssl.borrow_mut());
				if matches!(result, SslIo::Ok(_)) {
					// The borrow_mut above was a statement temporary and is gone.
					let finished = trunk.ssl.borrow().is_init_finished();
					if finished {
						trunk.established.set(true);
						// identify() tears the connection down if the peer turned
						// out to be anonymous, so nothing may touch it after.
						if !self.identify(&node, trunk) {
							return;
						}
					}
					self.touch(&node);
				}
				result
			} else {
				let result = ffi::read(&mut trunk.ssl.borrow_mut(), buffer);
				if let SslIo::Ok(len) = result
					&& len > 0
				{
					self.touch(&node);
					let _ = write_network_udp(
						&self.network,
						&self.injected(&node, trunk),
						&self.endpoint,
						&buffer[..len],
					);
				}
				result
			};

			match outcome {
				// Handshake step or read made progress: keep draining.
				SslIo::Ok(_) => continue,
				// Nothing more to read right now.
				SslIo::WantRead | SslIo::WantWrite => return,
				// close_notify, a connected-socket error (e.g. ECONNREFUSED
				// surfaced by the dgram BIO's recv), or a fatal alert.
				SslIo::ZeroReturn | SslIo::Syscall(_) | SslIo::Fatal => {
					return self.remove_conn(node);
				}
			}
		}
	}

	/// Take the peer's identity off a just-finished handshake.  Returns whether
	/// the connection survives: the acceptor requires a certificate, so `None`
	/// here means OpenSSL let a handshake finish without one, and serving an
	/// unidentified peer is worse than dropping it.
	#[must_use]
	fn identify(&mut self, node: &Rc<Node>, trunk: &Trunk) -> bool {
		let fp = peer_fingerprint(&trunk.ssl.borrow());
		trunk.fingerprint.set(fp);
		let Some(fp) = fp else {
			tracing::error!(bound = ?node.bound, "handshake finished with no peer certificate");
			self.remove_conn(node.clone());
			return false;
		};
		tracing::info!(
			bound = ?node.bound,
			peer = %fingerprint::base36(&fp),
			"handshake finished",
		);
		true
	}

	/// Attribute a freshly accepted association to the connection that produced
	/// it, and take ownership of its socket.
	fn attach_circuit(&mut self, peer: SocketAddrV6, sock: Sctp) {
		// The peer address is one we chose: its low 32 bits are the subscriber
		// index we injected this connection's plaintext from.
		let Some(index) = PlaintextIp::index_of(self.plaintext, peer.ip()) else {
			tracing::warn!(?peer, "association from outside the plaintext prefix");
			return;
		};
		let Some(node) = self.subscribers.get(&index).cloned() else {
			tracing::warn!(?peer, index, "association for a subscriber that has gone");
			return;
		};
		let Some(trunk) = node.trunk() else {
			return;
		};
		let Some(fp) = trunk.fingerprint.get() else {
			// The handshake has to finish before plaintext can flow, so this
			// should be unreachable; an unidentified association is not one we
			// are willing to carry.
			tracing::error!(
				?peer,
				index,
				"association before the handshake identified the peer"
			);
			return;
		};
		if trunk.circuit.borrow().is_some() {
			tracing::warn!(?peer, index, "second association for one connection");
			return;
		}
		if let Err(err) = sock.set_nonblocking(true) {
			tracing::warn!(?peer, %err, "could not set the circuit non-blocking");
			return;
		}

		*trunk.circuit.borrow_mut() = Some(sock);
		if let Err(err) = self.poll.register(&node, CIRCUIT, Interest::READABLE) {
			tracing::warn!(?peer, %err, "could not register the circuit");
			*trunk.circuit.borrow_mut() = None;
			return;
		}
		self.touch(&node);
		tracing::info!(
			bound = ?node.bound,
			peer = %fingerprint::base36(&fp),
			index,
			"circuit joined",
		);
	}

	/// A datagram for a known connection that is *not* endpoint plaintext:
	/// either a raced ClientHello retransmit (the socket already owns it) or a
	/// client that roamed.  If the record authenticates against the DTLS read
	/// keys, re-point the socket; otherwise drop it, since an off-path spoofer
	/// cannot forge the tag.
	fn try_mobility(&mut self, node: &Rc<Node>, roamed: SocketAddrV6, record: &mut [u8]) {
		let Some(trunk) = node.trunk() else {
			return;
		};
		if !trunk.established.get() {
			return;
		}
		if trunk.read_keys.get().is_none() {
			trunk.read_keys.set(export_read_keys(&trunk.ssl.borrow()));
		}
		let Some(keys) = trunk.read_keys.get() else {
			return;
		};
		let Some(seq) = check_record(&keys, trunk.highest_read_seq.get(), record) else {
			return;
		};
		if trunk.sock.connect(&SockAddr::from(roamed)).is_ok() {
			trunk.highest_read_seq.set(seq);
			trunk.connected.set(roamed);
			self.touch(node);
			tracing::debug!(bound = ?node.bound, ?roamed, "client mobility: re-pointed socket");
		}
	}

	/// Reap every connection whose lease has run out.  The list is sorted, so
	/// this stops at the first live one.
	fn reap(&mut self) {
		let now = Instant::now();
		while self
			.timeouts
			.front()
			.get()
			.is_some_and(|n| n.timeout.get() <= now)
		{
			let node = self.timeouts.pop_front().expect("front was Some");
			tracing::debug!(bound = ?node.bound, "connection timed out");
			self.remove_conn(node);
		}
	}

	/// Tear down any circuit that has been stalled on a channel for longer than
	/// that channel's extension allows.  A channel that never drains takes its
	/// circuit with it: the alternative is a circuit wedged indefinitely, and
	/// SCTP gives us no way to stall one stream without stalling them all.
	fn reap_stalls(&mut self) {
		let now = Instant::now();
		let mut expired = Vec::new();
		self.stalls.retain(|(deadline, weak)| match weak.upgrade() {
			None => false,
			Some(node) => {
				// Resumed, so the entry is stale.
				let still_stalled = node.trunk().is_some_and(|t| t.stalled_by.get().is_some());
				if !still_stalled {
					return false;
				}
				if *deadline <= now {
					expired.push(node);
					return false;
				}
				true
			}
		});
		for node in expired {
			let stream = node.trunk().and_then(|t| t.stalled_by.get());
			tracing::warn!(bound = ?node.bound, ?stream, "channel never drained: tearing down the circuit");
			self.remove_conn(node);
		}
	}

	/// How long we may block in `poll` before something needs attention.
	fn next_deadline(&self) -> Option<Duration> {
		let idle = self.timeouts.front().get().map(|n| n.timeout.get());
		let stall = self.stalls.iter().map(|(at, _)| *at).min();
		let next = match (idle, stall) {
			(Some(a), Some(b)) => a.min(b),
			(a, b) => a.or(b)?,
		};
		Some(next.saturating_duration_since(Instant::now()))
	}
}

const TUN: Static = Static(0);
const SCTP: Static = Static(1);

/// Bind the association listener.  One-to-one, so `accept` hands back a socket
/// per association: the peer address comes straight off the accept (no
/// `SCTP_ASSOC_CHANGE` round trip), each association gets its own send and
/// receive buffers, and the options set here are inherited by every accepted
/// socket.
fn listen_sctp(port: u16, interface: NonZero<u32>) -> Result<Sctp> {
	let listener = Sctp::one_to_one()?;
	listener.set_reuse_address(true)?;
	// Only ever accept associations that arrived over our own TUN, which is to
	// say only plaintext we decrypted.  Without this the listener is reachable
	// by anything that can find the host's SCTP-over-UDP port, and an
	// association would be established before we got to reject it.
	listener.bind_device_by_index_v6(Some(interface))?;
	listener.bind(&SockAddr::from(SocketAddrV6::new(
		Ipv6Addr::UNSPECIFIED,
		port,
		0,
		0,
	)))?;

	// Per-message metadata: which stream and ppid a message arrived on.
	listener.set_recv_rcv_info(&1)?;
	// Deliver large messages in pieces, and let other streams interleave rather
	// than queue behind them -- this is what keeps one bulk transfer from
	// stalling every other channel on the same association.
	listener.set_fragment_interleave(&2)?;
	listener.set_partial_delivery_point(&(16 * 1024))?;
	// Stream reset is how a channel closes in one direction.
	listener.set_reconfig_supported(&sctp_assoc_value {
		assoc_id: SCTP_FUTURE_ASSOC,
		assoc_value: 1,
	})?;
	listener.set_enable_stream_reset(&sctp_assoc_value {
		assoc_id: SCTP_FUTURE_ASSOC,
		assoc_value: SCTP_ENABLE_RESET_STREAM_REQ
			| SCTP_ENABLE_RESET_ASSOC_REQ
			| SCTP_ENABLE_CHANGE_ASSOC_REQ,
	})?;
	for event in [SCTP_SHUTDOWN_EVENT, SCTP_STREAM_RESET_EVENT] {
		listener.set_event(&sctp_event {
			se_assoc_id: SCTP_FUTURE_ASSOC,
			se_type: event,
			se_on: 1,
		})?;
	}

	listener.listen(128)?;
	listener.set_nonblocking(true)?;
	Ok(listener)
}

type Never = core::convert::Infallible;
pub fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// This IP is the destination and source of all plaintext
	let endpoint = SocketAddrV6::from_str(&args.endpoint)?;

	let poll = Poller::new(Poll::new()?);

	// The TUN interface carries first-contact ClientHellos (cookie exchange) and
	// endpoint plaintext.  Established client ciphertext is diverted to each
	// connection's connected transparent socket by nftables `socket transparent`.
	let network = {
		let mut builder = DeviceBuilder::new();
		#[cfg(target_os = "linux")]
		{
			builder = builder.offload(true); // checksum offload
		}
		if let Some(if_name) = args.if_name {
			builder = builder.name(if_name);
		}
		builder.build_sync()?
	};
	network.set_nonblocking(true)?;
	poll.register_static(network.as_raw_fd(), TUN, Interest::READABLE)?;

	let listener = listen_sctp(
		args.sctp_port,
		NonZero::new(network.if_index()?).ok_or_else(|| eyre!("the TUN has no interface index"))?,
	)?;
	poll.register_static(listener.as_raw_fd(), SCTP, Interest::READABLE)?;
	tracing::info!(port = args.sctp_port, "accepting associations");

	ensure!(
		args.plaintext.prefix_len() == 96,
		"--plaintext must be a /96: the low 32 bits carry the subscriber index",
	);
	let PlaintextIp { prefix, .. } = transmute!(args.plaintext.network().octets());

	let directory = Directory::load(&args.directory)?;

	let mut server = Server {
		poll,
		bound: RBTree::new(node::Bound::new()),
		timeouts: LinkedList::new(node::Timeout::new()),
		subscribers: HashMap::new(),
		// Seeded randomly rather than from 1.  Indexes are the low bits of the
		// address we inject from, so they are what the kernel keys an
		// association on; restarting at 1 would land a fresh connection on the
		// same 4-tuple as an association left over from the previous run, and
		// the kernel refuses the colliding INIT rather than accepting it.
		next_index: {
			let mut seed = [0u8; 4];
			openssl::rand::rand_bytes(&mut seed)?;
			u32::from_ne_bytes(seed)
		},
		plaintext: prefix,
		network,
		endpoint,
		router: args.router,
		directory,
		scratch: Vec::with_capacity(chan::MAX_PAYLOAD + chan::Header::LEN),
		stalls: Vec::new(),
	};

	let (mut even, mut odd) = load_config()?;
	// The HMAC key behind our stateless DTLS cookies.  Fresh per process: a
	// restart just costs in-flight handshakes one extra HelloVerifyRequest round.
	let keys = cookie::Keys::generate()?;
	let need_reconfig = Arc::new(AtomicBool::new(false));
	signal_hook::flag::register(signal_hook::consts::SIGHUP, need_reconfig.clone())?;

	let mut events = Events::with_capacity(128);
	let mut buffer = vec![0; 4096];

	loop {
		if need_reconfig.swap(false, Ordering::Relaxed) {
			(even, odd) = load_config()?;
		}

		let timeout = server.next_deadline();
		match server.poll.poll(&mut events, timeout) {
			// SIGHUP (or any signal) interrupts the wait; loop to reconfigure.
			Err(e) if e.kind() == ErrorKind::Interrupted => continue,
			v => v?,
		}

		for e in events.iter() {
			match server.poll.get(e.token()) {
				Err(TUN) => loop {
					let packet = match read_network(&server.network, &mut buffer, &server.router) {
						Ok(p) => p,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(e) => return Err(e.into()),
					};
					// DTLS has no ICMP back-channel (unlike TURN's ICMP attribute),
					// so inbound ICMP is dropped; client-path errors surface on the
					// connected socket instead.
					let Packet::Udp { ip, udp } = packet else {
						continue;
					};

					let send_from =
						SocketAddrV6::new(Ipv6Addr::from_octets(ip.dst), udp.dst_port.get(), 0, 0);
					let send_to =
						SocketAddrV6::new(Ipv6Addr::from_octets(ip.src), udp.src_port.get(), 0, 0);
					let length = udp.length.get() as usize - size_of::<Udp>();

					// Two kinds of packet arrive here.  Plaintext coming back
					// from the kernel's SCTP stack is addressed to one of our
					// injected addresses; everything else is client traffic aimed
					// at a deter address.  Established client ciphertext never
					// reaches the TUN at all -- nftables diverts it straight to
					// the connection's transparent socket.
					let dst = Ipv6Addr::from_octets(ip.dst);
					if let Some(index) = PlaintextIp::index_of(server.plaintext, &dst) {
						let data = &buffer[..length];
						// Plaintext for a connection that has gone away.
						let Some(node) = server.subscribers.get(&index).cloned() else {
							let _ = write_network_icmp(
								&server.network,
								send_from.ip(),
								1,
								4, // Port Unreachable
								0,
								ip,
								udp.as_bytes(),
								data,
							);
							continue;
						};
						let Some(trunk) = node.trunk() else {
							continue;
						};
						if !trunk.established.get() {
							continue;
						}
						server.touch(&node);

						let outcome = ffi::write(&mut trunk.ssl.borrow_mut(), data);
						match outcome {
							SslIo::Ok(_) | SslIo::WantRead | SslIo::WantWrite => {}
							// Client path shrank: apply the new MTU to the DTLS
							// stream and tell the endpoint to send less.
							SslIo::Syscall(err) if err.raw_os_error() == Some(libc::EMSGSIZE) => {
								if let Ok(pmtu) = SockRef::from(&trunk.sock).path_mtu() {
									let data_mtu = {
										let mut ssl = trunk.ssl.borrow_mut();
										let _ = ssl.set_mtu(pmtu.saturating_sub(IP_UDP));
										ffi::data_mtu(&ssl) as u32
									};
									let _ = write_network_icmp(
										&server.network,
										send_from.ip(),
										2, // ICMPv6 Packet Too Big
										0,
										data_mtu + IP_UDP,
										ip,
										udp.as_bytes(),
										data,
									);
								}
							}
							// ECONNREFUSED or a fatal error: drop it.
							_ => server.remove_conn(node),
						}
						continue;
					}

					// Client traffic for a connection we already have: a raced
					// ClientHello retransmit (the socket already owns it) or a
					// client that roamed.  Either way this datagram is dropped;
					// the client's next packet lands on the now-matching socket
					// and DTLS retransmit recovers anything lost.
					if let Some(node) = server.bound.find(&send_from).clone_pointer() {
						server.try_mobility(&node, send_to, &mut buffer[..length]);
						continue;
					}

					// First contact: statelessly verify a DTLS cookie.
					let data = &buffer[..length];
					match keys.inspect(send_to, send_from, data) {
						Verdict::Drop => {}
						Verdict::HelloVerify(hvr) => {
							let _ = write_network_udp(
								&server.network,
								&send_from,
								&send_to,
								hvr.as_bytes(),
							);
						}
						Verdict::Accept(verified) => {
							// The relayed port's low bit picks the half-year
							// certificate the client derived.
							let ctx = if send_from.port() & 0b1 == 0 {
								&even
							} else {
								&odd
							};
							if let Err(err) =
								server.create_client(ctx, &verified, send_from, send_to)
							{
								tracing::debug!("connection setup failed: {err}");
							}
						}
					}
				},
				// A new association: attribute it to the connection whose
				// plaintext produced it.
				Err(SCTP) => loop {
					let (sock, addr) = match listener.accept() {
						Ok(v) => v,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(err) => {
							tracing::warn!(%err, "sctp accept failed");
							break;
						}
					};
					match addr.as_socket_ipv6() {
						// Dropping `sock` here is what refuses the association.
						None => tracing::warn!("association from a non-IPv6 peer"),
						Some(peer) => server.attach_circuit(peer, sock),
					}
				},
				// Unused Static Tokens
				Err(_) => unreachable!(),
				// Event on the client's transparent socket
				Ok(Some((flag, node))) => match (&node.kind, flag) {
					// The peer's DTLS socket
					(Kind::Trunk(_), DTLS) => server.drive_connection(node, &mut buffer),
					// The peer's SCTP association
					(Kind::Trunk(_), CIRCUIT) => server.drive_circuit(node, &mut buffer),
					// An extension's end of one channel
					(Kind::Channel(_), _) => server.drive_channel(node, &mut buffer),
					_ => unreachable!("unused flag"),
				},
				// Trailing events for a node that has already gone away.
				Ok(None) => {}
			}
		}

		server.reap();
		server.reap_stalls();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const PREFIX: [u8; 12] = [0x2a, 0x01, 0x04, 0xff, 0x01, 0xf0, 0x7e, 0x46, 0, 0, 0, 6];

	#[test]
	fn injected_address_round_trips() {
		for index in [1, 2, 0xffff, 0x0001_0000, u32::MAX] {
			let addr = PlaintextIp::new(PREFIX, index).addr();
			assert_eq!(
				PlaintextIp::index_of(PREFIX, &addr),
				Some(index),
				"{addr} did not decode back to {index}",
			);
		}
	}

	/// The decode is what attributes plaintext to a subscriber, so an address
	/// outside our prefix must not be mistaken for one -- it has to fall through
	/// to the client-facing path instead.
	#[test]
	fn foreign_addresses_are_not_subscribers() {
		let mut deter = PREFIX;
		deter[11] = 4; // the prefix clients aim at, one nibble away from ours
		let addr = PlaintextIp::new(deter, 7).addr();
		assert_eq!(PlaintextIp::index_of(PREFIX, &addr), None);

		for s in ["::", "2001:db8::1", "fd01::dead:beef"] {
			let addr: Ipv6Addr = s.parse().unwrap();
			assert_eq!(PlaintextIp::index_of(PREFIX, &addr), None, "{s}");
		}
	}

	/// Index 0 is the prefix's own network address and is never handed out, so
	/// a stray packet to the bare prefix is attributed to nobody.
	#[test]
	fn index_zero_is_never_allocated() {
		let live: HashMap<u32, ()> = HashMap::new();
		let mut next = u32::MAX;
		assert_eq!(allocate_index(&mut next, &live), Some(u32::MAX));
		// next has now wrapped to 0.
		assert_eq!(allocate_index(&mut next, &live), Some(1));
	}

	/// A live index is never handed out twice.
	#[test]
	fn allocation_skips_live_indexes() {
		let live: HashMap<u32, ()> = [(5, ()), (6, ())].into_iter().collect();
		let mut next = 5;
		assert_eq!(allocate_index(&mut next, &live), Some(7));
	}

	/// Exhaustion is reported rather than spun on.
	#[test]
	fn allocation_gives_up_when_full() {
		let live: HashMap<u32, ()> = (0..4096).map(|i| (i, ())).collect();
		let mut next = 1;
		assert_eq!(allocate_index(&mut next, &live), None);
	}
}
