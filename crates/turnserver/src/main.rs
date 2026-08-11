use clap::Parser;
use eyre::{Result, eyre};
use intrusive_collections::{
	KeyAdapter, LinkedList, LinkedListLink, RBTree, RBTreeLink, intrusive_adapter, rbtree::Entry,
};
use ipnet::Ipv6Net;
use libc::in6_pktinfo;
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use nix::sys::socket::{
	ControlMessage, ControlMessageOwned, MsgFlags, SetSockOpt, SockaddrIn6,
	sockopt::Ipv6RecvPacketInfo,
};
use rand::random_range;
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use socket3::{SocketMtuExt, SocketQueueExt};
use std::{
	cell::Cell,
	io::{Error, ErrorKind, IoSlice, IoSliceMut, Read, Write},
	mem::ManuallyDrop,
	net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket},
	ops::RangeInclusive,
	os::fd::{AsFd, AsRawFd},
	rc::{Rc, Weak},
	sync::LazyLock,
	time::{Duration, Instant},
};
use stun::{
	Authkey, Class, Method, Parse, Parsed, Stun,
	addr::{Addr4, Addr6, Xor},
	known,
};
use tracing::trace;
use tracing_subscriber::EnvFilter;
use tun_rs::DeviceBuilder;
use zerocopy::{
	IntoBytes, TryFromBytes,
	network_endian::{U16, U32},
};

use common::{
	Ip6,
	Packet,
	Udp,
	read_network,
	//	socket::{UdpOpt, connected_udp, peek, recv_with_local, send_from, v4_path_mtu, v6_path_mtu},
	write_network_icmp,
	write_network_udp,
};

mod nonce;

/// md5('user:none:password')
static USER_KEY: LazyLock<Authkey> =
	LazyLock::new(|| Authkey::new(md5::compute(b"user:none:password").as_slice()));
static GUEST_KEY: LazyLock<Authkey> =
	LazyLock::new(|| Authkey::new(md5::compute(b"guest:none:password").as_slice()));

enum Conn {
	Udp(UdpSocket),
	// An alternative would be to use Socket.type() == Type::STREAM, but...
	Tcp(TcpStream),
}
impl AsRawFd for Conn {
	fn as_raw_fd(&self) -> std::os::fd::RawFd {
		match self {
			Self::Udp(v) => v.as_raw_fd(),
			Self::Tcp(v) => v.as_raw_fd(),
		}
	}
}
impl AsFd for Conn {
	fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
		match self {
			Self::Udp(v) => v.as_fd(),
			Self::Tcp(v) => v.as_fd(),
		}
	}
}
impl Conn {
	fn recv_msg<'i>(&self, buffer: &'i mut [u8]) -> Result<&'i mut Stun, Error> {
		match self {
			Self::Udp(udp) => {
				let retry = Error::new(ErrorKind::Interrupted, "");
				let len = udp.recv(buffer)?;
				if len < 20 {
					return Err(retry);
				}
				let msg = Stun::try_mut_from_bytes(buffer).map_err(|_| retry)?;
				Ok(msg)
			}
			Self::Tcp(tcp) => {
				let blocked = Error::new(ErrorKind::WouldBlock, "");
				let invalid = Error::new(ErrorKind::InvalidData, "");
				// Peek then read, to leave partial STUN frames in the kernel recv buffer
				// Our tcp streams are blocking, but we only want to block when sending frames or doing consuming reads
				let available = nix::sys::socket::recv(
					tcp.as_raw_fd(),
					buffer,
					MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
				)?;
				if available < 20 {
					return Err(blocked);
				}
				let msg = Stun::try_mut_from_bytes(buffer).map_err(|_| invalid)?;
				let expected = size_of_val(msg.trim());
				// TODO: msg.trim() doesn't expose errors.  Should check if length is unaligned or is too big for buffer.
				if available < expected {
					return Err(blocked);
				}
				(&*tcp)
					.read_exact(&mut buffer[..expected])
					.expect("Read after peek failed");
				Ok(Stun::try_mut_from_bytes(buffer).expect("Parse after read failed"))
			}
		}
	}
	fn maybe_send_frame(&self, frame: &[u8]) -> Result<(), Error> {
		let blocked = Error::new(ErrorKind::WouldBlock, "");

		let t = SockRef::from(self);
		let buff_len = t.send_buffer_size()?;
		let queue_len = t.send_queue_len()?;
		let available = (buff_len / 2).saturating_sub(queue_len);

		if frame.len() > available {
			return Err(blocked);
		}
		match self {
			Self::Udp(v) => {
				v.send(frame)?;
			}
			Self::Tcp(v) => (&*v).write_all(frame)?,
		}
		Ok(())
	}
}

struct Client {
	conn: Conn,

	keepalives: Cell<u8>,
	timeout: Cell<Instant>,
	timeout_link: LinkedListLink,

	relayed: SocketAddrV6,
	relayed_link: RBTreeLink,
}
impl AsRawFd for Client {
	fn as_raw_fd(&self) -> std::os::fd::RawFd {
		self.conn.as_raw_fd()
	}
}
intrusive_adapter!(Relayed = Rc<Client>: Client { relayed_link => RBTreeLink });
intrusive_adapter!(Timeout = Rc<Client>: Client { timeout_link => LinkedListLink });
impl<'a> KeyAdapter<'a> for Relayed {
	type Key = &'a SocketAddrV6;
	fn get_key(
		&self,
		value: &'a <Self::PointerOps as intrusive_collections::PointerOps>::Value,
	) -> Self::Key {
		&value.relayed
	}
}

/// Poller is a wrapper that handles the Token(usize) -> Weak<T> registration/deregistration
struct Poller<T> {
	poll: Poll,
	deregistered: Vec<Weak<T>>,
}
impl<T: AsRawFd> Poller<T> {
	fn new(poll: Poll) -> Self {
		Self {
			poll,
			deregistered: Vec::new(),
		}
	}
	fn register(&self, client: &Rc<T>, interest: Interest) -> Result<(), Error> {
		let fd = client.as_raw_fd();
		let weak = Rc::downgrade(client).into_raw();
		let token = Token(weak as usize);
		if let Err(reason) = self
			.poll
			.registry()
			.register(&mut SourceFd(&fd), token, interest)
		{
			// If registration fails, reconstruct the Weak immediately
			unsafe {
				Weak::from_raw(weak);
			}
			Err(reason)
		} else {
			Ok(())
		}
	}
	fn deregister(&mut self, client: Rc<T>) -> Result<(), Error> {
		let fd = client.as_raw_fd();
		let temp = Rc::downgrade(&client);
		// Reconstruct the Weak we loaned to the OS as the Token, then keep it in our list for final disposal immediately before re-polling
		self.deregistered
			.push(unsafe { Weak::from_raw(temp.as_ptr()) });

		self.poll.registry().deregister(&mut SourceFd(&fd))
	}
	fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> Result<(), Error> {
		// The Token Weak is released right before we poll, since it will no longer appear in any future Event
		self.deregistered.clear();
		self.poll.poll(events, timeout)
	}
	/// This method must only be called with Tokens that were registered using the Poller *not* on Poll directly, prior to constructing the Poller
	fn get(&self, token: Token) -> Option<Rc<T>> {
		let ptr = token.0 as *const T;
		// Attempt to upgrade our *shared* Weak (multiple copies between the registry, and multiple Event's), without decrementing the weak ptr.
		let t = ManuallyDrop::new(unsafe { Weak::from_raw(ptr) });
		// Upgrade takes &self, therefore the ManuallyDrop<Weak<T>> survives past this call.
		t.upgrade()
	}
}

struct Server {
	ip_range: RangeInclusive<u128>,
	port_range: RangeInclusive<u16>,
	poll: Poller<Client>,
	relayed: RBTree<Relayed>,
	timeouts: LinkedList<Timeout>,
}
impl Server {
	fn remove_client(&mut self, client: Rc<Client>) -> Result<(), Error> {
		// TODO: Probably use a better way like RBTree::cursor_from_ptr_mut or something
		// We only have 1 tree/list per link type, thus if the object is linked it must be linked in that collection
		let mut t = None;
		if client.relayed_link.is_linked() {
			t = t.or(unsafe { self.relayed.cursor_mut_from_ptr(&*client) }.remove());
		}
		if client.timeout_link.is_linked() {
			t = t.or(unsafe { self.timeouts.cursor_mut_from_ptr(&*client) }.remove());
		}
		let client = t.expect("Fuck, in order to *recover* the Rc<Client> from a list/tree we must *remove* it which returns Option<Rc<Client>>.  Since the object presumably is in at least one collection, we tried both and failed.");
		self.poll.deregister(client)
	}
	/// All of our timeouts are the same duration, so keeping the list sorted is just pushing to the back of the list
	fn timeout() -> Instant {
		Instant::now() + Duration::from_mins(1)
	}
	fn new_client(&mut self, conn: Conn) -> Result<SocketAddrV6, Error> {
		// 1. Find a random ip+port that's not currently occupied
		let mut tries = 5;
		let (relayed, i) = loop {
			let ret = SocketAddrV6::new(
				random_range(self.ip_range.clone()).into(),
				random_range(self.port_range.clone()),
				0,
				0,
			);
			let Entry::Vacant(v) = self.relayed.entry(&ret) else {
				if tries == 0 {
					return Err(Error::new(ErrorKind::QuotaExceeded, ""));
				}
				tries -= 1;
				continue;
			};
			break (ret, v);
		};
		// 2. Create the client
		let client = Rc::new(Client {
			conn,
			relayed,
			relayed_link: Default::default(),

			keepalives: Cell::new(0),
			timeout: Cell::new(Self::timeout()),
			timeout_link: Default::default(),
		});
		// 3. Try to register the new client
		self.poll.register(&client, Interest::READABLE)?;
		// 4. Insert the client into the timeout list
		self.timeouts.push_back(client.clone());
		// 5. Insert the client into the relayed tree
		i.insert(client);
		Ok(relayed)
	}
}

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short)]
	router: Ipv6Addr,

	#[arg(long, short)]
	if_name: Option<String>,

	/// IPv6 subnet the relayed transport addresses are drawn from.
	#[arg(long, short)]
	net: Ipv6Net,

	#[arg(long, default_value_t = 10_000)]
	min_port: u16,

	#[arg(long, default_value_t = u16::MAX)]
	max_port: u16,
}

// Tokens used by everything that isn't an allocation socket.
const UDP: Token = Token(usize::MAX);
const TCP: Token = Token(usize::MAX - 1);
const TUN: Token = Token(usize::MAX - 2);

enum Action {
	Drop,
	/// Stateless Responses
	Reply(usize),
	/// Stateless Refresh (if received over an established socket: respond, generate new timeout, push_back client)
	Refresh(usize),
	/// Nonce+Integrity were valid, proceed with allocation and return the XOR-RELAYED-ADDRESS once you have it
	Allocate(&'static Authkey),
	/// Refresh lifetime=0
	Close,
}
fn handle_turn(msg: &mut Stun, mapped: SocketAddr) -> Action {
	if msg.txid.id == [0; 12] {
		return Action::Drop;
	}
	if msg.class != Class::Request {
		return Action::Drop;
	}

	let mut username = Parsed::NotPresent;
	let mut software = Parsed::NotPresent;
	let mut channel = Parsed::NotPresent;
	let mut lifetime = Parsed::NotPresent;
	let mut peer = Parsed::NotPresent;
	let mut data = Parsed::NotPresent;
	let mut realm = Parsed::NotPresent;
	let mut nonce = Parsed::NotPresent;
	let mut transport = Parsed::NotPresent;
	let mut integrity = None;

	let attrs = msg
		.trim()
		.parse::<{ known::USERNAME }, str>(&mut username)
		.parse::<{ known::SOFTWARE }, str>(&mut software)
		.parse::<{ known::CHANNEL_NUMBER }, [u8; 4]>(&mut channel)
		.parse::<{ known::LIFETIME }, U32>(&mut lifetime)
		.parse::<{ known::XOR_PEER_ADDRESS }, Addr6<Xor>>(&mut peer)
		.parse::<{ known::DATA }, [u8]>(&mut data)
		.parse::<{ known::REALM }, str>(&mut realm)
		.parse::<{ known::NONCE }, [u8; 24]>(&mut nonce)
		.parse::<{ known::REQUESTED_TRANSPORT }, [u8; 4]>(&mut transport);

	let mut unk = Vec::new();
	msg.length.set(U16::new(0));

	for (prefix, attr) in attrs {
		match attr.typ {
			known::MESSAGE_INTEGRITY => {
				integrity = match username {
					Parsed::Valid("guest")
						if attr.value == prefix.expected_message_integrity(&GUEST_KEY) =>
					{
						Some(&GUEST_KEY)
					}
					Parsed::Valid("user")
						if attr.value == prefix.expected_message_integrity(&USER_KEY) =>
					{
						Some(&USER_KEY)
					}
					_ => None,
				};
				break;
			}
			_ if attr.is_optional() => {}
			t => unk.push(t),
		}
	}

	// Cap the reported allocation lifetime at 4min so conforming clients refresh
	// well before the ~6min heartbeat-counter expiry.  A `Refresh` with lifetime
	// 0 still clamps to 0 and is handled as a close below.
	let lifetime = U32::new(match lifetime {
		Parsed::Valid(l) => l.get().min(240),
		_ => 240,
	});

	let add_mapped = |msg: &mut Stun| match mapped {
		SocketAddr::V4(v4) => {
			msg.append_val(
				known::XOR_MAPPED_ADDRESS,
				&Addr4::new(*v4.ip(), v4.port()).xor(&msg.txid),
			);
		}
		SocketAddr::V6(v6) => {
			msg.append_val(
				known::XOR_MAPPED_ADDRESS,
				&Addr6::new(*v6.ip(), v6.port()).xor(&msg.txid),
			);
		}
	};

	match msg.method {
		Method::Allocate if !unk.is_empty() => {
			msg.class = Class::Response;
			msg.method = msg.method.to_err().unwrap();
			msg.length.get_mut().set(0);
			msg.append_val(known::UNKNOWN_ATTRIBUTES, unk.as_slice());
		}
		_ if !unk.is_empty() => return Action::Drop,

		Method::Bind => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			add_mapped(msg);
		}
		// No usable credentials: 401, challenging with a fresh nonce bound to
		// this client.  Unsigned — we have no key to sign with.
		m if integrity.is_none()
			|| realm != Parsed::Valid("none")
			|| !crate::nonce::verify_nonce(&nonce, &mapped) =>
		{
			msg.class = Class::Response;
			let Some(err_method) = m.to_err() else {
				trace!(?msg.method, "to_err failed?");
				return Action::Drop;
			};
			msg.method = err_method;
			msg.length.get_mut().set(0);
			if integrity.is_none() {
				msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 1]);
			} else {
				msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 38]);
			}
			msg.append_val(known::REALM, "none");
			// TODO: For Client's, this is the peer_addr on the socket, but for the unconnected UDP (which I haven't worked through yet) this would come from recv_from stuff.
			msg.append_val(
				known::NONCE,
				// Even though this could be a 401 we still issue a 30 min nonce since
				&crate::nonce::issue_nonce(&mapped, Duration::from_mins(30)),
			);
		}
		Method::Allocate => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			add_mapped(msg);
			msg.append_val(known::LIFETIME, &lifetime);
			return Action::Allocate(integrity.unwrap());
		}
		// Close notification: tear the allocation down.
		Method::Refresh if lifetime.get() == 0 => return Action::Close,
		Method::Refresh => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			msg.append_val(known::LIFETIME, &lifetime);
			msg.append_val(
				known::MESSAGE_INTEGRITY,
				&msg.trim().expected_message_integrity(integrity.unwrap()),
			);
			return Action::Refresh(size_of_val(msg.trim()));
		}
		Method::AddPermission => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
		}
		// We don't do channels.  438 with *no* NONCE attribute is the refusal
		// that costs nothing: we've just told Chrome its nonce is expired, so it
		// won't retransmit with that one, and we gave it no replacement, so it
		// drops the request — without expiring the nonce it's happily using for
		// everything else.  Anything else is fatal for the entry (400 was tried)
		// and tears down the peer's Send/Data indication path a few seconds
		// after it came up.  So: don't add REALM/NONCE here for symmetry with
		// the stale-nonce arm above — that's what makes it a no-op rather than a
		// retry loop — and don't touch any of it without an e2e that holds a
		// relayed pair open for a minute (`tests/soak.html`).
		Method::UseChannel => {
			msg.class = Class::Response;
			msg.method = msg.method.to_err().unwrap();
			msg.length.get_mut().set(0);
			msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 38]);
		}
		_ => return Action::Drop,
	}

	if let Some(authkey) = integrity {
		msg.append_val(
			known::MESSAGE_INTEGRITY,
			&msg.trim().expected_message_integrity(authkey),
		);
	}
	Action::Reply(size_of_val(msg.trim()))
}

type Never = core::convert::Infallible;
pub fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;
	// WARN: The Iterator and DoubleEndedIterator implementation for Ipv6AddrRange are O(1) for these functions
	#[allow(clippy::iter_nth_zero)]
	let first_ip = args.net.hosts().nth(0).expect("Empty IP subnet");
	let last_ip = args.net.hosts().nth_back(0).expect("Empty IP subnet");

	// Setup async
	let poll = Poll::new()?;

	let bind = SockAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0));
	// Wildcard UDP socket: dual-stack, REUSEPORT (so connected allocation sockets
	// can share the port), IPV6_RECVPKTINFO (so we learn the local dest address).
	let udp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
	udp.set_only_v6(false)?;
	udp.set_reuse_address(true)?;
	udp.set_reuse_port(true)?;
	Ipv6RecvPacketInfo.set(&udp, &true)?;
	udp.bind(&bind)?;
	udp.set_nonblocking(true)?;
	poll.registry()
		.register(&mut SourceFd(&udp.as_raw_fd()), UDP, Interest::READABLE)?;

	// TCP listener.
	let listener = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
	listener.set_only_v6(false)?;
	listener.set_reuse_address(true)?;
	listener.set_reuse_port(true)?;
	listener.bind(&bind)?;
	listener.listen(128)?;
	listener.set_nonblocking(true)?;
	poll.registry().register(
		&mut SourceFd(&listener.as_raw_fd()),
		TCP,
		Interest::READABLE,
	)?;

	// Setup the TUN interface
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
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let mut events = Events::with_capacity(128);
	let mut buffer = vec![0; 65536];

	// Collect all the mutable state and mediate access to it via methods
	let mut server = Server {
		poll: Poller::new(poll),
		ip_range: u128::from(first_ip)..=u128::from(last_ip),
		port_range: args.min_port..=args.max_port,
		relayed: RBTree::new(Relayed::new()),
		timeouts: LinkedList::new(Timeout::new()),
	};

	loop {
		for e in events.into_iter() {
			match e.token() {
				TCP => loop {
					let (stream, _sender) = match listener.accept() {
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						v => v?,
					};
					stream.set_tcp_nodelay(true)?;

					server.new_client(Conn::Tcp(stream.into()))?;
				},
				UDP => loop {
					let mut control_buffer = nix::cmsg_space!(in6_pktinfo);
					let mut iovs = [IoSliceMut::new(&mut buffer)];
					let msg = match nix::sys::socket::recvmsg::<SockaddrIn6>(
						udp.as_raw_fd(),
						&mut iovs,
						Some(&mut control_buffer),
						MsgFlags::empty(),
					)
					.map_err(Error::from)
					{
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						v => v?,
					};
					let local = msg
						.cmsgs()?
						.find_map(|cmsg| {
							if let ControlMessageOwned::Ipv6PacketInfo(ret) = cmsg {
								Some(ret)
							} else {
								None
							}
						})
						.expect("No local ipv6 packet info?");
					let sender = msg.address.expect("No sender address");
					let len = msg.bytes;
					let Ok(msg) = Stun::try_mut_from_bytes(&mut buffer) else {
						continue;
					};
					// Verify the expected length of the STUN message against the received datagram
					if size_of_val(msg.trim()) != len {
						continue;
					}

					let mapped = match sender.ip().to_canonical() {
						IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, sender.port())),
						IpAddr::V6(v4) => {
							SocketAddr::V6(SocketAddrV6::new(v4, sender.port(), 0, 0))
						}
					};
					// NOTE: For when sending, the local address is already sitting in the control_buffer.  I think we can just sendmsg using the same value we received.

					let end = match handle_turn(msg, mapped) {
						// Drop everything that isn't stateless or allocate
						Action::Close | Action::Drop | Action::Refresh(_) => {
							continue;
						}
						Action::Reply(end) => end,
						Action::Allocate(authkey) => {
							let socket =
								Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
							let local = SockAddr::from(SocketAddrV6::new(
								Ipv6Addr::from_octets(local.ipi6_addr.s6_addr),
								3478,
								0,
								0,
							));
							let peer =
								SockAddr::from(SocketAddrV6::new(sender.ip(), sender.port(), 0, 0));

							socket.set_reuse_address(true)?;
							socket.set_reuse_port(true)?;
							socket.set_nonblocking(true)?;
							// Bind to whatever local address the packet was received to
							socket.bind(&local)?;
							// Connect to whatever remote address
							match socket.connect(&peer) {
								Ok(_) => {}
								// If the address is inuse then we must have already issued an allocation / established a UDP socket to them:
								Err(reason) => {
									trace!(
										?reason,
										"Failed to connect socket.  Claude says linux won't check for duplicate 4tuple during connect only during bind.  I find that hard to believe."
									);
									continue;
								}
							};

							let relayed = server.new_client(Conn::Udp(socket.into()))?;
							// Since we successfully allocated a client, we respond from our unconnected socket (connected socket gets eaten by server)
							let xor_relayed =
								Addr6::new(*relayed.ip(), relayed.port()).xor(&msg.txid);
							msg.append_val(known::XOR_RELAYED_ADDRESS, &xor_relayed);
							msg.append_val(
								known::MESSAGE_INTEGRITY,
								&msg.trim().expected_message_integrity(authkey),
							);
							size_of_val(msg.trim())
						}
					};

					// Send the reply/allocated message
					let iov = [IoSlice::new(&buffer[..end])];
					let _ = match nix::sys::socket::sendmsg(
						udp.as_raw_fd(),
						&iov,
						// The local socket address is already in the control buffer from when we read it:
						&[ControlMessage::Ipv6PacketInfo(&local)],
						MsgFlags::empty(),
						Some(&sender),
					)
					.map_err(Error::from)
					{
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
						v => v?,
					};
				},
				TUN => loop {
					const TURN_DATA_OVERHEAD: usize = 20 + 24 + 4;
					let packet = match read_network(
						&network,
						&mut buffer[TURN_DATA_OVERHEAD..],
						args.router.octets(),
					) {
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						v => v?,
					};

					let msg;
					let receiver;
					match packet {
						Packet::Udp { ip, udp } => {
							// Peer -> relayed: dst is the relayed address.
							receiver =
								SocketAddrV6::new(Ipv6Addr::from(ip.dst), udp.dst_port.get(), 0, 0);

							let datagram_length = udp.length.get() - size_of::<Udp>() as u16;
							let sender =
								Addr6::new(Ipv6Addr::from_octets(ip.src), udp.src_port.get());
							msg = Stun::new(Class::Request, Method::Recv, &mut buffer)
								.map_err(|e| eyre!("{e:?}"))?;
							msg.append_val(known::XOR_PEER_ADDRESS, &sender.xor(&msg.txid));
							msg.append_once(|_, a| {
								a.typ = known::DATA;
								a.length.set(datagram_length); // UDP data already in position.
							});
						}
						Packet::Icmp {
							ip: _,
							icmp,
							inner_ip,
							inner_udp,
						} => {
							receiver = SocketAddrV6::new(
								Ipv6Addr::from(inner_ip.src),
								inner_udp.src_port.get(),
								0,
								0,
							);

							// RFC8656 Section 11.5: XOR-PEER-ADDRESS = destination
							// of the returned UDP packet.
							let peer = Addr6::new(
								Ipv6Addr::from_octets(inner_ip.dst),
								inner_udp.dst_port.get(),
							);
							msg = Stun::new(Class::Request, Method::Recv, &mut buffer)
								.map_err(|e| eyre!("{e:?}"))?;
							msg.append_val(known::XOR_PEER_ADDRESS, &peer.xor(&msg.txid));
							msg.append_once(|_, a| {
								use bytes::BufMut;
								a.typ = known::ICMP;
								// FUCK: The stupid ICMP vs LEGACY_ICMP shit
								a.put_u8(icmp.typ);
								a.put_u8(icmp.code);
								a.put_u8(icmp.typ);
								a.put_u8(icmp.code);
								a.put_u32(icmp.mtu.get());
							});
						}
					}

					let cursor = server.relayed.find_mut(&receiver);
					// UDP/ICMP for existant client
					if let Some(client) = cursor.get() {
						let end = size_of_val(msg.trim());
						match client.conn.maybe_send_frame(&buffer[..end]) {
							Ok(_) => {}
							// Client path can't carry the relayed Data indication: tell the
							// peer to send less (ICMPv6 Packet Too Big).
							Err(e)
								if let (Some(libc::EMSGSIZE), Packet::Udp { ip, udp }) =
									(e.raw_os_error(), packet) =>
							{
								let t = SockRef::from(&client.conn);
								let pmtu = t.path_mtu()?;
								let peer_addr = t
									.peer_addr()?
									.as_socket_ipv6()
									.expect("Our sockets should dual stack/mapped?");

								// To compute the MTU we should report in our ICMPv6 PTB:
								// - We only expect EMSGSIZE errors for UDP clients (Subtract out IP4/6 + UDP)
								// - We only issue/relay IPv6 UDP packets (XOR-PEER-ADDRESS is always Family=IPv6)
								// - Add back in IP6+UDP since the information in those is accounted for in the TURN prefix
								let reported_mtu = pmtu
									.saturating_sub(
										// IP Header
										if peer_addr.ip().to_ipv4_mapped().is_some() {
											20 // IPv4 Header
										} else {
											size_of::<Ip6>() as u32
										}
										// UDP Header
										+ size_of::<Udp>() as u32
										// TURN DATA Indication Prefix (With IPv6 Peer address)
										+ TURN_DATA_OVERHEAD as u32,
									)
									.saturating_add(
										size_of::<Ip6>() as u32 + size_of::<Udp>() as u32,
									);
								let datagram_length = udp.length.get() as usize - size_of::<Udp>();
								let _ = write_network_icmp(
									&network,
									receiver.ip().octets(),
									2,
									0, // ICMPv6 Packet Too Big
									reported_mtu,
									ip,
									udp.as_bytes(),
									// The UDP payload was untouched when writing the TURN data indication above.
									// However, don't use end (size_of_val(msg.trim())) here since the STUN message may include padding bytes that follow after the original UDP payload:
									&buffer[TURN_DATA_OVERHEAD..][..datagram_length],
								);
							}
							Err(_) => {}
						}
					}
					// UDP For non-existant client
					else if let Packet::Udp { ip, udp } = packet {
						let datalen = udp.length.get() as usize - size_of::<Udp>();
						let _ = write_network_icmp(
							&network,
							receiver.ip().octets(),
							1,
							4, // ICMP Port Unreachable
							0,
							ip,
							udp.as_bytes(),
							&buffer[48..][..datalen],
						);
					}
				},
				// Event on a non-released client
				t if let Some(client) = server.poll.get(t) => loop {
					if e.is_read_closed() || e.is_error() {
						trace!(?e, "closing allocation (is_error / is_read_closed)");
						server.remove_client(client)?;
						break;
					}

					let msg = match client.conn.recv_msg(&mut buffer) {
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(reason) => {
							trace!(?reason, "closing allocation read error");
							server.remove_client(client)?;
							break;
						}
						v => v?,
					};

					// Handle Send indications here since we only want to process them via established sockets
					if msg.class == Class::Request && msg.method == Method::Send {
						let mut peer = Parsed::NotPresent;
						let mut data = Parsed::NotPresent;

						let mut attrs = msg
							.trim()
							.parse::<{ known::XOR_PEER_ADDRESS }, Addr6<Xor>>(&mut peer)
							.parse::<{ known::DATA }, [u8]>(&mut data)
							.filter(|(_, a)| !a.is_optional());
						msg.length.set(U16::new(0));
						// Ensure that there are no unknown attributes (but no need to collect them into unk, since we can't respond to an indication anyway)
						let None = attrs.next() else { continue };

						let (Parsed::Valid(peer), Parsed::Valid(data)) = (peer, data) else {
							continue;
						};
						let peer = peer.xor(&msg.txid);
						// Realy the data as UDP
						let _ = write_network_udp(
							&network,
							(
								client.relayed.ip().octets(),
								U16::new(client.relayed.port()),
							),
							(peer.ip().octets(), U16::new(peer.port())),
							data,
						);
						continue;
					}

					// Get the canonical peer address off the established socket
					let sock = SockRef::from(&client.conn);
					let mapped = sock.peer_addr()?.as_socket().expect("fuck");
					let mapped = match mapped.ip().to_canonical() {
						IpAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(v4, mapped.port())),
						IpAddr::V6(v4) => {
							SocketAddr::V6(SocketAddrV6::new(v4, mapped.port(), 0, 0))
						}
					};

					// Handle the TURN message
					let end = match handle_turn(msg, mapped) {
						Action::Drop => continue,
						Action::Reply(end) => end,
						Action::Close => {
							server.remove_client(client)?;
							break;
						}
						Action::Allocate(authkey) => {
							// Allocate received over a connected socket (likely TCP, though could be retransmission hitting a newly connected UDP socket)
							let xor_relayed =
								Addr6::new(*client.relayed.ip(), client.relayed.port())
									.xor(&msg.txid);
							msg.append_val(known::XOR_RELAYED_ADDRESS, &xor_relayed);
							msg.append_val(
								known::MESSAGE_INTEGRITY,
								&msg.trim().expected_message_integrity(authkey),
							);
							size_of_val(msg.trim())
						}
						Action::Refresh(end) => {
							// Update keepalive tracking
							client.keepalives.set(0);
							client.timeout.set(Server::timeout());

							// Interesting: The linked list refuses to insert an object if it's already in a list.
							if client.timeout_link.is_linked() {
								unsafe { server.timeouts.cursor_mut_from_ptr(&*client) }.remove();
							};
							server.timeouts.push_back(client.clone());
							end
						}
					};

					match client.conn.maybe_send_frame(&buffer[..end]) {
						Err(e) if e.kind() == ErrorKind::Interrupted => continue,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Ok(_) => continue,
						Err(reason) => {
							trace!(?reason, "closing client");
							server.remove_client(client)?;
							break;
						}
					}
				},
				// Event for an already closed/released client
				_ => {}
			}
		}

		while let Some(client) = server.timeouts.pop_front() {
			let now = Instant::now();
			if client.keepalives.get() >= 5 {
				// 5 keepalives ~6min without seeing a refresh request means the lifetime (4min) has expired
				server.remove_client(client)?;
			} else if now < client.timeout.get() {
				// Put the client back and continue
				server.timeouts.push_front(client);
				break;
			} else {
				// Try to send a keepalive message:
				let msg = Stun::new(Class::Request, Method::Shit, &mut buffer).unwrap();
				let end = size_of_val(msg.trim());
				client.keepalives.update(|v| v + 1);
				match client.conn.maybe_send_frame(&buffer[..end]) {
					Err(e) if e.kind() == ErrorKind::Interrupted => {}
					Err(e) if e.kind() == ErrorKind::WouldBlock => {}
					Ok(_) => {}
					Err(reason) => {
						trace!(?reason, "Closing client");
						server.remove_client(client)?;
						continue;
					}
				}

				// Put the client back in the timeouts eueue with a new timeout
				client.timeout.set(Server::timeout());
				server.timeouts.push_back(client);
			}
		}

		server
			.poll
			.poll(&mut events, Some(Duration::from_mins(1)))?;
	}
}
