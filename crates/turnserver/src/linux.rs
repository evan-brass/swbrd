use clap::Parser;
use eyre::{Result, eyre};
use ipnet::Ipv6Net;
use mio::{Events, Interest, Poll, Registry, Token, unix::SourceFd};
use slab::Slab;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
	collections::HashMap,
	io::{ErrorKind, Read, Write},
	net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
	os::fd::AsRawFd,
	str::FromStr,
};
use stun::{
	Authkey, Class, Method, Parse, Parsed, Stun,
	addr::{Addr4, Addr6, Xor},
	known,
};
use tracing::{trace, warn};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{
	AlignedTryCastError, TryFromBytes,
	network_endian::{U16, U32},
};

use common::{
	Packet, read_network,
	socket::{
		UdpOpt, connected_udp, peek, recv_with_local, send_from, set_recv_pktinfo, tcp_send_space,
	},
	write_network_udp,
};

/// md5('user:none:password')
const USER_KEY: &Authkey = &Authkey {
	ipad: [
		0xac, 0xf7, 0x05, 0x5c, 0xf4, 0xd9, 0x24, 0x8e, 0x97, 0x30, 0x36, 0x4c, 0x9d, 0x42, 0x13,
		0xc5, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36,
	],
	opad: [
		0xc6, 0x9d, 0x6f, 0x36, 0x9e, 0xb3, 0x4e, 0xe4, 0xfd, 0x5a, 0x5c, 0x26, 0xf7, 0x28, 0x79,
		0xaf, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c,
	],
};
// md5('guest:none:password')
const GUEST_KEY: &Authkey = &Authkey {
	ipad: [
		0x37, 0x6a, 0xbc, 0xa1, 0x08, 0x92, 0x82, 0x9f, 0xff, 0x73, 0xc0, 0xa6, 0x22, 0x1d, 0xc5,
		0x9b, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36,
	],
	opad: [
		0x5d, 0x00, 0xd6, 0xcb, 0x62, 0xf8, 0xe8, 0xf5, 0x95, 0x19, 0xaa, 0xcc, 0x48, 0x77, 0xaf,
		0xf1, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c,
	],
};

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:3478")]
	address: String,

	#[arg(long, short)]
	router: Ipv6Addr,

	#[arg(long, short)]
	if_name: Option<String>,

	/// IPv6 subnet the relayed transport addresses are drawn from.
	#[arg(long)]
	relay_net: Ipv6Net,

	/// Port range for relayed addresses, as `start-end` (inclusive).
	#[arg(long)]
	relay_ports: String,
}

// Tokens used by everything that isn't an allocation socket.
const UDP: Token = Token(usize::MAX);
const TCP: Token = Token(usize::MAX - 1);
const TUN: Token = Token(usize::MAX - 2);

/// Linear map between a slab key and a relayed transport address, laid out
/// port-first then IP: `key = ip_index * ports + port_index`.  The pool is
/// IPv6-only (as the relayed/subnet address always has been).
struct RelayRange {
	base: u128, // relay_net.network() as bits
	ips: u128,  // number of addresses in the subnet
	port_start: u16,
	ports: u32, // number of ports (end - start + 1)
}
impl RelayRange {
	fn new(net: Ipv6Net, ports: &str) -> Result<Self> {
		let (a, b) = ports
			.split_once('-')
			.ok_or_else(|| eyre!("--relay-ports must be start-end"))?;
		let port_start: u16 = a.trim().parse()?;
		let port_end: u16 = b.trim().parse()?;
		if port_end < port_start {
			return Err(eyre!("--relay-ports end < start"));
		}
		let prefix = net.prefix_len();
		let ips = if prefix == 0 {
			u128::MAX
		} else {
			1u128 << (128 - prefix)
		};
		Ok(Self {
			base: net.network().to_bits(),
			ips,
			port_start,
			ports: (port_end - port_start) as u32 + 1,
		})
	}

	/// The relayed address for a slab key, or `None` if the key is outside the
	/// pool (server full).
	fn from_key(&self, key: usize) -> Option<SocketAddrV6> {
		let key = key as u128;
		let ports = self.ports as u128;
		let ip_index = key / ports;
		if ip_index >= self.ips {
			return None;
		}
		let port = self.port_start as u128 + (key % ports);
		let ip = Ipv6Addr::from_bits(self.base + ip_index);
		Some(SocketAddrV6::new(ip, port as u16, 0, 0))
	}

	/// The slab key a relayed address maps to, or `None` if the address is
	/// outside the pool.  Occupancy is checked separately against the slab.
	fn to_key(&self, ip: Ipv6Addr, port: u16) -> Option<usize> {
		if port < self.port_start {
			return None;
		}
		let port_index = (port - self.port_start) as u128;
		if port_index >= self.ports as u128 {
			return None;
		}
		let bits = ip.to_bits();
		if bits < self.base {
			return None;
		}
		let ip_index = bits - self.base;
		if ip_index >= self.ips {
			return None;
		}
		usize::try_from(ip_index * self.ports as u128 + port_index).ok()
	}

	/// Upper bound on concurrent allocations (`ips * ports`), saturated to fit a
	/// `usize` for the slab cap.
	fn capacity(&self) -> usize {
		usize::try_from(self.ips.saturating_mul(self.ports as u128)).unwrap_or(usize::MAX)
	}
}

/// What `handle_turn` decided to do with a message.
enum Turn<'i> {
	/// Send this message back to the client.
	Respond(&'i mut Stun),
	/// Nothing to send (relayed out the TUN, or dropped).
	Silent,
	/// Tear the allocation down (Refresh with lifetime 0).
	Close,
}

enum Write2 {
	Kept,
	Abort,
}

/// Write a whole STUN frame to a TCP allocation with no remainder buffer: drop
/// the frame if it will not fit the send buffer, otherwise write it fully
/// (retrying `EINTR`); any mid-frame stall or error aborts the connection.
fn tcp_write_frame(sock: &mut Socket, frame: &[u8]) -> Write2 {
	match tcp_send_space(sock) {
		Ok(space) if frame.len() > space => {
			warn!(
				len = frame.len(),
				space, "dropping TCP frame: send buffer full"
			);
			return Write2::Kept;
		}
		Ok(_) => {}
		Err(reason) => {
			trace!(?reason, "tcp_send_space failed; aborting");
			return Write2::Abort;
		}
	}
	let mut off = 0;
	while off < frame.len() {
		match sock.write(&frame[off..]) {
			Ok(0) => return Write2::Abort,
			Ok(n) => off += n,
			Err(e) if e.kind() == ErrorKind::Interrupted => continue,
			Err(reason) => {
				trace!(?reason, "TCP write failed mid-frame; aborting");
				return Write2::Abort;
			}
		}
	}
	Write2::Kept
}

/// Deregister, drop, and forget an allocation.  Removes the `by_peer` entry for
/// connected UDP sockets; a no-op for TCP whose client addr was never indexed.
fn remove_alloc(
	streams: &mut Slab<Socket>,
	by_peer: &mut HashMap<SocketAddrV6, usize>,
	registry: &Registry,
	key: usize,
) {
	let Some(sock) = streams.get(key) else {
		return;
	};
	let fd = sock.as_raw_fd();
	let _ = registry.deregister(&mut SourceFd(&fd));
	if let Ok(peer) = sock.peer_addr()
		&& let Some(peer) = peer.as_socket_ipv6()
	{
		by_peer.remove(&peer);
	}
	streams.remove(key);
}

type Never = core::convert::Infallible;
pub fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	let relay = RelayRange::new(args.relay_net, &args.relay_ports)?;

	let bind = match SocketAddr::from_str(&args.address)? {
		SocketAddr::V6(a) => a,
		SocketAddr::V4(_) => return Err(eyre!("--address must be an IPv6 socket address")),
	};
	let server_port = bind.port();

	// Setup async
	let mut poll = Poll::new()?;

	// Wildcard UDP socket: dual-stack, REUSEPORT (so connected allocation sockets
	// can share the port), IPV6_RECVPKTINFO (so we learn the local dest address).
	let udp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
	udp.set_only_v6(false)?;
	udp.set_reuse_address(true)?;
	udp.set_reuse_port(true)?;
	set_recv_pktinfo(&udp)?;
	udp.bind(&SockAddr::from(bind))?;
	udp.set_nonblocking(true)?;
	poll.registry()
		.register(&mut SourceFd(&udp.as_raw_fd()), UDP, Interest::READABLE)?;

	// TCP listener.
	let listener = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
	listener.set_only_v6(false)?;
	listener.set_reuse_address(true)?;
	listener.set_reuse_port(true)?;
	listener.bind(&SockAddr::from(bind))?;
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

	// Every allocation is a connected socket (connected UDP or accepted TCP);
	// the slab key is the allocation identity and drives the relayed address.
	let mut streams: Slab<Socket> = Slab::with_capacity(64.min(relay.capacity()));
	// Dedup index for Allocate retransmits that race the fork (keyed by client).
	let mut by_peer: HashMap<SocketAddrV6, usize> = HashMap::new();

	loop {
		for e in events.into_iter() {
			match e.token() {
				TCP => loop {
					let stream = match listener.accept() {
						Ok((stream, _sender)) => stream,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => return Err(e.into()),
					};
					if streams.len() >= relay.capacity() {
						warn!("relay pool full; dropping TCP connection");
						continue;
					}
					stream.set_tcp_nodelay(true)?;
					stream.set_nonblocking(true)?;
					let entry = streams.vacant_entry();
					poll.registry().register(
						&mut SourceFd(&stream.as_raw_fd()),
						Token(entry.key()),
						Interest::READABLE,
					)?;
					entry.insert(stream);
				},
				UDP => loop {
					let (n, remote, local) = match recv_with_local(&udp, &mut buffer) {
						Ok(v) => v,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => return Err(e.into()),
					};
					if n < 20 {
						continue;
					}
					let Ok(msg) = Stun::try_mut_from_bytes(&mut buffer).map_err(|_| ()) else {
						continue;
					};
					if msg.txid.id == [0; 12] {
						continue;
					}
					if msg.class != Class::Request
						|| msg.method == Method::Recv
						|| msg.method.is_err()
					{
						continue;
					}

					match msg.method {
						// Stateless binding reply from the correct source address.
						Method::Bind => {
							let unspec = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
							if let Turn::Respond(resp) = handle_turn(unspec, remote, msg, &network)?
							{
								let end = size_of_val(resp.trim());
								let _ = send_from(&udp, local, remote, &buffer[..end]);
							}
						}
						// Fork a connected socket for a new allocation.
						Method::Allocate => {
							if by_peer.contains_key(&remote) {
								// Retransmit that raced the fork; the connected
								// socket will service further retransmits.
								continue;
							}
							let entry = streams.vacant_entry();
							let key = entry.key();
							let Some(relayed) = relay.from_key(key) else {
								warn!("relay pool full; dropping Allocate");
								continue;
							};
							let Turn::Respond(resp) = handle_turn(relayed, remote, msg, &network)?
							else {
								continue;
							};
							let success = !resp.method.is_err();
							let end = size_of_val(resp.trim());
							if success {
								let sock = connected_udp(
									SocketAddrV6::new(local, server_port, 0, 0),
									remote,
									UdpOpt::ReusePort,
								)?;
								poll.registry().register(
									&mut SourceFd(&sock.as_raw_fd()),
									Token(key),
									Interest::READABLE,
								)?;
								let _ = sock.send(&buffer[..end]);
								entry.insert(sock);
								by_peer.insert(remote, key);
							} else {
								// Auth/validation error: reply off the wildcard,
								// do not allocate (vacant entry is dropped).
								let _ = send_from(&udp, local, remote, &buffer[..end]);
							}
						}
						// Refresh/CreatePermission/Send/... on the wildcard are
						// packets queued before the split: drop them.
						_ => continue,
					}
				},
				TUN => loop {
					let receiver;
					let msg;
					match read_network(&network, &mut buffer[20 + 24 + 4..], args.router.octets()) {
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => return Err(e.into()),
						Ok(Packet::Udp { ip, udp }) => {
							// Peer -> relayed: dst is the relayed address.
							receiver =
								SocketAddrV6::new(Ipv6Addr::from(ip.dst), udp.dst_port.get(), 0, 0);

							let data_length = udp.length.get() - 8;
							let sender =
								Addr6::new(Ipv6Addr::from_octets(ip.src), udp.src_port.get());
							msg = Stun::new(Class::Request, Method::Recv, &mut buffer)
								.map_err(|e| eyre!("{e:?}"))?;
							msg.append_val(known::XOR_PEER_ADDRESS, &sender.xor(&msg.txid));
							msg.append_once(|_, a| {
								a.typ = known::DATA;
								a.length.set(data_length); // UDP data already in position.
							});
						}
						Ok(Packet::Icmp {
							ip: _,
							icmp,
							inner_ip,
							inner_udp,
						}) => {
							// ICMP quotes a packet we sent (src = relayed): key on
							// its source; peer is the quoted destination.
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
					};

					let end = size_of_val(msg.trim());

					// Which allocation does the relayed address belong to?
					let Some(key) = relay.to_key(*receiver.ip(), receiver.port()) else {
						continue;
					};
					let Some(sock) = streams.get_mut(key) else {
						continue;
					};
					let is_udp = sock.r#type().map(|t| t == Type::DGRAM).unwrap_or(false);
					if is_udp {
						let _ = sock.send(&buffer[..end]);
					} else if let Write2::Abort = tcp_write_frame(sock, &buffer[..end]) {
						remove_alloc(&mut streams, &mut by_peer, poll.registry(), key);
					}
				},
				Token(key) => {
					if streams.get(key).is_none() {
						continue;
					}
					if e.is_read_closed() || e.is_error() {
						trace!(?e, "closing allocation (is_error / is_read_closed)");
						remove_alloc(&mut streams, &mut by_peer, poll.registry(), key);
						continue;
					}

					let is_udp = streams
						.get(key)
						.and_then(|s| s.r#type().ok())
						.map(|t| t == Type::DGRAM)
						.unwrap_or(false);
					let close = if is_udp {
						handle_udp_alloc(key, &relay, &mut streams, &mut buffer, &network)?
					} else {
						handle_tcp_alloc(key, &relay, &mut streams, &mut buffer, &network)?
					};
					if close {
						remove_alloc(&mut streams, &mut by_peer, poll.registry(), key);
					}
				}
			}
		}

		poll.poll(&mut events, None)?;
	}
}

/// Drain a connected UDP allocation. Returns `true` if it should be torn down.
fn handle_udp_alloc(
	key: usize,
	relay: &RelayRange,
	streams: &mut Slab<Socket>,
	buffer: &mut [u8],
	network: &SyncDevice,
) -> Result<bool> {
	let sock = streams.get(key).unwrap();
	let Some(relayed) = relay.from_key(key) else {
		return Ok(true);
	};
	let Some(remote) = sock.peer_addr().ok().and_then(|a| a.as_socket_ipv6()) else {
		return Ok(true);
	};

	loop {
		let n = match recv_with_local(sock, buffer) {
			Ok((n, _, _)) => n,
			Err(e) if e.kind() == ErrorKind::WouldBlock => break,
			Err(reason) => {
				trace!(?reason, "UDP allocation recv error; closing");
				return Ok(true);
			}
		};
		if n < 20 {
			continue;
		}
		let Ok(msg) = Stun::try_mut_from_bytes(buffer).map_err(|_| ()) else {
			continue;
		};
		if msg.txid.id == [0; 12] {
			continue;
		}
		match handle_turn(relayed, remote, msg, network)? {
			Turn::Respond(resp) => {
				let end = size_of_val(resp.trim());
				let _ = sock.send(&buffer[..end]);
			}
			Turn::Silent => {}
			Turn::Close => return Ok(true),
		}
	}
	Ok(false)
}

/// Read framed STUN from a TCP allocation. Returns `true` if it should be torn
/// down.
fn handle_tcp_alloc(
	key: usize,
	relay: &RelayRange,
	streams: &mut Slab<Socket>,
	buffer: &mut [u8],
	network: &SyncDevice,
) -> Result<bool> {
	let Some(relayed) = relay.from_key(key) else {
		return Ok(true);
	};
	let Some(remote) = streams
		.get(key)
		.and_then(|s| s.peer_addr().ok())
		.and_then(|a| a.as_socket_ipv6())
	else {
		return Ok(true);
	};

	loop {
		let sock = streams.get_mut(key).unwrap();
		let available = match peek(sock, buffer) {
			Ok(0) => return Ok(true), // peer closed
			Ok(n) => n,
			Err(e) if e.kind() == ErrorKind::WouldBlock => break,
			Err(reason) => {
				trace!(?reason, "TCP peek error; closing");
				return Ok(true);
			}
		};
		let end = match Stun::try_mut_from_bytes(buffer).map_err(AlignedTryCastError::from) {
			Err(AlignedTryCastError::Validity(reason)) if available >= 20 => {
				trace!(?reason, "Non-STUN frame; closing");
				return Ok(true);
			}
			Ok(m) => {
				let end = size_of_val(m.trim());
				if available < end {
					break;
				}
				end
			}
			_ => break,
		};
		// Consume exactly one framed message.
		let n = sock.read(&mut buffer[..end])?;
		if n < end {
			// Shouldn't happen: peek reported >= end bytes buffered.
			trace!(n, end, "short read after peek; closing");
			return Ok(true);
		}
		// Parse over the FULL buffer (not buffer[..end]) so handle_turn has
		// headroom to append the response; the STUN length header bounds the
		// request and trim() handles trailing bytes.
		let Ok(msg) = Stun::try_mut_from_bytes(buffer).map_err(|_| ()) else {
			continue;
		};
		if msg.txid.id == [0; 12] {
			continue;
		}
		match handle_turn(relayed, remote, msg, network)? {
			Turn::Respond(resp) => {
				let end = size_of_val(resp.trim());
				// Reborrow the socket mutably for the write.
				let sock = streams.get_mut(key).unwrap();
				if let Write2::Abort = tcp_write_frame(sock, &buffer[..end]) {
					return Ok(true);
				}
			}
			Turn::Silent => {}
			Turn::Close => return Ok(true),
		}
	}
	Ok(false)
}

fn handle_turn<'i>(
	relayed: SocketAddrV6,
	remote: SocketAddrV6,
	msg: &'i mut Stun,
	network: &SyncDevice,
) -> Result<Turn<'i>> {
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
		.parse::<{ known::NONCE }, str>(&mut nonce)
		.parse::<{ known::REQUESTED_TRANSPORT }, [u8; 4]>(&mut transport);

	let mut unk = Vec::new();
	msg.length.set(U16::new(0));

	for (prefix, attr) in attrs {
		match attr.typ {
			known::MESSAGE_INTEGRITY => {
				integrity = match username {
					Parsed::Valid("guest")
						if attr.value == prefix.expected_message_integrity(GUEST_KEY) =>
					{
						Some(GUEST_KEY)
					}
					Parsed::Valid("user")
						if attr.value == prefix.expected_message_integrity(USER_KEY) =>
					{
						Some(USER_KEY)
					}
					_ => None,
				};
				break;
			}
			_ if attr.is_optional() => {}
			t => unk.push(t),
		}
	}

	let lifetime = if let Parsed::Valid(l) = lifetime {
		*l
	} else {
		U32::new(60_000)
	};

	let add_mapped = move |msg: &mut Stun| match remote.ip().to_canonical() {
		IpAddr::V4(v4) => {
			msg.append_val(
				known::XOR_MAPPED_ADDRESS,
				&Addr4::new(v4, remote.port()).xor(&msg.txid),
			);
		}
		IpAddr::V6(v6) => {
			msg.append_val(
				known::XOR_MAPPED_ADDRESS,
				&Addr6::new(v6, remote.port()).xor(&msg.txid),
			);
		}
	};

	match msg.method {
		Method::Allocate if !unk.is_empty() => {
			msg.class = Class::Response;
			msg.method = msg.method.to_err();
			msg.length.get_mut().set(0);
			msg.append_val(known::UNKNOWN_ATTRIBUTES, unk.as_slice());
		}
		_ if !unk.is_empty() => return Ok(Turn::Silent),

		Method::Bind => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			add_mapped(msg);
		}
		Method::Send => {
			let (Parsed::Valid(peer), Parsed::Valid(data)) = (peer, data) else {
				return Ok(Turn::Silent);
			};
			let peer = peer.xor(&msg.txid);

			// Relay with src = the relayed transport address; peers must see the
			// relayed address, not the client's mapped address.
			let _ = write_network_udp(
				network,
				(relayed.ip().octets(), U16::new(relayed.port())),
				(peer.ip().octets(), U16::new(peer.port())),
				data,
			);

			return Ok(Turn::Silent);
		}
		m if realm != Parsed::Valid("none") => {
			msg.class = Class::Response;
			msg.method = m.to_err();
			msg.length.get_mut().set(0);
			msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 1]);
			msg.append_val(known::REALM, "none");
			msg.append_val(known::NONCE, "none");
		}
		m if (nonce, integrity.is_some()) != (Parsed::Valid("none"), true) => {
			msg.class = Class::Response;
			msg.method = m.to_err();
			msg.length.get_mut().set(0);
			msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 3]);
		}
		Method::Allocate => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			add_mapped(msg);
			msg.append_val(
				known::XOR_RELAYED_ADDRESS,
				&Addr6::new(*relayed.ip(), relayed.port()).xor(&msg.txid),
			);
			msg.append_val(known::LIFETIME, &lifetime);
		}
		// Close notification: tear the allocation down.
		Method::Refresh if lifetime.get() == 0 => return Ok(Turn::Close),
		Method::Refresh => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			msg.append_val(known::LIFETIME, &lifetime);
		}
		Method::AddPermission => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
		}
		Method::UseChannel => {
			msg.class = Class::Response;
			msg.method = msg.method.to_err();
			msg.length.get_mut().set(0);
			msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 38]);
		}
		_ => return Ok(Turn::Silent),
	}

	if let Some(authkey) = integrity {
		msg.append_val(
			known::MESSAGE_INTEGRITY,
			&msg.trim().expected_message_integrity(authkey),
		);
	}

	Ok(Turn::Respond(msg))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn range() -> RelayRange {
		// 2 addresses (::/127-ish via a /127) x 3 ports.
		RelayRange::new(Ipv6Net::from_str("2001:db8::/127").unwrap(), "50000-50002").unwrap()
	}

	#[test]
	fn round_trip() {
		let r = range();
		assert_eq!(r.capacity(), 2 * 3);
		for key in 0..r.capacity() {
			let addr = r.from_key(key).expect("in range");
			let back = r.to_key(*addr.ip(), addr.port()).expect("maps back");
			assert_eq!(back, key, "round trip for {addr}");
		}
	}

	#[test]
	fn port_first_layout() {
		let r = range();
		// key 0..3 share the base IP, ascending port; key 3 rolls to next IP.
		let base = Ipv6Addr::from_str("2001:db8::").unwrap();
		let next = Ipv6Addr::from_str("2001:db8::1").unwrap();
		assert_eq!(r.from_key(0).unwrap(), SocketAddrV6::new(base, 50000, 0, 0));
		assert_eq!(r.from_key(2).unwrap(), SocketAddrV6::new(base, 50002, 0, 0));
		assert_eq!(r.from_key(3).unwrap(), SocketAddrV6::new(next, 50000, 0, 0));
		assert_eq!(r.from_key(5).unwrap(), SocketAddrV6::new(next, 50002, 0, 0));
	}

	#[test]
	fn bounds() {
		let r = range();
		let base = Ipv6Addr::from_str("2001:db8::").unwrap();
		assert!(r.from_key(6).is_none(), "past capacity");
		assert!(r.to_key(base, 49999).is_none(), "port below range");
		assert!(r.to_key(base, 50003).is_none(), "port above range");
		let outside = Ipv6Addr::from_str("2001:db8::2").unwrap();
		assert!(r.to_key(outside, 50000).is_none(), "ip outside subnet");
		let below = Ipv6Addr::from_str("2001:db7::").unwrap();
		assert!(r.to_key(below, 50000).is_none(), "ip below base");
	}
}
