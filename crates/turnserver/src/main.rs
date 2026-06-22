use clap::Parser;
use eyre::{Result, eyre};
use ipnet::Ipv6Net;
use mio::{
	Events, Interest, Poll, Registry, Token,
	net::{TcpListener, TcpStream, UdpSocket},
	unix::SourceFd,
};
use slab::Slab;
use std::{
	io::{ErrorKind, IoSlice, Read, Write},
	net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
	ops::{BitAnd, BitOr, Deref, DerefMut},
	os::fd::AsRawFd,
	str::FromStr,
};
use stun::{
	Class, Method, Parse, Parsed, Stun,
	addr::{Addr4, Addr6, Xor},
	known,
};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{
	AlignedTryCastError, IntoBytes, TryFromBytes,
	network_endian::{U16, U32},
};

use common::{Ip6, Packet, Udp, VNET, full_checksum, partial_checksum, proto, read_network};

/// md5('user:none:password')
const TURNKEY: &[u8] = &[
	0x9a, 0xc1, 0x33, 0x6a, 0xc2, 0xef, 0x12, 0xb8, 0xa1, 0x06, 0x00, 0x7a, 0xab, 0x74, 0x25, 0xf3,
];

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value = "[::]:3478")]
	address: String,

	#[arg(long, short)]
	router: Ipv6Addr,

	#[arg(long, short)]
	mapping: Vec<String>,

	#[arg(long, short)]
	if_name: Option<String>,

	#[arg(long, short, default_value = "::6666:0:0/96")]
	tcpnet: String,
}

// 1-to-1 IPv6 subnet mappings.  Primarily intended for mapping ::ffff:0.0.0.0/96<->[a network that you control], and potentially for mapping 2000::/3<->A000::/3 to statelessly differentiate between TURN/UDP packets from normal UDP packets received from IPv6 peers.
struct Mapping {
	udp: Ipv6Net,
	tun: Ipv6Net,
}
impl FromStr for Mapping {
	type Err = eyre::Report;
	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		let (udp, tun) = s.split_once("<->").ok_or(eyre!("stuff"))?;
		let udp = Ipv6Net::from_str(udp)?;
		let tun = Ipv6Net::from_str(tun)?;
		if udp.prefix_len() != tun.prefix_len() {
			return Err(eyre!("subnets need to have the same size"));
		}
		Ok(Self { udp, tun })
	}
}
impl Mapping {
	fn to_net(&self, addr: &mut Ipv6Addr) -> bool {
		if self.udp.contains(&*addr) {
			*addr = self.tun.network().bitor(self.udp.hostmask().bitand(*addr));
			return true;
		}
		false
	}
	fn to_udp(&self, addr: &mut Ipv6Addr) -> bool {
		if self.tun.contains(&*addr) {
			*addr = self.udp.network().bitor(self.tun.hostmask().bitand(*addr));
			return true;
		}
		false
	}
}

// Holder for a tcpstream and any partial data waiting to be written to it
struct Conn {
	partial: Option<(usize, Box<[u8]>)>,
	stream: TcpStream,
}

struct Cleanup<'a> {
	key: usize,
	streams: &'a mut Slab<Conn>,
	registry: &'a Registry,
}
impl Deref for Cleanup<'_> {
	type Target = Conn;
	fn deref(&self) -> &Self::Target {
		// Hopefully these indexes are cheap.  I would prefer to hold an slab entry instead, but I think slab only has a vacant entry type.
		self.streams.get(self.key).unwrap()
	}
}
impl DerefMut for Cleanup<'_> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.streams.get_mut(self.key).unwrap()
	}
}
impl<'a, 'b: 'a> Cleanup<'a> {
	pub fn get_mut(
		streams: &'a mut Slab<Conn>,
		key: usize,
		registry: &'a Registry,
	) -> Option<Self> {
		let _ = streams.get_mut(key)?;
		Some(Self {
			key,
			streams,
			registry,
		})
	}
	pub fn cleanup(self) -> Result<(), std::io::Error> {
		let Conn {
			mut stream,
			partial: _,
		} = self.streams.remove(self.key);
		self.registry.deregister(&mut stream)
	}
}

// Tokens used by everything that isn't a TcpStream
const UDP: Token = Token(usize::MAX);
const TCP: Token = Token(usize::MAX - 1);
const TUN: Token = Token(usize::MAX - 2);

struct TcpNet {
	subnet: Ipv6Net,
}
impl TcpNet {
	fn from_index(&self, index: usize) -> Option<SocketAddrV6> {
		// The least 15 bits become the port
		let port = (index & 0x7fff | 0x8000) as u16;

		// The remaining 17 or 49 bits are the host
		let host = Ipv6Addr::from_bits(index as u128 >> 15);
		let ip = self.subnet.network() | host;

		// Check if we've exceeded our subnet
		if !self.subnet.contains(&ip) {
			return None;
		}

		Some(SocketAddrV6::new(ip, port, 0, 0))
	}
	fn to_index(&self, addr: SocketAddrV6) -> Option<usize> {
		if !self.subnet.contains(addr.ip()) {
			return None;
		};
		let host = addr.ip() & self.subnet.hostmask();
		let ret = (host.to_bits() << 15) | (0x7FFF & addr.port()) as u128;
		Some(ret as usize)
	}
}

type Never = core::convert::Infallible;
fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Parse/split the net mappings
	let mut mappings = Vec::new();
	for s in args.mapping.into_iter() {
		mappings.push(Mapping::from_str(&s)?)
	}

	// This is silly, it's just saying "what subnet should tcp streams be mapped to" in the same way that ipv4 udp is mapped to ::ffff:0:0/96
	let tcpnet = TcpNet {
		subnet: Ipv6Net::from_str(&args.tcpnet)?,
	};

	// Setup async
	let mut poll = Poll::new()?;

	// Listen for TURN traffic
	let socket = std::net::UdpSocket::bind(&args.address)?;
	socket.set_nonblocking(true)?;
	let mut socket = UdpSocket::from_std(socket);
	poll.registry()
		.register(&mut socket, UDP, Interest::READABLE)?;

	let listener = std::net::TcpListener::bind(&args.address)?;
	listener.set_nonblocking(true)?;
	let mut listener = TcpListener::from_std(listener);
	poll.registry()
		.register(&mut listener, TCP, Interest::READABLE)?;

	// Setup the TUN interface
	let network = {
		let mut builder = DeviceBuilder::new();
		#[cfg(target_os = "linux")]
		{
			builder = builder.offload(true); // I'm not trying to do segmentation offloading, I'm only trying to do checksum offloading, but...
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

	let mut streams = Slab::new();

	// Preload the authkey into the buffer.  As long as we never touch bellow the HEADROOM of the buffer then this data will stay in place
	{
		let t = Stun::new(Class::Request, Method::Bind, buffer.as_mut_slice())
			.map_err(|e| eyre!("{e:?}"))?;
		t.set_authkey(TURNKEY);
	}

	loop {
		for e in events.into_iter() {
			match e.token() {
				TCP => loop {
					let mut stream = match listener.accept() {
						Ok((stream, _sender)) => stream,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => return Err(e.into()),
					};
					stream.set_nodelay(true)?;
					let entry = streams.vacant_entry();
					poll.registry().register(
						&mut stream,
						Token(entry.key()),
						Interest::READABLE | Interest::WRITABLE,
					)?;
					entry.insert(Conn {
						partial: None,
						stream,
					});
				},
				UDP => loop {
					let sender = match socket.recv_from(&mut buffer[Stun::HEADROOM..]) {
						Ok((20.., SocketAddr::V6(sender))) => sender,
						Ok(_) => continue,
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => return Err(e.into()),
					};
					let Ok(msg) = Stun::try_mut_from_bytes(&mut buffer).map_err(|_| ()) else {
						continue;
					};
					if msg.class != Class::Request
						|| msg.method == Method::Recv
						|| msg.method.is_err()
					{
						continue;
					}
					if let Some(resp) = handle_turn(&mappings, sender, msg, &network)? {
						let end = size_of_val(resp.trim());
						socket.send_to(&buffer[Stun::HEADROOM..end], sender.into())?;
					}
				},
				TUN => loop {
					let receiver;
					let msg;
					match read_network(
						&network,
						&mut buffer[Stun::HEADROOM + 20 + 24 + 4..],
						&args.router,
					) {
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => return Err(e.into()),
						Ok(Packet::Udp { ip, udp }) => {
							// Unmap the destination ip address
							let mut peer_ip = Ipv6Addr::from(ip.dst);
							for m in &mappings {
								if m.to_udp(&mut peer_ip) {
									break;
								}
							}
							receiver = SocketAddrV6::new(peer_ip, udp.dst_port.get(), 0, 0);

							let data_length = udp.length.get() - 8;
							let sender =
								Addr6::new(Ipv6Addr::from_octets(ip.src), udp.src_port.get());
							msg = Stun::new(Class::Request, Method::Recv, &mut buffer)
								.map_err(|e| eyre!("{e:?}"))?;
							msg.append_val(known::XOR_PEER_ADDRESS, &sender.xor(&msg.txid));
							msg.append_once(|_, a| {
								a.typ = known::DATA;
								a.length.set(data_length); // If my headroom calculations are correct, the UDP data is already in the correct position.
							});
						}
						Ok(Packet::Icmp {
							ip: _,
							icmp,
							inner_ip,
							inner_udp,
						}) => {
							// Unmap the inner ip address
							let mut peer_ip = Ipv6Addr::from(inner_ip.src);
							for m in &mappings {
								if m.to_udp(&mut peer_ip) {
									break;
								}
							}
							receiver = SocketAddrV6::new(peer_ip, inner_udp.src_port.get(), 0, 0);

							// How to handle receiving ICMP packets [RFC8656 Section 11.5](https://datatracker.ietf.org/doc/html/rfc8656#section-11.5)
							// The XOR-PEER-ADDRESS attribute is set to the destination ip+port (if port is unavailable it is zeroed) of the returned UDP packet.  The Outer IP src ip address (The router / host that generated the ICMP message) is not used.
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
								// NOTE: We are not changing the ICMP mtu because the client already knows we are relaying their data as IPv6+UDP packets (because of the family in XOR-PEER-ADDRESS).
								a.put_u32(icmp.mtu.get());
							});
						}
					};

					let end = size_of_val(msg.trim());
					let frame = &buffer[Stun::HEADROOM..end];
					// Send to TCP clients
					if let Some(key) = tcpnet.to_index(receiver) {
						let Some(mut conn) = Cleanup::get_mut(&mut streams, key, poll.registry())
						else {
							// TODO: Return ICMP Port Unreachable for closed TCP streams?  Part of the problem is that our slab will reuse indexes frequently, meaning you are probably talking to a previous client/association.  I really want to use raw file descriptors instead of the slab allocator because I think that those will rotate less frequently.  Frankly we should probably just btreemap<u32, TcpStream> with an incrementing key... whatever.
							continue;
						};
						if conn.partial.is_some() {
							continue;
						}

						let mut offset = 0;
						loop {
							let rest = &buffer[Stun::HEADROOM + offset..end];
							match conn.stream.write(rest) {
								Ok(written) if written >= rest.len() => break,
								Ok(written) => offset += written,
								Err(e) if e.kind() == ErrorKind::WouldBlock => {
									conn.partial = Some((0, Box::from(rest)));
								}
								Err(_) => {
									conn.cleanup()?;
									break;
								}
							}
						}
					}
					// Send to UDP clients
					else {
						let _ = socket.send_to(frame, receiver.into());
					}
				},
				Token(key) => 'event: {
					let Some(mut conn) = Cleanup::get_mut(&mut streams, key, poll.registry())
					else {
						break 'event;
					};

					// NOTE: For cleanup, there's no need to finish writing partial data or anything like that, we just close.
					if e.is_read_closed() || e.is_error() {
						conn.cleanup()?;
						break 'event;
					}

					// Continue writing previous partial frame
					while e.is_writable() {
						let Some((offset, buffer)) = conn.partial.take() else {
							break;
						};
						let rest = &buffer[offset..];

						match conn.stream.write(rest) {
							Ok(written) if written >= rest.len() => break,
							Ok(written) => conn.partial = Some((offset + written, buffer)),
							Err(e) if e.kind() == ErrorKind::WouldBlock => {
								conn.partial = Some((offset, buffer));
								break;
							}
							Err(_) => {
								conn.cleanup()?;
								break 'event;
							}
						}
					}

					// Handle reading
					while e.is_readable() {
						let available = match conn.stream.peek(&mut buffer[Stun::HEADROOM..]) {
							Ok(n) => Stun::HEADROOM + n,
							Err(e) if e.kind() == ErrorKind::WouldBlock => break,
							Err(_) => {
								conn.cleanup()?;
								break;
							}
						};
						let msg = match Stun::try_mut_from_bytes(&mut buffer)
							.map_err(AlignedTryCastError::from)
						{
							Err(AlignedTryCastError::Validity(_v)) if available >= 20 => {
								conn.cleanup()?;
								break;
							}
							Ok(m) => {
								let end = size_of_val(m.trim());
								if available < end {
									break;
								}
								// TODO: If read is less than what we peek'd then we're fucked
								let n = conn.stream.read(&mut buffer[Stun::HEADROOM..end])?;
								if (Stun::HEADROOM + n) < n {
									panic!("Read short of peek'd!");
								}
								Stun::try_mut_from_bytes(&mut buffer).unwrap()
							}
							_ => break,
						};

						// Drop the TURN message if we have partial data waiting to be written out
						if conn.partial.is_some() {
							continue;
						};

						let Some(sender) = tcpnet.from_index(key) else {
							continue;
						};
						let Some(resp) = handle_turn(&mappings, sender, msg, &network)? else {
							continue;
						};

						let end = size_of_val(resp.trim());
						let mut offset = 0;
						loop {
							let rest = &buffer[Stun::HEADROOM + offset..end];
							match conn.stream.write(rest) {
								Ok(written) if written >= rest.len() => break,
								Ok(written) => offset += written,
								Err(e) if e.kind() == ErrorKind::WouldBlock => {
									conn.partial = Some((0, Box::from(rest)));
								}
								Err(_) => {
									conn.cleanup()?;
									break 'event;
								}
							}
						}
					}
				}
			}
		}

		poll.poll(&mut events, None)?;
	}
}

fn handle_turn<'i>(
	mappings: &Vec<Mapping>,
	sender: SocketAddrV6,
	msg: &'i mut Stun,
	network: &SyncDevice,
) -> Result<Option<&'i mut Stun>> {
	// Apply our subnet mappings to the sender/source ip
	let mut src_ip = *sender.ip();
	for m in mappings {
		if m.to_net(&mut src_ip) {
			break;
		}
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
	let mut integrity = false;

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
				integrity = attr.value == prefix.expected_message_integrity();
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

	let add_mapped = move |msg: &mut Stun| match sender.ip().to_canonical() {
		IpAddr::V4(v4) => {
			msg.append_val(
				known::XOR_MAPPED_ADDRESS,
				&Addr4::new(v4, sender.port()).xor(&msg.txid),
			);
		}
		IpAddr::V6(v6) => {
			msg.append_val(
				known::XOR_MAPPED_ADDRESS,
				&Addr6::new(v6, sender.port()).xor(&msg.txid),
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
		_ if !unk.is_empty() => return Ok(None),

		Method::Bind => {
			msg.class = Class::Response;
			msg.length.get_mut().set(0);
			add_mapped(msg);
		}
		Method::Send => {
			let (Parsed::Valid(peer), Parsed::Valid(data)) = (peer, data) else {
				return Ok(None);
			};
			let peer = peer.xor(&msg.txid);
			let ip = Ip6 {
				flags: Ip6::FLAGS,
				length: U16::new((size_of::<Udp>() + data.len()) as u16),
				next_header: proto::UDP,
				hop_limit: 64,
				src: src_ip.octets(),
				dst: peer.ip().octets(),
			};
			let mut udp = Udp {
				src_port: U16::new(sender.port()),
				dst_port: U16::new(peer.port()),
				length: ip.length,
				checksum: 0,
			};

			let vnet = partial_checksum(&ip, &mut udp);
			if VNET == 0 {
				full_checksum(&mut udp, &[data]);
			}
			let vnet = &vnet.as_bytes()[..VNET];
			network.send_vectored(&[
				IoSlice::new(vnet),
				IoSlice::new(ip.as_bytes()),
				IoSlice::new(udp.as_bytes()),
				IoSlice::new(data),
			])?;

			return Ok(None);
		}
		m if realm != Parsed::Valid("none") => {
			msg.class = Class::Response;
			msg.method = m.to_err();
			msg.length.get_mut().set(0);
			msg.append_val(known::ERROR_CODE, &[0u8, 0, 4, 1]);
			msg.append_val(known::REALM, "none");
			msg.append_val(known::NONCE, "none");
		}
		m if (nonce, integrity) != (Parsed::Valid("none"), true) => {
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
				&Addr6::new(src_ip, sender.port()).xor(&msg.txid),
			);
			msg.append_val(known::LIFETIME, &lifetime);
		}
		// Close notification, just drop
		Method::Refresh if lifetime.get() == 0 => return Ok(None),
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
		_ => return Ok(None),
	}

	if integrity {
		msg.append_val(
			known::MESSAGE_INTEGRITY,
			&msg.trim().expected_message_integrity(),
		);
	}

	Ok(Some(msg))
}
