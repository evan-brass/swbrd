use std::{
	cell::{Cell, RefCell},
	io::{Error, ErrorKind},
	net::{Ipv6Addr, SocketAddrV6},
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
	poller::{Flag, Poller, Sourced, Static},
	read_network, write_network_icmp, write_network_udp,
};
use eyre::Result;
use intrusive_collections::{
	KeyAdapter, LinkedList, LinkedListLink, RBTree, RBTreeLink, intrusive_adapter,
};
use mio::{Events, Interest, Poll};
use openssl::ssl::{
	Ssl, SslAcceptor, SslContext, SslContextRef, SslFiletype, SslMethod, SslVersion,
};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use socket3::SocketMtuExt;
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{IntoBytes, network_endian::U16};

mod cookie;
mod ffi;
mod keys;
use crate::{
	cookie::{Verdict, Verified},
	ffi::SslIo,
	keys::{ReadKeys, check_record, export_read_keys},
};

/// IPv6 (40) + UDP (8) header overhead between a link/path MTU and the UDP
/// payload a DTLS record occupies.
const IP_UDP: u32 = 40 + 8;

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short)]
	if_name: Option<String>,

	#[arg(long, short)]
	router: Ipv6Addr,

	#[arg(long, short, default_value = "[::1]:9899")]
	endpoint: String,
}

/// An established or in-flight DTLS connection.  The client-facing ciphertext
/// rides its own connected `IP_TRANSPARENT` socket, managed by OpenSSL's dgram
/// BIO; only endpoint plaintext and first-contact ClientHellos touch the TUN.
struct Client {
	ssl: RefCell<Ssl>,
	/// Connected transparent socket (owns the fd the dgram BIO borrows).
	sock: Socket,
	established: Cell<bool>,
	/// Read-direction (client write) keys, derived lazily once established and
	/// used to authenticate roamed records for client mobility.
	read_keys: Cell<Option<ReadKeys>>,
	/// Highest record number authenticated for mobility so far; a roamed record
	/// must strictly exceed it to re-point the socket (anti-replay).
	highest_read_seq: Cell<u64>,

	bound: SocketAddrV6, // Replaces send_from
	bound_link: RBTreeLink,
	connected: Cell<SocketAddrV6>,
	connected_link: RBTreeLink,

	keepalives: Cell<u8>,
	timeout: Cell<Instant>,
	timeout_link: LinkedListLink,
}
impl Sourced for Client {
	fn fd(&self, flag: common::poller::Flag) -> Option<std::os::fd::RawFd> {
		match flag {
			Flag::A => Some(self.sock.as_raw_fd()),
			// TODO: Flag::B will be a :5000/sctp peeled_off/stream socket that was established via the dtls-proxy
			_ => unreachable!(),
		}
	}
}
intrusive_adapter!(Bound = Rc<Client>: Client { bound_link => RBTreeLink });
intrusive_adapter!(Connected = Rc<Client>: Client { connected_link => RBTreeLink });
intrusive_adapter!(Timeout = Rc<Client>: Client { timeout_link => LinkedListLink });
impl<'a> KeyAdapter<'a> for Bound {
	type Key = &'a SocketAddrV6;
	fn get_key(
		&self,
		value: &'a <Self::PointerOps as intrusive_collections::PointerOps>::Value,
	) -> Self::Key {
		&value.bound
	}
}
impl KeyAdapter<'_> for Connected {
	type Key = SocketAddrV6;
	fn get_key(
		&self,
		value: &<Self::PointerOps as intrusive_collections::PointerOps>::Value,
	) -> Self::Key {
		value.connected.get()
	}
}

/// Pin the negotiation to AES-128-GCM over DTLS 1.2 — the single record layout
/// that [`keys::check_record`] can authenticate for client mobility.  Both Chrome
/// and Firefox offer these suites for ECDSA/RSA certs (see `docs/ciphersuites.md`).
fn pin_suite(acceptor: &mut openssl::ssl::SslAcceptorBuilder) -> Result<()> {
	acceptor.set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")?;
	acceptor.set_min_proto_version(Some(SslVersion::DTLS1_2))?;
	acceptor.set_max_proto_version(Some(SslVersion::DTLS1_2))?;
	Ok(())
}

fn load_config() -> Result<(SslContext, SslContext)> {
	let january = {
		let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
		acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
		acceptor.set_certificate_file("January.der", SslFiletype::ASN1)?;
		acceptor.check_private_key()?;
		pin_suite(&mut acceptor)?;
		cookie::configure(&mut acceptor);
		acceptor.build().into_context()
	};
	let july = {
		let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
		acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
		acceptor.set_certificate_file("July.der", SslFiletype::ASN1)?;
		acceptor.check_private_key()?;
		pin_suite(&mut acceptor)?;
		cookie::configure(&mut acceptor);
		acceptor.build().into_context()
	};

	println!("Configuration loaded");

	Ok((january, july))
}

struct Server {
	poll: Poller<Client>,
	bound: RBTree<Bound>,
	connected: RBTree<Connected>,
	timeouts: LinkedList<Timeout>,
}
impl Server {
	fn remove_conn(&mut self, client: Rc<Client>) -> Result<(), Error> {
		// let Some(conn) = streams.try_remove(key) else {
		// 	return;
		// };
		// let _ = registry.deregister(&mut SourceFd(&conn.sock.as_raw_fd()));
		// by_addr.remove(&conn.send_from);
		todo!()
	}
	fn create_client(
		&mut self,
		ctx: &SslContext,
		verified: &Verified,
		send_from: SocketAddrV6,
		send_to: SocketAddrV6,
	) -> Result<(), Error> {
		// let local = SocketAddrV6::new(Ipv6Addr::from(send_from.0), send_from.1.get(), 0, 0);
		// let remote = SocketAddrV6::new(Ipv6Addr::from(send_to.0), send_to.1.get(), 0, 0);
		// let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
		// sock.set_only_v6(true)?;
		// #[cfg(target_os = "linux")]
		// sock.set_ip_transparent_v6(true)?;
		// SockRef::from(&sock).set_path_mtu_discovery(true)?;
		// sock.bind(&SockAddr::from(local))?;
		// sock.connect(&SockAddr::from(remote))?;
		// sock.set_nonblocking(true)?;

		// let hs = cookie::promote(ctx, verified)?;

		// // Unfragmented hello: the ServerHello flight is already produced; send it on
		// // the socket before cutover.  (Fragmented: nothing yet — the rest arrives on
		// // the socket.)
		// for datagram in hs.drain_output() {
		// 	let _ = sock.send(&datagram);
		// }

		// let fd = sock.as_raw_fd();
		// let established = hs.is_finished();
		// let ssl = hs.into_established(fd)?;

		// let entry = streams.vacant_entry();
		// let key = entry.key();
		// registry.register(&mut SourceFd(&fd), Token(key), Interest::READABLE)?;
		// entry.insert(Connection {
		// 	ssl,
		// 	sock,
		// 	send_from,
		// 	established,
		// 	last_update: Instant::now(),
		// 	read_keys: None,
		// 	highest_read_seq: 0,
		// });
		// by_addr.insert(send_from, key);
		// Ok(())
		todo!()
	}
	fn drive_connection(&mut self) -> Result<(), Error> {
		// loop {
		// 	let Some(conn) = streams.get_mut(key) else {
		// 		return;
		// 	};
		// 	let outcome = if !conn.established {
		// 		let r = ffi::do_handshake(&mut conn.ssl);
		// 		if matches!(r, SslIo::Ok(_)) {
		// 			conn.established = conn.ssl.is_init_finished();
		// 			conn.last_update = Instant::now();
		// 		}
		// 		r
		// 	} else {
		// 		let r = ffi::read(&mut conn.ssl, buffer);
		// 		if let SslIo::Ok(len) = r
		// 			&& len > 0
		// 		{
		// 			conn.last_update = Instant::now();
		// 			let from = conn.send_from;
		// 			let _ = write_network_udp(network, from, endpoint, &buffer[..len]);
		// 		}
		// 		r
		// 	};

		// 	match outcome {
		// 		// Handshake step or read made progress: keep draining.
		// 		SslIo::Ok(_) => continue,
		// 		// Nothing more to read right now.
		// 		SslIo::WantRead | SslIo::WantWrite => return,
		// 		// close_notify, a connected-socket error (e.g. ECONNREFUSED surfaced
		// 		// by the dgram BIO's recv), or a fatal alert: tear down.
		// 		SslIo::ZeroReturn | SslIo::Syscall(_) | SslIo::Fatal => {
		// 			remove_conn(streams, by_addr, registry, key);
		// 			return;
		// 		}
		// 	}
		// }
		todo!()
	}
}

const TUN: Static = Static(0);

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

	let mut poll = Poller::new(Poll::new()?);

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

	let mut server = Server {
		poll,
		bound: RBTree::new(Bound::new()),
		connected: RBTree::new(Connected::new()),
		timeouts: LinkedList::new(Timeout::new()),
	};
	/// All of our timeouts are the same duration, so keeping the list sorted is just pushing to the back of the list
	fn timeout() -> Instant {
		Instant::now() + Duration::from_mins(1)
	}

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

		match server.poll.poll(&mut events, None) {
			// SIGHUP (or any signal) interrupts the wait; loop to reconfigure.
			Err(e) if e.kind() == ErrorKind::Interrupted => continue,
			v => v?,
		}

		for e in events.iter() {
			match server.poll.get(e.token()) {
				Err(TUN) => loop {
					let packet = match read_network(&network, &mut buffer, &args.router) {
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

					let c = server.bound.find_mut(&send_from);
					// Known connection: only endpoint plaintext reaches the TUN
					// (established client ciphertext is diverted to the socket).
					if let Some(client) = c.get() {
						if send_to != endpoint {
							// Not endpoint plaintext on a known CID: either a raced
							// ClientHello retransmit (the socket already owns it) or a
							// client that roamed to a new source address.  If the
							// record authenticates against the DTLS read keys, treat it
							// as mobility and re-point the socket at the new peer;
							// otherwise drop it (an off-path spoofer can't forge a tag).
							let creds = {
								// TODO: This is fucked.  Likely these Options/Cells should be consolidated into a single cell around a single enum.
								if client.established.get() {
									if client.read_keys.get().is_none() {
										client
											.read_keys
											.set(export_read_keys(&client.ssl.borrow()));
									}
									let highest = client.highest_read_seq.get();
									client.read_keys.get().map(|k| (k, highest))
								} else {
									None
								}
							};
							if let Some((rkeys, highest)) = creds
								&& let Some(seq) =
									check_record(&rkeys, highest, &mut buffer[..length])
							{
								if client.sock.connect(&SockAddr::from(send_to)).is_ok() {
									client.highest_read_seq.set(seq);
									// TODO: timeouts push_back
									client.timeout.set(timeout());
									tracing::debug!(?send_to, "client mobility: re-pointed socket");
								}
							}
							// Drop this record: the client's next packet lands on the
							// now-matching socket, and DTLS/SCTP retransmit recovers it.
							continue;
						}
						let data = &buffer[..length];
						let teardown = {
							if !client.established.get() {
								continue;
							}
							// TODO: timeouts push_back
							client.timeout.set(timeout());
							match ffi::write(&mut client.ssl.borrow_mut(), data) {
								SslIo::Ok(_) | SslIo::WantRead | SslIo::WantWrite => false,
								// Client path shrank: apply the new MTU to the
								// DTLS stream and tell the endpoint to send less.
								SslIo::Syscall(err)
									if err.raw_os_error() == Some(libc::EMSGSIZE) =>
								{
									if let Ok(pmtu) = SockRef::from(&client.sock).path_mtu() {
										let _ = client
											.ssl
											.borrow_mut()
											.set_mtu(pmtu.saturating_sub(IP_UDP));
										let data_mtu = ffi::data_mtu(&client.ssl.borrow()) as u32;
										let _ = write_network_icmp(
											&network,
											send_from.ip(),
											2, // ICMPv6 Packet Too Big
											0,
											data_mtu + IP_UDP,
											ip,
											udp.as_bytes(),
											data,
										);
									}
									false
								}
								// ECONNREFUSED or a fatal error: drop it.
								_ => true,
							}
						};
						if teardown {
							// TODO:
							// server.remove_conn(&mut streams, &mut by_addr, poll.registry(), key);
						}
					}
					// Unknown relayed address.
					else {
						let data = &buffer[..length];
						// Endpoint spoke to a relayed address with no connection.
						if send_to == endpoint {
							let _ = write_network_icmp(
								&network,
								&send_from.ip(),
								1,
								4, // Port Unreachable
								0,
								ip,
								udp.as_bytes(),
								data,
							);
							continue;
						}
						// Statelessly verify a DTLS cookie.
						match keys.inspect(send_to, send_from, data) {
							Verdict::Drop => {}
							Verdict::HelloVerify(hvr) => {
								let _ = write_network_udp(
									&network,
									&send_from,
									&send_to,
									hvr.as_bytes(),
								);
							}
							Verdict::Accept(verified) => {
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
					}
				},
				// Unused Static Tokens
				Err(_) => unreachable!(),
				// Event on the UDP
				Ok(Some((Flag::A, client))) => {
					// TODO: drive_connection
					// drive_connection(
					// 	key,
					// 	&mut streams,
					// 	&mut by_addr,
					// 	poll.registry(),
					// 	&network,
					// 	endpoint,
					// 	&mut buffer,
					// )
				}
				// Trailing events for a closed client:
				Ok(None) => {}
				// Unused Flags
				Ok(Some((_, _))) => unreachable!(),
			}
		}

		// Reap idle connections when the map has grown enough to bother.
		// TODO: timeout handling
		// let max_age = Duration::from_secs(5 * 60);
		// if streams.len() > next_cleanup {
		// 	let registry = poll.registry();
		// 	streams.retain(|_key, conn| {
		// 		let keep = conn.last_update.elapsed() < max_age;
		// 		if !keep {
		// 			let _ = registry.deregister(&mut SourceFd(&conn.sock.as_raw_fd()));
		// 			by_addr.remove(&conn.send_from);
		// 		}
		// 		keep
		// 	});
		// 	next_cleanup = streams.len() + 10;
		// }
	}
}
