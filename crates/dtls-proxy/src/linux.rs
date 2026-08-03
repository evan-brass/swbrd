use std::{
	collections::HashMap,
	io::ErrorKind,
	net::{Ipv6Addr, SocketAddrV6},
	os::fd::AsRawFd,
	str::FromStr,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::{Duration, Instant},
};

use clap::Parser;
use common::{
	Packet, Udp, read_network,
	socket::{UdpOpt, connected_udp, reconnect, set_v6_pmtudisc, v6_path_mtu},
	write_network_icmp, write_network_udp,
};
use eyre::Result;
use mio::{Events, Interest, Poll, Registry, Token, unix::SourceFd};
use openssl::ssl::{
	Ssl, SslAcceptor, SslContext, SslContextRef, SslFiletype, SslMethod, SslVersion,
};
use slab::Slab;
use socket2::Socket;
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{IntoBytes, network_endian::U16};

use crate::{
	cookie::{self, Verdict, Verified},
	ffi::{self, SslIo},
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
struct Connection {
	ssl: Ssl,
	/// Connected transparent socket (owns the fd the dgram BIO borrows).
	sock: Socket,
	/// The relayed address the client sent to = our local addr on this socket;
	/// the `by_addr` key and the source of forwarded plaintext / ICMP.
	send_from: ([u8; 16], U16),
	established: bool,
	last_update: Instant,
	/// Read-direction (client write) keys, derived lazily once established and
	/// used to authenticate roamed records for client mobility.
	read_keys: Option<ReadKeys>,
	/// Highest record number authenticated for mobility so far; a roamed record
	/// must strictly exceed it to re-point the socket (anti-replay).
	highest_read_seq: u64,
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

/// Drop a connection: deregister its socket and forget its address.
fn remove_conn(
	streams: &mut Slab<Connection>,
	by_addr: &mut HashMap<([u8; 16], U16), usize>,
	registry: &Registry,
	key: usize,
) {
	let Some(conn) = streams.try_remove(key) else {
		return;
	};
	let _ = registry.deregister(&mut SourceFd(&conn.sock.as_raw_fd()));
	by_addr.remove(&conn.send_from);
}

/// A cookie-verified ClientHello: fork a connected transparent socket, run the
/// cookie catch-up on an in-memory BIO pair, then cut over to the fd-backed
/// dgram BIO and register the socket.
fn create_connection(
	ctx: &SslContextRef,
	verified: &Verified,
	send_from: ([u8; 16], U16),
	send_to: ([u8; 16], U16),
	streams: &mut Slab<Connection>,
	by_addr: &mut HashMap<([u8; 16], U16), usize>,
	registry: &Registry,
) -> Result<()> {
	let local = SocketAddrV6::new(Ipv6Addr::from(send_from.0), send_from.1.get(), 0, 0);
	let remote = SocketAddrV6::new(Ipv6Addr::from(send_to.0), send_to.1.get(), 0, 0);
	let sock = connected_udp(local, remote, UdpOpt::Transparent)?;
	set_v6_pmtudisc(&sock)?;

	let hs = cookie::promote(ctx, verified)?;

	// Unfragmented hello: the ServerHello flight is already produced; send it on
	// the socket before cutover.  (Fragmented: nothing yet — the rest arrives on
	// the socket.)
	for datagram in hs.drain_output() {
		let _ = sock.send(&datagram);
	}

	let fd = sock.as_raw_fd();
	let established = hs.is_finished();
	let ssl = hs.into_established(fd)?;

	let entry = streams.vacant_entry();
	let key = entry.key();
	registry.register(&mut SourceFd(&fd), Token(key), Interest::READABLE)?;
	entry.insert(Connection {
		ssl,
		sock,
		send_from,
		established,
		last_update: Instant::now(),
		read_keys: None,
		highest_read_seq: 0,
	});
	by_addr.insert(send_from, key);
	Ok(())
}

/// Drain a connection's socket: drive the handshake, then read decrypted
/// application data and forward it to the endpoint over the TUN.
fn drive_connection(
	key: usize,
	streams: &mut Slab<Connection>,
	by_addr: &mut HashMap<([u8; 16], U16), usize>,
	registry: &Registry,
	network: &SyncDevice,
	endpoint: ([u8; 16], U16),
	buffer: &mut [u8],
) {
	loop {
		let Some(conn) = streams.get_mut(key) else {
			return;
		};
		let outcome = if !conn.established {
			let r = ffi::do_handshake(&mut conn.ssl);
			if matches!(r, SslIo::Ok(_)) {
				conn.established = conn.ssl.is_init_finished();
				conn.last_update = Instant::now();
			}
			r
		} else {
			let r = ffi::read(&mut conn.ssl, buffer);
			if let SslIo::Ok(len) = r
				&& len > 0
			{
				conn.last_update = Instant::now();
				let from = conn.send_from;
				let _ = write_network_udp(network, from, endpoint, &buffer[..len]);
			}
			r
		};

		match outcome {
			// Handshake step or read made progress: keep draining.
			SslIo::Ok(_) => continue,
			// Nothing more to read right now.
			SslIo::WantRead | SslIo::WantWrite => return,
			// close_notify, a connected-socket error (e.g. ECONNREFUSED surfaced
			// by the dgram BIO's recv), or a fatal alert: tear down.
			SslIo::ZeroReturn | SslIo::Syscall(_) | SslIo::Fatal => {
				remove_conn(streams, by_addr, registry, key);
				return;
			}
		}
	}
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
	let endpoint = (endpoint.ip().octets(), U16::new(endpoint.port()));

	let mut poll = Poll::new()?;

	// The TUN interface carries first-contact ClientHellos (cookie exchange) and
	// endpoint plaintext.  Established client ciphertext is diverted to each
	// connection's connected transparent socket by nftables `socket transparent`.
	let network = {
		let mut builder = DeviceBuilder::new();
		builder = builder.offload(true); // checksum offload
		if let Some(if_name) = args.if_name {
			builder = builder.name(if_name);
		}
		builder.build_sync()?
	};
	network.set_nonblocking(true)?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;

	let (mut even, mut odd) = load_config()?;
	// The HMAC key behind our stateless DTLS cookies.  Fresh per process: a
	// restart just costs in-flight handshakes one extra HelloVerifyRequest round.
	let keys = cookie::Keys::generate()?;
	let need_reconfig = Arc::new(AtomicBool::new(false));
	signal_hook::flag::register(signal_hook::consts::SIGHUP, need_reconfig.clone())?;

	let mut streams: Slab<Connection> = Slab::new();
	// Relayed address -> slab key: TUN-side lookup for endpoint plaintext, and
	// dedup for ClientHello retransmits that raced the socket fork.
	let mut by_addr: HashMap<([u8; 16], U16), usize> = HashMap::new();
	let mut next_cleanup = 10;

	let mut events = Events::with_capacity(128);
	let mut buffer = vec![0; 4096];

	loop {
		if need_reconfig.swap(false, Ordering::Relaxed) {
			(even, odd) = load_config()?;
		}

		match poll.poll(&mut events, None) {
			Ok(()) => {}
			// SIGHUP (or any signal) interrupts the wait; loop to reconfigure.
			Err(e) if e.kind() == ErrorKind::Interrupted => continue,
			Err(e) => return Err(e.into()),
		}

		for e in events.iter() {
			match e.token() {
				TUN => loop {
					let packet = match read_network(&network, &mut buffer, args.router.octets()) {
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

					let send_from = (ip.dst, udp.dst_port);
					let send_to = (ip.src, udp.src_port);
					let length = udp.length.get() as usize - size_of::<Udp>();

					match by_addr.get(&send_from).copied() {
						// Known connection: only endpoint plaintext reaches the TUN
						// (established client ciphertext is diverted to the socket).
						Some(key) => {
							if send_to != endpoint {
								// Not endpoint plaintext on a known CID: either a raced
								// ClientHello retransmit (the socket already owns it) or a
								// client that roamed to a new source address.  If the
								// record authenticates against the DTLS read keys, treat it
								// as mobility and re-point the socket at the new peer;
								// otherwise drop it (an off-path spoofer can't forge a tag).
								let creds = {
									let conn = &mut streams[key];
									if conn.established {
										if conn.read_keys.is_none() {
											conn.read_keys = export_read_keys(&conn.ssl);
										}
										let highest = conn.highest_read_seq;
										conn.read_keys.map(|k| (k, highest))
									} else {
										None
									}
								};
								if let Some((rkeys, highest)) = creds
									&& let Some(seq) =
										check_record(&rkeys, highest, &mut buffer[..length])
								{
									let new_peer = SocketAddrV6::new(
										Ipv6Addr::from(send_to.0),
										send_to.1.get(),
										0,
										0,
									);
									let conn = &mut streams[key];
									if reconnect(&conn.sock, new_peer).is_ok() {
										conn.highest_read_seq = seq;
										conn.last_update = Instant::now();
										tracing::debug!(
											?new_peer,
											"client mobility: re-pointed socket"
										);
									}
								}
								// Drop this record: the client's next packet lands on the
								// now-matching socket, and DTLS/SCTP retransmit recovers it.
								continue;
							}
							let data = &buffer[..length];
							let teardown = {
								let conn = &mut streams[key];
								if !conn.established {
									continue;
								}
								conn.last_update = Instant::now();
								match ffi::write(&mut conn.ssl, data) {
									SslIo::Ok(_) | SslIo::WantRead | SslIo::WantWrite => false,
									// Client path shrank: apply the new MTU to the
									// DTLS stream and tell the endpoint to send less.
									SslIo::Syscall(err)
										if err.raw_os_error() == Some(libc::EMSGSIZE) =>
									{
										if let Ok(pmtu) = v6_path_mtu(&conn.sock) {
											let _ = conn.ssl.set_mtu(pmtu.saturating_sub(IP_UDP));
											let data_mtu = ffi::data_mtu(&conn.ssl) as u32;
											let _ = write_network_icmp(
												&network,
												send_from.0,
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
								remove_conn(&mut streams, &mut by_addr, poll.registry(), key);
							}
						}

						// Unknown relayed address.
						None => {
							let data = &buffer[..length];
							// Endpoint spoke to a relayed address with no connection.
							if send_to == endpoint {
								let _ = write_network_icmp(
									&network,
									send_from.0,
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
										send_from,
										send_to,
										hvr.as_bytes(),
									);
								}
								Verdict::Accept(verified) => {
									let ctx = if send_from.1.get() & 0b1 == 0 {
										&even
									} else {
										&odd
									};
									if let Err(err) = create_connection(
										ctx,
										&verified,
										send_from,
										send_to,
										&mut streams,
										&mut by_addr,
										poll.registry(),
									) {
										tracing::debug!("connection setup failed: {err}");
									}
								}
							}
						}
					}
				},

				// A connection's socket: ciphertext arrived (or an error).
				Token(key) => drive_connection(
					key,
					&mut streams,
					&mut by_addr,
					poll.registry(),
					&network,
					endpoint,
					&mut buffer,
				),
			}
		}

		// Reap idle connections when the map has grown enough to bother.
		let max_age = Duration::from_secs(5 * 60);
		if streams.len() > next_cleanup {
			let registry = poll.registry();
			streams.retain(|_key, conn| {
				let keep = conn.last_update.elapsed() < max_age;
				if !keep {
					let _ = registry.deregister(&mut SourceFd(&conn.sock.as_raw_fd()));
					by_addr.remove(&conn.send_from);
				}
				keep
			});
			next_cleanup = streams.len() + 10;
		}
	}
}

const TUN: Token = Token(usize::MAX);
