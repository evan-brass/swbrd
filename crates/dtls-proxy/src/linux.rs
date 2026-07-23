use std::{
	collections::{BTreeMap, VecDeque, btree_map::Entry},
	io::{self, ErrorKind, Read, Write},
	net::{Ipv6Addr, SocketAddrV6},
	rc::Rc,
	str::FromStr,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::{Duration, Instant},
};

use clap::Parser;
use common::{Packet, Udp, read_network, write_network_icmp, write_network_udp};
use eyre::Result;
use openssl::ssl::{ErrorCode, SslAcceptor, SslContext, SslFiletype, SslMethod, SslStream};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{IntoBytes, network_endian::U16};

use crate::cookie::{self, Capture, Verdict};

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

struct Bio {
	// This is what we key our BTree with
	send_from: ([u8; 16], U16),
	// This is where we last received ciphertext from and where we should forward our own handshake/ciphertext to
	pub send_to: ([u8; 16], U16),

	recv: VecDeque<u8>,
	send: Rc<SyncDevice>,

	// We store a small amount of plaintext data to be passed along in ICMP errors when we forward them to endpoint
	plain_data: Option<[u8; 12]>,

	// While cookie::promote walks a fresh Ssl into its post-HelloVerifyRequest
	// state, the HelloVerifyRequest it writes is captured here instead of sent
	capture: Option<Vec<u8>>,

	last_update: Instant,
}
impl Read for Bio {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		match self.recv.read(buf) {
			Ok(0) => Err(io::Error::new(ErrorKind::WouldBlock, "")),
			r => r,
		}
	}
}
impl Write for Bio {
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		if let Some(captured) = &mut self.capture {
			captured.extend_from_slice(buf);
			return Ok(buf.len());
		}
		let _ = write_network_udp(&self.send, self.send_from, self.send_to, buf);

		// TODO: It would probably be better to update this somewhere else
		self.last_update = Instant::now();

		Ok(buf.len())
	}
}
impl Capture for Bio {
	fn feed(&mut self, datagram: &[u8]) {
		self.recv.extend(datagram);
	}
	fn capture(&mut self) {
		self.capture = Some(Vec::new());
	}
	fn take_captured(&mut self) -> Vec<u8> {
		self.capture.take().unwrap_or_default()
	}
}

fn load_config() -> Result<(SslContext, SslContext)> {
	// Construct an acceptor and apply it
	let january = {
		let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
		acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
		acceptor.set_certificate_file("January.der", SslFiletype::ASN1)?;
		acceptor.check_private_key()?;
		cookie::configure(&mut acceptor);
		acceptor.build().into_context()
	};
	let july = {
		let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
		acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
		acceptor.set_certificate_file("July.der", SslFiletype::ASN1)?;
		acceptor.check_private_key()?;
		cookie::configure(&mut acceptor);
		acceptor.build().into_context()
	};

	println!("Configuration loaded");

	Ok((january, july))
}

type Never = core::convert::Infallible;
pub fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Parse the endpoint address
	// This IP is the destination and source of all plaintext
	let endpoint = SocketAddrV6::from_str(&args.endpoint)?;
	let endpoint = (endpoint.ip().octets(), U16::new(endpoint.port()));

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

		Rc::new(builder.build_sync()?)
	};

	let (mut even, mut odd) = load_config()?;
	// The HMAC key behind our stateless DTLS cookies.  Fresh per process: a
	// restart just costs in-flight handshakes one extra HelloVerifyRequest round.
	let keys = cookie::Keys::generate()?;
	let need_reconfig = Arc::new(AtomicBool::new(true));
	signal_hook::flag::register(signal_hook::consts::SIGHUP, need_reconfig.clone())?;

	let mut streams: BTreeMap<([u8; 16], zerocopy::U16<zerocopy::BigEndian>), SslStream<Bio>> =
		BTreeMap::new();
	let mut next_cleanup = 10;

	let mut buffer = vec![0; 4096];
	loop {
		if need_reconfig.swap(false, Ordering::Relaxed) {
			(even, odd) = load_config()?;
		}

		match read_network(&network, &mut buffer, args.router.octets()) {
			Err(e) if e.kind() == ErrorKind::Interrupted => continue,
			Err(e) => return Err(e.into()),
			Ok(Packet::Icmp {
				ip,
				icmp,
				mut inner_ip,
				mut inner_udp,
			}) => {
				// All offending packets must have been sent by our proxy (because the outer dst ip must be in our subnet)
				// However, we have to modify the src/dst to pretend like the offending packet was sent by the client/endpoint
				let cid = (inner_ip.src, inner_udp.src_port);

				let Some(ssl) = streams.get(&cid) else {
					continue;
				};

				// If the "offending" packet was ciphertext (not from endpoint) then we must have sent it on-behalf of endpoint (endpoint is the src)
				let mut plain: &[u8] = &[];
				let new_src = if (inner_ip.dst, inner_udp.dst_port) != endpoint {
					if let Some(ref plain_data) = ssl.get_ref().plain_data {
						plain = plain_data;
					}
					endpoint
				}
				// If the "offending" packet was plaintext (from endpoint) then we must have sent it on-behalf of a client (client is the src)
				else {
					ssl.get_ref().send_to
				};
				inner_ip.src = new_src.0;
				inner_ip.dst = cid.0;
				inner_udp.src_port = new_src.1;
				inner_udp.dst_port = cid.1;

				// TODO: Apply the discovered MTU to the SSL stream (currently not possible because we can't get an &mut SSL which is required to call SSL.set_mtu())
				// Reduce the MTU in the ICMP message to
				// TODO: Actually get this overhead properly off of the ssl stream? In order to use DTLS_get_data_mtu, we must set SSL_set_mtu or DTLS_set_link_mtu.
				const OVERHEAD: u32 = 13 + 8 + 16;
				let _ = write_network_icmp(
					&network,
					ip.src, // TODO: Should I also change the src "router" ip address?
					icmp.typ,
					icmp.code,
					icmp.mtu.get().saturating_sub(OVERHEAD),
					inner_ip,
					inner_udp.as_bytes(),
					plain,
				);
			}
			Ok(Packet::Udp { ip, udp }) => {
				let send_from = (ip.dst, udp.dst_port);
				let send_to = (ip.src, udp.src_port);

				let length = udp.length.get() as usize - size_of::<Udp>();
				let data = &buffer[..length];
				// Lookup the ssl via the destination ip + port
				let mut entry = match streams.entry(send_from) {
					// Return Port Unreachable errors to endpoint, for vacant ssl
					Entry::Vacant(_) if send_to == endpoint => {
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

					// Unknown src/dst pair: statelessly verify a DTLS cookie.
					// Ssl state is only ever created (in cookie::promote) for a
					// ClientHello fragment bearing a valid cookie.
					Entry::Vacant(e) => {
						match keys.inspect(send_to, send_from, data) {
							// Not the start of a ClientHello: ignore
							Verdict::Drop => {}
							// No/stale cookie: answer without allocating anything
							Verdict::HelloVerify(hvr) => {
								let _ =
									write_network_udp(&network, send_from, send_to, hvr.as_bytes());
							}
							Verdict::Accept(verified) => {
								let bio = Bio {
									send_from,
									send_to,
									recv: VecDeque::new(),
									send: network.clone(),
									last_update: Instant::now(),
									plain_data: None,
									capture: None,
								};
								let ctx = if send_from.1.get() & 0b1 == 0 {
									&even
								} else {
									&odd
								};
								match cookie::promote(ctx, bio, &verified) {
									// Remaining fragments of the hello (if any)
									// arrive through the Occupied path below
									Ok(stream) => {
										e.insert(stream);
									}
									Err(err) => tracing::debug!("promotion failed: {err}"),
								}
							}
						}
						continue;
					}

					// Existing connection
					Entry::Occupied(e) => e,
				};
				let stream = entry.get_mut();

				let res = if !stream.ssl().is_init_finished() {
					let _ = stream.get_mut().recv.write(data);
					// Progress the handshake if that's what we're doing
					stream.do_handshake()
				} else if send_to == endpoint {
					// Store the first 12 bytes of the plaintext, to replace the ciphertext in forwarded ICMP errors
					stream.get_mut().plain_data = data.first_chunk().cloned();

					// Write plaintext from endpoint or fetch/peek data off the stream
					stream.ssl_write(&data).map(|_| {})
				} else {
					let _ = stream.get_mut().recv.write(data);
					// Use peek to prime the thing in the thing
					let mut temp = [0; 4];
					stream.ssl_peek(&mut temp).map(|_| {})
				};

				// Handle errors:
				if let Err(e) = res
					&& !matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE)
				{
					entry.remove();
					continue;
				}

				// Pull data out, and emit plaintext UDP
				while stream.ssl().pending() > 0 {
					let Ok(len) = stream.ssl_read(&mut buffer) else {
						break;
					};
					let data = &buffer[..len];

					// After a successful read, update the send_to because we must have had valid application data:
					stream.get_mut().send_to = send_to;

					let _ = write_network_udp(&network, send_from, endpoint, data);
				}

				if !stream.get_ref().recv.is_empty() {
					panic!("Why isn't your buffer empty?")
				}
			}
		}

		// Handle cleaning up old connections
		let max_age = Duration::from_mins(5);
		if streams.len() > next_cleanup {
			streams.retain(|_, stream| stream.get_ref().last_update.elapsed() < max_age);
			next_cleanup = streams.len() + 10;
		}
	}
}
