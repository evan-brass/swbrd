use std::{
	collections::{BTreeMap, VecDeque, btree_map::Entry},
	io::{self, ErrorKind, IoSlice, IoSliceMut, Read, Write},
	net::SocketAddrV6,
	rc::Rc,
	str::FromStr,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
	time::{Duration, Instant},
};

use clap::Parser;
use common::{Ip6, Udp, VNET, VirtioNet, full_checksum, partial_checksum};
use eyre::Result;
use openssl::ssl::{ErrorCode, Ssl, SslAcceptor, SslContext, SslFiletype, SslMethod, SslStream};
use tracing_subscriber::EnvFilter;
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{FromZeros, IntoBytes, network_endian::U16};

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short)]
	if_name: Option<String>,

	#[arg(long, short, default_value = "[::1]:9899")]
	endpoint: String,
}

struct Bio {
	// This is what we key our BTree with
	send_from: ([u8; 16], U16),
	// This is where we last received ciphertext from and where we should forward our own handshake/ciphertext to
	send_to: ([u8; 16], U16),

	recv: VecDeque<u8>,
	send: Rc<SyncDevice>,

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
		let ip = Ip6 {
			flags: Ip6::FLAGS,
			length: U16::new((buf.len() + size_of::<Udp>()) as u16),
			next_header: 17,
			hop_limit: 63,
			src: self.send_from.0,
			dst: self.send_to.0,
		};
		let mut udp = Udp {
			src_port: self.send_from.1,
			dst_port: self.send_to.1,
			checksum: 0,
			length: ip.length,
		};
		let vnet = partial_checksum(&ip, &mut udp);
		if VNET == 0 {
			full_checksum(&ip, &mut udp, buf);
		}
		self.send.send_vectored(&[
			IoSlice::new(&vnet.as_bytes()[..VNET]),
			IoSlice::new(ip.as_bytes()),
			IoSlice::new(udp.as_bytes()),
			IoSlice::new(buf),
		])?;

		// TODO: It would probably be better to update this somewhere else
		self.last_update = Instant::now();

		Ok(buf.len())
	}
}

fn load_config() -> Result<(SslContext, SslContext)> {
	// Construct an acceptor and apply it
	let january = {
		let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
		acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
		acceptor.set_certificate_file("January.der", SslFiletype::ASN1)?;
		acceptor.check_private_key()?;
		acceptor.build().into_context()
	};
	let july = {
		let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
		acceptor.set_private_key_file("key.pem", SslFiletype::PEM)?;
		acceptor.set_certificate_file("July.der", SslFiletype::ASN1)?;
		acceptor.check_private_key()?;
		acceptor.build().into_context()
	};

	println!("Configuration loaded");

	Ok((january, july))
}

type Never = core::convert::Infallible;
fn main() -> Result<Never> {
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
	let need_reconfig = Arc::new(AtomicBool::new(true));
	signal_hook::flag::register(signal_hook::consts::SIGHUP, need_reconfig.clone())?;

	let mut streams = BTreeMap::new();
	let mut next_cleanup = 10;

	let mut buffer = vec![0; 65536];
	let mut vnet = VirtioNet::new_zeroed();
	let mut ip = Ip6::new_zeroed();
	let mut udp = Udp::new_zeroed();
	loop {
		if need_reconfig.swap(false, Ordering::Relaxed) {
			(even, odd) = load_config()?;
		}
		let len = match network.recv_vectored(&mut [
			IoSliceMut::new(&mut vnet.as_mut_bytes()[..VNET]),
			IoSliceMut::new(&mut ip.as_mut_bytes()),
			IoSliceMut::new(&mut udp.as_mut_bytes()),
			IoSliceMut::new(&mut buffer),
		]) {
			Ok(n) => n,
			Err(e) if e.kind() == ErrorKind::Interrupted => continue,
			Err(e) => return Err(e.into()),
		};
		if len < VNET + size_of::<Ip6>() + size_of::<Udp>() {
			continue;
		}
		if u32::from_be(ip.flags) >> 28 != 6 {
			continue;
		}
		// TODO: Handle ICMP?
		if ip.next_header != 17 {
			continue;
		}
		if ip.length.get() < 8 {
			continue;
		}
		if ip.length != udp.length {
			continue;
		}
		let length = udp.length.get() as usize - size_of::<Udp>();
		let data = &buffer[..length];

		// Lookup the ssl via the destination ip + port
		let send_from = (ip.dst, udp.dst_port);
		let send_to = (ip.src, udp.src_port);
		let mut entry = match streams.entry(send_from) {
			// Drop packets coming from endpoint where we don't have a stream
			// TODO: This should be an ICMP host / port unreachable
			Entry::Vacant(_) if send_from == endpoint => continue,

			// Create a new SSL to hold this packet.  I really wish I could have DTLS cookies, but fucking Firefox is a piece of shit.
			Entry::Vacant(e) => {
				let mut ssl = Ssl::new(if udp.dst_port.get() & 0b1 == 0 {
					&even
				} else {
					&odd
				})?;
				ssl.set_accept_state();
				let stream = SslStream::new(
					ssl,
					Bio {
						send_from,
						send_to,
						recv: VecDeque::from(Vec::from(data)),
						send: network.clone(),
						last_update: Instant::now(),
					},
				)?;

				e.insert_entry(stream)
			}

			// Existing connection
			Entry::Occupied(mut e) => {
				let vd = &mut e.get_mut().get_mut().recv;
				if vd.len() == 0 {
					let _ = vd.write(data);
				}
				e
			}
		};
		let stream = entry.get_mut();

		let res = if !stream.ssl().is_init_finished() {
			// Progress the handshake if that's what we're doing
			stream.do_handshake()
		} else if send_to == endpoint {
			// Write plaintext from endpoint or fetch/peek data off the stream
			stream.ssl_write(&data).map(|_| {})
		} else {
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

			// Construct our plaintext packet
			let ip = Ip6 {
				flags: Ip6::FLAGS,
				src: send_from.0,
				dst: endpoint.0,
				length: U16::new((len + size_of::<Udp>()) as u16),
				next_header: 17,
				hop_limit: ip.hop_limit.saturating_sub(1),
			};
			let mut udp = Udp {
				src_port: send_from.1,
				dst_port: endpoint.1,
				length: ip.length,
				checksum: 0,
			};
			let vnet = partial_checksum(&ip, &mut udp);
			if VNET == 0 {
				full_checksum(&ip, &mut udp, data);
			}

			let _ = network.send_vectored(&[
				IoSlice::new(&vnet.as_bytes()[..VNET]),
				IoSlice::new(ip.as_bytes()),
				IoSlice::new(udp.as_bytes()),
				IoSlice::new(data),
			]);
		}

		// Handle cleaning up old connections
		let max_age = Duration::from_mins(5);
		if streams.len() > next_cleanup {
			streams.retain(|_, stream| stream.get_ref().last_update.elapsed() < max_age);
			next_cleanup = streams.len() + 10;
		}
	}
}
