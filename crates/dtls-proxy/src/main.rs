use std::{
	collections::{BTreeMap, VecDeque, btree_map::Entry},
	fs,
	io::{self, ErrorKind, IoSlice, IoSliceMut, Read, Write},
	net::Ipv6Addr,
	rc::Rc,
};

use common::{Ip6, Udp, VNET, VirtioNet, full_checksum, partial_checksum};
use eyre::{Result, eyre};
use openssl::{
	hash::MessageDigest,
	pkey::PKey,
	ssl::{ErrorCode, Ssl, SslAcceptor, SslMethod, SslStream},
	x509::X509,
};
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{FromZeros, IntoBytes, network_endian::U16};

struct Bio {
	// This is what we key our BTree with
	send_from: ([u8; 16], U16),
	// This is where we last received ciphertext from and where we should forward our own handshake/ciphertext to
	send_to: ([u8; 16], U16),

	recv: VecDeque<u8>,
	send: Rc<SyncDevice>,
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
		Ok(buf.len())
	}
}

type Never = core::convert::Infallible;
fn main() -> Result<Never> {
	// Setup the TUN interface
	let network = {
		#[allow(unused_mut)]
		let mut builder = DeviceBuilder::new();
		#[cfg(target_os = "linux")]
		{
			builder = builder.offload(true); // I'm not trying to do segmentation offloading, I'm only trying to do checksum offloading, but...
		}

		Rc::new(builder.build_sync()?)
	};

	// Load current certificate
	let key_pem = fs::read("key.pem")?;
	let cert_der = fs::read("January.der")?;

	// Construct an acceptor and apply it
	let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::dtls())?;
	let pkey = PKey::private_key_from_pem(&key_pem)?;
	let cert = X509::from_der(&cert_der)?;
	acceptor.set_private_key(&pkey)?;
	acceptor.set_certificate(&cert)?;
	acceptor.check_private_key()?;

	// Get the fingerprint of the cert
	let fingerprint = cert.digest(MessageDigest::sha256())?;
	let low16 = u16::from_be_bytes(*fingerprint.last_chunk().ok_or(eyre!("Wat??"))?);

	// Apply addresses on the TUN interface matching our certificate subnet(s)
	network.add_address_v6(Ipv6Addr::new(0xfd01, 0, 0, 0, low16, 0, 0, 0), 80)?;
	network.add_address_v6(
		Ipv6Addr::new(0x2a01, 0x4ff, 0x1f0, 0x7e46, low16, 0, 0, 0),
		80,
	)?;

	// This IP is the destination and source of all plaintext
	let endpoint = (
		Ipv6Addr::new(0x2a01, 0x4ff, 0x1f0, 0x7e46, 0, 0, 0, 1).octets(),
		U16::new(9899),
	);

	let context = acceptor.build().into_context();
	let mut streams = BTreeMap::new();

	let mut buffer = vec![0; 65536];
	let mut vnet = VirtioNet::new_zeroed();
	let mut ip = Ip6::new_zeroed();
	let mut udp = Udp::new_zeroed();
	loop {
		let len = network.recv_vectored(&mut [
			IoSliceMut::new(&mut vnet.as_mut_bytes()[..VNET]),
			IoSliceMut::new(&mut ip.as_mut_bytes()),
			IoSliceMut::new(&mut udp.as_mut_bytes()),
			IoSliceMut::new(&mut buffer),
		])?;
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
				let mut ssl = Ssl::new(&context)?;
				ssl.set_accept_state();
				let stream = SslStream::new(
					ssl,
					Bio {
						send_from,
						send_to,
						recv: VecDeque::from(Vec::from(data)),
						send: network.clone(),
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
	}
}
