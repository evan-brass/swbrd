use eyre::Result;
use std::{
	io::IoSlice,
	net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
	thread::{Builder as ThreadBuilder, scope},
};
use stun::{
	Class, Method, Parse, Parsed, Stun,
	addr::{Addr4, Addr6, Xor},
	known,
};
use tun_rs::{DeviceBuilder, SyncDevice};
use zerocopy::{
	FromBytes, IntoBytes, TryFromBytes,
	network_endian::{U16, U32},
};

#[cfg(target_os = "linux")]
use crate::wire::VirtioNet;
use crate::wire::{Ip6, Udp, full_checksum, partial_checksum};

type Never = core::convert::Infallible;
mod wire;

/// md5('user:none:password')
const TURNKEY: &[u8] = &[
	0x9a, 0xc1, 0x33, 0x6a, 0xc2, 0xef, 0x12, 0xb8, 0xa1, 0x06, 0x00, 0x7a, 0xab, 0x74, 0x25, 0xf3,
];

fn handle_turn(socket: &UdpSocket, network: &SyncDevice) -> Result<Never> {
	let mut buffer = vec![0; 65536];
	loop {
		let Ok((20.., SocketAddr::V6(sender))) = socket.recv_from(&mut buffer[Stun::HEADROOM..])
		else {
			continue;
		};
		let Ok(msg) = Stun::try_mut_from_bytes(&mut buffer) else {
			continue;
		};
		if msg.class != Class::Request || msg.method == Method::Recv || msg.method.is_err() {
			continue;
		}
		msg.set_authkey(TURNKEY);

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

		msg.length.set(U16::new(0));
		for (prefix, attr) in attrs {
			match attr.typ {
				known::MESSAGE_INTEGRITY => {
					integrity = attr.value == prefix.expected_message_integrity();
					break;
				}
				_ if attr.is_optional() => {}
				t => todo!("Unknown Attributes error response {t:?}"),
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
			Method::Bind => {
				msg.class = Class::Response;
				msg.length.get_mut().set(0);
				add_mapped(msg);
			}
			Method::Send => {
				let (Parsed::Valid(peer), Parsed::Valid(data)) = (peer, data) else {
					continue;
				};
				let peer = peer.xor(&msg.txid);
				let ip = Ip6 {
					flags: Ip6::FLAGS,
					length: U16::new((size_of::<Udp>() + data.len()) as u16),
					next_header: 17,
					hop_limit: 64,
					src: sender.ip().octets(),
					dst: peer.ip().octets(),
				};
				let mut udp = Udp {
					src_port: U16::new(sender.port()),
					dst_port: U16::new(peer.port()),
					length: ip.length,
					checksum: 0,
				};

				if cfg!(target_os = "linux") {
					let vnet = partial_checksum(&ip, &mut udp);
					network.send_vectored(&[
						IoSlice::new(vnet.as_bytes()),
						IoSlice::new(ip.as_bytes()),
						IoSlice::new(udp.as_bytes()),
						IoSlice::new(data),
					])
				} else {
					full_checksum(&ip, &mut udp, data);
					network.send_vectored(&[
						IoSlice::new(ip.as_bytes()),
						IoSlice::new(udp.as_bytes()),
						IoSlice::new(data),
					])
				}?;

				continue;
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
					&Addr6::new(*sender.ip(), sender.port()).xor(&msg.txid),
				);
				msg.append_val(known::LIFETIME, &lifetime);
			}
			// Close notification, just drop
			Method::Refresh if lifetime.get() == 0 => continue,
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
			_ => continue,
		}

		if integrity {
			msg.append_val(
				known::MESSAGE_INTEGRITY,
				&msg.trim().expected_message_integrity(),
			);
		}

		let end = size_of_val(msg.trim());
		socket.send_to(&buffer[Stun::HEADROOM..end], sender)?;
	}
}

fn handle_tun(socket: &UdpSocket, network: &SyncDevice) -> Result<Never> {
	let mut buffer = vec![0; 65536];

	#[cfg(target_os = "linux")]
	const VNET: usize = size_of::<VirtioNet>();
	#[cfg(not(target_os = "linux"))]
	const VNET: usize = 0;

	const HEADROOM: usize = (Stun::HEADROOM + 20 + 24 + 4) - (VNET + 40 + 8);

	loop {
		let 40.. = network.recv(&mut buffer[HEADROOM..])? else {
			continue;
		};

		let Ok((ip, rest)) = Ip6::read_from_prefix(&buffer[HEADROOM + VNET..]) else {
			continue;
		};
		println!("{ip:?}");
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
		let Ok((udp, _rest)) = Udp::read_from_prefix(rest) else {
			continue;
		};

		println!("{udp:?}");
		if ip.length != udp.length {
			continue;
		}

		let data_length = udp.length.get() - 8;
		let receiver = SocketAddrV6::new(Ipv6Addr::from_octets(ip.dst), udp.dst_port.get(), 0, 0);
		let sender = Addr6::new(Ipv6Addr::from_octets(ip.src), udp.src_port.get());
		let msg = Stun::new(Class::Request, Method::Recv, &mut buffer).unwrap();
		msg.append_val(known::XOR_PEER_ADDRESS, &sender.xor(&msg.txid));
		msg.append_once(|_, a| {
			a.typ = known::DATA;
			a.length.set(data_length); // If my headroom calculations are correct, the UDP data is already in the correct position.
		});

		let end = size_of_val(msg.trim());
		socket.send_to(&buffer[Stun::HEADROOM..end], receiver)?;
	}
}

fn main() -> Result<()> {
	let socket = UdpSocket::bind("[::]:3478")?;
	let network = {
		let builder = DeviceBuilder::new();
		#[cfg(target_os = "linux")]
		let builder = builder.offload(true); // I'm not trying to do segmentation offloading, I'm only trying to do checksum offloading, but...
		builder.build_sync()?
	};

	let turn_handler = ThreadBuilder::new().name("TURN handler".into());
	let tun_handler = ThreadBuilder::new().name("TUN handler".into());

	scope(|s| -> Result<()> {
		turn_handler.spawn_scoped(s, || handle_turn(&socket, &network))?;
		tun_handler.spawn_scoped(s, || handle_tun(&socket, &network))?;

		Ok(())
	})?;

	Ok(())
}
