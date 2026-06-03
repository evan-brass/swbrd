use eyre::Result;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use stun::{
	Class, Method, Parse, Parsed, Stun,
	addr::{Addr4, Addr6, Xor},
	known,
};
use zerocopy::{
	TryFromBytes,
	network_endian::{U16, U32},
};

type Never = core::convert::Infallible;

/// md5('user:none:password')
const TURNKEY: &[u8] = &[
	0x9a, 0xc1, 0x33, 0x6a, 0xc2, 0xef, 0x12, 0xb8, 0xa1, 0x06, 0x00, 0x7a, 0xab, 0x74, 0x25, 0xf3,
];

fn main() -> Result<Never> {
	let socket = UdpSocket::bind("[::]:3478")?;

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
				let (Parsed::Valid(_peer), Parsed::Valid(_data)) = (peer, data) else {
					continue;
				};
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
