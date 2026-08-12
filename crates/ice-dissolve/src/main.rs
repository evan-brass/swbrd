use std::net::{Ipv6Addr, SocketAddrV6};

use eyre::Result;

use common::{Packet, read_network, write_network_udp};
use stun::{Authkey, Class, Method, Stun, addr::Addr6, known};
use tun_rs::DeviceBuilder;
use zerocopy::TryFromBytes;

type Never = core::convert::Infallible;
fn main() -> Result<Never> {
	// Setup the TUN interface
	let network = {
		let mut builder = DeviceBuilder::new();
		#[cfg(target_os = "linux")]
		{
			builder = builder.offload(true); // I'm not trying to do segmentation offloading, I'm only trying to do checksum offloading, but...
		}
		builder = builder.name("ice-dissolve");

		builder.build_sync()?
	};

	let mut buffer = vec![0; 4096];

	// Write the ICE password into the buffer
	let authkey = Authkey::new(b"the/ice/password/constant");

	loop {
		let Packet::Udp { ip, udp } = read_network(
			&network,
			&mut buffer,
			&Ipv6Addr::UNSPECIFIED, /* ICE Dissolve can't emit ICMP errors because our firewall rules only redirect UDP packets to this interface. */
		)?
		else {
			continue;
		};

		let Ok(msg) = Stun::try_mut_from_bytes(&mut buffer) else {
			continue;
		};
		if (msg.class, msg.method) != (Class::Request, Method::Bind) {
			continue;
		}

		msg.class = Class::Response;
		msg.length.get_mut().set(0);
		let mapped = Addr6::new(ip.src.into(), udp.src_port.get()).xor(&msg.txid);
		msg.append_val(known::XOR_MAPPED_ADDRESS, &mapped);
		msg.append_val(
			known::MESSAGE_INTEGRITY,
			&msg.trim().expected_message_integrity(&authkey),
		);
		msg.append_val(known::FINGERPRINT, &msg.trim().expected_fingerprint());
		let end = size_of_val(msg.trim());
		let frame = &buffer[..end];

		let _ = write_network_udp(
			&network,
			&SocketAddrV6::new(Ipv6Addr::from_octets(ip.dst), udp.dst_port.get(), 0, 0),
			&SocketAddrV6::new(Ipv6Addr::from_octets(ip.src), udp.src_port.get(), 0, 0),
			frame,
		);
	}
}
