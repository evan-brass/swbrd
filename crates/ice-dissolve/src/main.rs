use eyre::{Result, eyre};

use common::{Ip6, Udp, VNET, VirtioNet, full_checksum, partial_checksum, proto};
use stun::{Class, Method, Stun, addr::Addr6, known};
use tun_rs::DeviceBuilder;
use zerocopy::{FromZeros, IntoBytes, TryFromBytes};

use std::io::{IoSlice, IoSliceMut};

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

	let mut buffer = vec![0; 65536];

	// Write the ICE password into the buffer
	let t = Stun::new(Class::Request, Method::Bind, &mut buffer).map_err(|e| eyre!("{e:?}"))?;
	t.set_authkey(b"the/ice/password/constant");

	let mut vnet = VirtioNet::new_zeroed();
	let mut ip = Ip6::new_zeroed();
	let mut udp = Udp::new_zeroed();
	loop {
		let len = network.recv_vectored(&mut [
			IoSliceMut::new(&mut vnet.as_mut_bytes()[..VNET]),
			IoSliceMut::new(&mut ip.as_mut_bytes()),
			IoSliceMut::new(&mut udp.as_mut_bytes()),
			IoSliceMut::new(&mut buffer[Stun::HEADROOM..]),
		])?;
		if len < VNET + size_of::<Ip6>() + size_of::<Udp>() {
			continue;
		}
		if u32::from_be(ip.flags) >> 28 != 6 {
			continue;
		}
		// TODO: Handle ICMP?
		if ip.next_header != proto::UDP {
			continue;
		}
		if ip.length.get() < 8 {
			continue;
		}
		if ip.length != udp.length {
			continue;
		}

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
			&msg.trim().expected_message_integrity(),
		);
		msg.append_val(known::FINGERPRINT, &msg.trim().expected_fingerprint());
		let end = size_of_val(msg.trim());
		let frame = &buffer[Stun::HEADROOM..end];

		// Swap src and dst
		let t = ip.src;
		ip.src = ip.dst;
		ip.dst = t;
		let t = udp.src_port;
		udp.src_port = udp.dst_port;
		udp.dst_port = t;
		udp.length.set(size_of::<Udp>() as u16 + frame.len() as u16);
		ip.length = udp.length;

		vnet = partial_checksum(&ip, &mut udp);
		if VNET == 0 {
			full_checksum(&mut udp, &[frame]);
		}
		let vnet = &vnet.as_bytes()[..VNET];
		network.send_vectored(&[
			IoSlice::new(vnet),
			IoSlice::new(ip.as_bytes()),
			IoSlice::new(udp.as_bytes()),
			IoSlice::new(frame),
		])?;
	}
}
