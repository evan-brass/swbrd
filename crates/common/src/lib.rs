use core::mem::{offset_of, size_of};
use std::{
	io::{IoSlice, IoSliceMut},
	net::Ipv6Addr,
	str::from_utf8,
};
use tun_rs::SyncDevice;
use zerocopy::{
	FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned,
	network_endian::{U16, U32},
	transmute, transmute_ref,
};

pub mod dtls;
pub mod poller;

pub mod proto {
	pub const UDP: u8 = 17;
	pub const ICMP6: u8 = 58;
	pub const IP6_FRAGMENT: u8 = 44;
}

// Checksum offloading support
#[cfg(target_os = "linux")]
pub const VNET: usize = size_of::<VirtioNet>();
#[cfg(not(target_os = "linux"))]
pub const VNET: usize = 0;

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct Ip6 {
	pub flags: u32,
	pub length: U16,
	pub next_header: u8,
	pub hop_limit: u8,
	pub src: [u8; 16],
	pub dst: [u8; 16],
}
impl Ip6 {
	#[allow(clippy::unusual_byte_groupings)]
	pub const FLAGS: u32 = u32::to_be(0b0110__0000_0000__0000_0000_0000_0000_0000);
}

pub trait Ipsum: KnownLayout + Immutable + IntoBytes {
	fn checksum(&mut self) -> &mut u16;
	fn checksum_offset() -> u16;
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct Udp {
	pub src_port: U16,
	pub dst_port: U16,
	pub length: U16,
	pub checksum: u16,
}
impl Ipsum for Udp {
	fn checksum(&mut self) -> &mut u16 {
		&mut self.checksum
	}
	fn checksum_offset() -> u16 {
		offset_of!(Self, checksum) as u16
	}
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct Icmp6 {
	pub typ: u8,
	pub code: u8,
	pub checksum: u16,
	pub mtu: U32, // For my purposes this will be an MTU or unused
}
impl Ipsum for Icmp6 {
	fn checksum(&mut self) -> &mut u16 {
		&mut self.checksum
	}
	fn checksum_offset() -> u16 {
		offset_of!(Self, checksum) as u16
	}
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct VirtioNet {
	pub flags: u8,
	pub gso_type: u8,
	pub hdr_len: u16,
	pub gso_size: u16,
	pub csum_start: u16,
	pub csum_offset: u16,
}
#[allow(unused)]
impl VirtioNet {
	pub const FLAG_NEEDS_CSUM: u8 = 1;
	pub const FLAG_DATA_VALID: u8 = 2;
	pub const FLAG_RSC_INFO: u8 = 4;
	pub const FLAG_UDP_TUNNEL_CSUM: u8 = 8;

	pub const GSO_NONE: u8 = 0;
}

/// Sum the Pseudo header using u32 chunks and u64 accumulator
pub fn partial_checksum<N: Ipsum>(ip: &Ip6, next: &mut N) -> VirtioNet {
	let [_, _, s1, s2, s3, s4, d1, d2, d3, d4]: &[u32; 10] = transmute_ref!(ip);
	let [l1, l2] = ip.length.to_bytes();

	let mut sum = 0u64;
	sum += *s1 as u64;
	sum += *s2 as u64;
	sum += *s3 as u64;
	sum += *s4 as u64;
	sum += *d1 as u64;
	sum += *d2 as u64;
	sum += *d3 as u64;
	sum += *d4 as u64;
	sum += u32::from_ne_bytes([0, 0, l1, l2]) as u64;
	sum += u32::from_ne_bytes([0, 0, 0, ip.next_header]) as u64;

	while sum > 0xFFFF {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	*next.checksum() = sum as u16;

	VirtioNet {
		flags: VirtioNet::FLAG_NEEDS_CSUM,
		gso_type: VirtioNet::GSO_NONE,
		hdr_len: (size_of::<Ip6>() + size_of::<N>()) as u16,
		gso_size: 0,
		csum_start: size_of::<Ip6>() as u16,
		csum_offset: N::checksum_offset(),
	}
}

/// Complete a partial checksum into a full checksum using u32 chunks and u64 accumulator
pub fn full_checksum<N: Ipsum>(next: &mut N, pieces: &[&[u8]]) {
	let [u1, u2]: &[u32; 2] = transmute_ref!(next);
	let mut sum: u64 = *u1 as u64 + *u2 as u64;

	for piece in pieces {
		// TODO: Add an assertion to ensure 2-byte alignment of the pieces.  For non-final pieces, rest must be empty or [u8; 2].  The final piece may be empty, [u8; 1], [u8; 2], or [u8; 3].
		let (chunks, rest) = piece.as_chunks();

		let mut last = [0; 4];
		last[4 - rest.len()..].copy_from_slice(rest);

		for c in chunks {
			sum += u32::from_ne_bytes(*c) as u64;
		}
		sum += u32::from_ne_bytes(last) as u64;
	}

	while sum > 0xFFFF {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	let ip_sum = !(sum as u16);
	*next.checksum() = if ip_sum == 0 { 0xffff } else { ip_sum };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct DcepOpenHeader {
	pub msg_typ: u8,
	pub channel_typ: u8,
	pub priority: U16,
	pub reliability_parameter: U32,
	pub label_len: U16,
	pub protocol_len: U16,
}
impl DcepOpenHeader {
	pub fn parse(buffer: &[u8]) -> Option<(Self, &str, &str)> {
		let (header, rest) = Self::read_from_prefix(buffer).ok()?;
		let (label, rest) = rest.split_at_checked(header.label_len.get() as usize)?;
		let (protocol, _) = rest.split_at_checked(header.protocol_len.get() as usize)?;
		let label = from_utf8(label).ok()?;
		let protocol = from_utf8(protocol).ok()?;
		Some((header, label, protocol))
	}
}

pub enum Packet {
	Icmp {
		ip: Ip6,
		icmp: Icmp6,
		inner_ip: Ip6,
		inner_udp: Udp,
	},
	Udp {
		ip: Ip6,
		udp: Udp,
	},
}

pub fn write_network_udp(
	network: &SyncDevice,
	from: ([u8; 16], U16),
	to: ([u8; 16], U16),
	buffer: &[u8],
) -> Result<(), std::io::Error> {
	let ip = Ip6 {
		flags: Ip6::FLAGS,
		length: U16::new((size_of::<Udp>() + buffer.len()) as u16),
		next_header: proto::UDP,
		hop_limit: 64,
		src: from.0,
		dst: to.0,
	};
	let mut udp = Udp {
		src_port: from.1,
		dst_port: to.1,
		length: ip.length,
		checksum: 0,
	};

	let vnet = partial_checksum(&ip, &mut udp);
	if VNET == 0 {
		full_checksum(&mut udp, &[buffer]);
	}
	network.send_vectored(&[
		IoSlice::new(&vnet.as_bytes()[..VNET]),
		IoSlice::new(ip.as_bytes()),
		IoSlice::new(udp.as_bytes()),
		IoSlice::new(buffer),
	])?;
	Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_network_icmp(
	network: &SyncDevice,
	from: [u8; 16],
	typ: u8,
	code: u8,
	arg: u32,

	inner_ip: Ip6,
	inner_transport: &[u8],
	buffer: &[u8],
) -> Result<(), std::io::Error> {
	//
	let quoted = &buffer[..usize::min(
		buffer.len(),
		/* Minimum IP6 MTU */
		1280
		/* IP Header */
		- size_of::<Ip6>()
		/* ICMP Header */
		- size_of::<Icmp6>()
		/* Quoted IP Header */
		- size_of::<Ip6>()
		/* Quoted Transport Header */
		- size_of_val(inner_transport),
	)];

	let ip = Ip6 {
		flags: Ip6::FLAGS,
		next_header: proto::ICMP6,
		hop_limit: 64,
		src: from,
		dst: inner_ip.src,
		length: U16::new(
			(size_of::<Icmp6>() + size_of::<Ip6>() + size_of::<Udp>() + size_of_val(quoted)) as u16,
		),
	};
	let mut icmp = Icmp6 {
		typ,
		code,
		mtu: U32::new(arg),
		checksum: 0,
	};

	let mut vnet = partial_checksum(&ip, &mut icmp);
	vnet.flags = 0;
	full_checksum(
		&mut icmp,
		&[inner_ip.as_bytes(), inner_transport.as_bytes(), quoted],
	);
	network.send_vectored(&[
		IoSlice::new(&vnet.as_bytes()[..VNET]),
		IoSlice::new(ip.as_bytes()),
		IoSlice::new(icmp.as_bytes()),
		IoSlice::new(inner_ip.as_bytes()),
		IoSlice::new(inner_transport.as_bytes()),
		IoSlice::new(quoted),
	])?;
	Ok(())
}

pub fn read_network(
	network: &SyncDevice,
	buffer: &mut [u8],
	// ICMP Errors will be issued from this IP address
	router: [u8; 16],
) -> Result<Packet, std::io::Error> {
	loop {
		let mut vnet = VirtioNet::new_zeroed();
		let mut ip = Ip6::new_zeroed();
		let mut transport = [0u8; 8];
		match network.recv_vectored(&mut [
			IoSliceMut::new(&mut vnet.as_mut_bytes()[..VNET]),
			IoSliceMut::new(ip.as_mut_bytes()),
			IoSliceMut::new(&mut transport),
			IoSliceMut::new(buffer),
		]) {
			Ok(len) if len < (VNET + size_of::<Ip6>() + size_of_val(&transport)) => continue,
			Err(e) => return Err(e),

			// Check the IP version
			_ if u32::from_be(ip.flags) >> 28 != 6 => continue,
			// Check that the IP length matches length received
			Ok(len) if ip.length.get() as usize != (len - VNET - size_of::<Ip6>()) => continue,

			// Drop multicast traffic
			_ if Ipv6Addr::from_octets(ip.dst).is_multicast() => continue,
			// Drop IP fragments
			_ if ip.next_header == proto::IP6_FRAGMENT => continue,

			// Handle the packet
			_ => {}
		};

		// TCP, non-error ICMP, etc.
		if (ip.next_header == proto::ICMP6 && transport[0] >= 128)
			|| !matches!(ip.next_header, proto::UDP | proto::ICMP6)
		{
			// Emit a host unreachable
			let _ = write_network_icmp(network, router, 1, 3, 0, ip, &transport, buffer);
		}
		// ICMP
		if ip.next_header == proto::ICMP6 {
			let icmp: Icmp6 = transmute!(transport);

			// Look inside for the offending UDP packet.
			if ip.length.get() < 8 + 40 + 8 {
				continue;
			}
			let (inner_ip, rest) = Ip6::read_from_prefix(buffer).unwrap();
			if inner_ip.next_header != proto::UDP {
				continue;
			}
			if ip.dst != inner_ip.src {
				eprintln!("What the fuck?");
				continue;
			}
			let (inner_udp, _rest) = Udp::read_from_prefix(rest).unwrap();
			return Ok(Packet::Icmp {
				ip,
				icmp,
				inner_ip,
				inner_udp,
			});
		}
		// UDP
		else {
			let udp: Udp = transmute!(transport);
			if ip.length != udp.length {
				continue;
			}
			return Ok(Packet::Udp { ip, udp });
		}
	}
}
