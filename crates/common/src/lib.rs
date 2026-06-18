use core::mem::{offset_of, size_of};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16, transmute_ref};

pub mod proto {
	pub const UDP: u8 = 17;
	pub const ICMP6: u8 = 58;
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
	typ: u8,
	code: u8,
	checksum: u16,
	mtu: u32, // For my purposes this will be an MTU or unused
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

pub fn partial_checksum<N: Ipsum>(ip: &Ip6, next: &mut N) -> VirtioNet {
	let [_1, _2, s1, s2, s3, s4, d1, d2, d3, d4]: &[u32; 10] = transmute_ref!(ip);
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
		hdr_len: (size_of::<Ip6>() + size_of::<Udp>()) as u16,
		gso_size: 0,
		csum_start: size_of::<Ip6>() as u16,
		csum_offset: N::checksum_offset(),
	}
}

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

#[test]
fn sample1() {
	let ip = Ip6 {
		flags: u32::to_be(0b0110__0000_0000__0011_0000_1010_0000_0000),
		length: U16::new(28),
		next_header: proto::UDP,
		hop_limit: 64,
		src: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
		dst: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
	};
	let mut udp = Udp {
		src_port: U16::new(57184),
		dst_port: U16::new(3478),
		length: ip.length,
		checksum: 0x9999,
	};
	partial_checksum(&ip, &mut udp);

	assert_eq!(udp.checksum, u16::from_be(0x002f));
}
