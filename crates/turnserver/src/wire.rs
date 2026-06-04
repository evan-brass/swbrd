use core::mem::{offset_of, size_of};
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, network_endian::U16, transmute_ref,
};

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

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct Udp {
	pub src_port: U16,
	pub dst_port: U16,
	pub length: U16,
	pub checksum: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
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

pub fn partial_checksum(ip: &Ip6, udp: &mut Udp) -> VirtioNet {
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
	udp.checksum = sum as u16;

	VirtioNet {
		flags: VirtioNet::FLAG_NEEDS_CSUM,
		gso_type: VirtioNet::GSO_NONE,
		hdr_len: (size_of::<Ip6>() + size_of::<Udp>()) as u16,
		gso_size: 0,
		csum_start: size_of::<Ip6>() as u16,
		csum_offset: offset_of!(Udp, checksum) as u16,
	}
}
#[allow(unused)]
pub fn full_checksum(ip: &Ip6, udp: &mut Udp, data: &[u8]) {
	partial_checksum(ip, udp);

	let (chunks, rest) = data.as_chunks();
	let mut last = [0; 4];
	last[4 - rest.len()..].copy_from_slice(rest);

	let [u1, u2]: &[u32; 2] = transmute_ref!(udp);

	let mut sum: u64 = *u1 as u64 + *u2 as u64;
	for c in chunks {
		sum += u32::from_ne_bytes(*c) as u64;
	}
	sum += u32::from_ne_bytes(last) as u64;

	while sum > 0xFFFF {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	let ip_sum = !(sum as u16);
	udp.checksum = if ip_sum == 0 { 0xffff } else { ip_sum };
}

#[test]
fn sample1() {
	let ip = Ip6 {
		flags: u32::to_be(0b0110__0000_0000__0011_0000_1010_0000_0000),
		length: U16::new(28),
		next_header: 17,
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
