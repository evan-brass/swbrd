use crate::Txid;

use core::marker::PhantomData;
use core::net::{Ipv4Addr, Ipv6Addr};

use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum Family {
	IPv4 = 0x01,
	IPv6 = 0x02,
}

#[derive(Debug, Clone, Copy)]
pub struct Xor;
#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub struct Addr<const N: usize, M> {
	mode: PhantomData<M>,
	pad1: u8,
	pub family: Family,
	port: [u8; 2],
	octets: [u8; N],
}
pub type Addr4<M> = Addr<4, M>;
pub type Addr6<M> = Addr<16, M>;

fn xor_bytes<const N: usize>(src: [u8; N], txid: &Txid) -> [u8; N] {
	let xor = txid.as_bytes();
	core::array::from_fn(|i| xor[i] ^ src[i])
}
impl<const N: usize> Addr<N, Xor> {
	pub fn xor(self, txid: &Txid) -> Addr<N, ()> {
		Addr {
			mode: PhantomData,
			pad1: self.pad1,
			family: self.family,
			port: xor_bytes(self.port, txid),
			octets: xor_bytes(self.octets, txid),
		}
	}
}
impl<const N: usize> Addr<N, ()> {
	pub fn xor(self, txid: &Txid) -> Addr<N, Xor> {
		Addr {
			mode: PhantomData,
			pad1: self.pad1,
			family: self.family,
			port: xor_bytes(self.port, txid),
			octets: xor_bytes(self.octets, txid),
		}
	}
	pub fn port(&self) -> u16 {
		u16::from_be_bytes(self.port)
	}
}
impl Addr4<()> {
	pub fn new(ip: Ipv4Addr, port: u16) -> Self {
		Self {
			mode: PhantomData,
			pad1: 0,
			family: Family::IPv4,
			port: port.to_be_bytes(),
			octets: ip.octets(),
		}
	}
	pub fn ip(&self) -> Ipv4Addr {
		self.octets.into()
	}
}
impl Addr6<()> {
	pub fn new(ip: Ipv6Addr, port: u16) -> Self {
		Self {
			mode: PhantomData,
			pad1: 0,
			family: Family::IPv6,
			port: port.to_be_bytes(),
			octets: ip.octets(),
		}
	}
	pub fn ip(&self) -> Ipv6Addr {
		self.octets.into()
	}
}
