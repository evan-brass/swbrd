#![no_std]

use core::{cell::Cell, marker::PhantomData, mem::offset_of};

use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, TryFromBytes, Unaligned,
	network_endian::U16,
};

pub use crate::typ::*;

mod typ;

#[derive(Debug)]
pub struct Iterating;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, IntoBytes, SplitAt)]
pub struct Stun<M = ()> {
	iter: PhantomData<M>,
	opad: [u8; 64],
	ipad: [u8; 64],
	pub class: Class,
	pub method: Method,
	pub(crate) length: Cell<U16>,
	pub txid: Txid,
	pub(crate) body: [[u8; 4]],
}
impl Stun<()> {
	pub const HEADROOM: usize = offset_of!(Self, class);
	pub const MAX_LENGTH: u16 = 0xff00;
}

#[repr(C, packed)]
#[derive(KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct Attr {
	pub typ: u16,
	length: U16,
	pub value: [u8],
}
impl Attr {
	pub const MAX_LENGTH: u16 = Stun::MAX_LENGTH - 4;
}
