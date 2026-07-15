#![no_std]

use core::{cell::Cell, mem::offset_of};

use zerocopy::{
	AlignedTryCastError, FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, SplitAt,
	TryFromBytes, Unaligned, network_endian::U16,
};

pub use crate::parse::*;
pub use crate::typ::*;

pub mod addr;
mod encode;
mod integrity;
pub mod known;
mod parse;
mod typ;

pub struct Authkey {
	pub opad: [u8; 64],
	pub ipad: [u8; 64],
}
impl Authkey {
	pub fn new(key: &[u8]) -> Self {
		assert!(key.len() <= 64);
		let mut ipad = [0x36; 64];
		let mut opad = [0x5c; 64];
		for (i, b) in key.iter().enumerate() {
			ipad[i] ^= b;
			opad[i] ^= b;
		}
		Self { ipad, opad }
	}
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, KnownLayout, Unaligned, TryFromBytes, IntoBytes, SplitAt)]
pub struct Stun {
	pub class: Class,
	pub method: Method,
	#[doc(hidden)]
	pub length: Cell<U16>,
	pub txid: Txid,
	pub(crate) body: [[u8; 4]],
}
impl Stun {
	pub const MAX_LENGTH: u16 = 0xff00;
	pub fn trim(&self) -> &Self {
		let length = self.length.get().get();
		let offset = if length.is_multiple_of(4) {
			length as usize >> 2
		} else {
			0
		};
		let (ret, _) = self
			.split_at(usize::min(offset, self.body.len()))
			.unwrap()
			.via_into_bytes();
		ret
	}
	pub fn new(
		class: Class,
		method: Method,
		buffer: &mut [u8],
	) -> Result<&mut Self, SizeError<&mut [u8], Self>> {
		// Write valid bytes into the buffer before trying to read it as a &mut Stun
		if buffer.len() >= 20 {
			// This is less then ideal.  1.8 billion slice indexes instead of 3 raw pointers... sux
			class
				.write_to(&mut buffer[offset_of!(Self, class)..][..size_of_val(&class)])
				.unwrap();
			method
				.write_to(&mut buffer[offset_of!(Self, method)..][..size_of_val(&method)])
				.unwrap();
			U16::new(0)
				.write_to(&mut buffer[offset_of!(Self, length)..][..size_of::<U16>()])
				.unwrap();
			let txid = Txid::new();
			txid.write_to(&mut buffer[offset_of!(Self, txid)..][..size_of_val(&txid)])
				.unwrap();
		}
		match Self::try_mut_from_bytes(buffer).map_err(AlignedTryCastError::from) {
			Ok(v) => Ok(v),
			Err(AlignedTryCastError::Alignment(a)) => match a {},
			Err(AlignedTryCastError::Size(s)) => Err(s),
			Err(AlignedTryCastError::Validity(_)) => unreachable!(),
		}
	}
}

#[repr(C, packed)]
#[derive(KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct Attr {
	pub typ: u16,
	#[doc(hidden)]
	pub length: U16,
	pub value: [u8],
}
impl Attr {
	pub const MAX_LENGTH: u16 = Stun::MAX_LENGTH - 4;
	pub fn is_optional(&self) -> bool {
		self.typ & u16::to_be(0x8000) != 0
	}
}
