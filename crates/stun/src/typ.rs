use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, try_transmute};

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum Class {
	Request = 0x00,
	Response = 0x01,
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
#[non_exhaustive]
pub enum Method {
	Bind = 0x01,
	Allocate = 0x03,
	Refresh = 0x04,
	Send = 0x16,
	Recv = 0x17,
	AddPermission = 0x08,
	UseChannel = 0x09,

	// Don't use these:
	// As a client, treat any response.method != request.method as an error
	// As a server, use .to_err to get these variants
	#[doc(hidden)]
	Fuck = 0x11, // Bind Error or Bind Indication
	#[doc(hidden)]
	#[deprecated]
	This = 0x13, // Allocate Error
	#[doc(hidden)]
	#[deprecated]
	Shit = 0x14, // Refresh Error
	#[doc(hidden)]
	#[deprecated]
	So = 0x18, // AddPermission Error
	#[doc(hidden)]
	#[deprecated]
	Ass = 0x19, // UseChannel Error
}
impl Method {
	pub fn to_err(self) -> Self {
		try_transmute!(self as u8 ^ 0x10).unwrap()
	}
	pub fn is_err(&self) -> bool {
		!matches!(self, Self::Send | Self::Recv) && *self as u8 & 0x10 != 0
	}
}

#[repr(u32)]
#[derive(
	Default, Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, TryFromBytes, IntoBytes,
)]
pub enum Cookie {
	#[default]
	Magic = u32::to_be(0x2112_A442),
}

#[repr(C, packed)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub struct Txid {
	cookie: Cookie,
	pub id: [u8; 12],
}
impl Txid {
	pub fn new() -> Self {
		#[cfg(feature = "rand")]
		let id = {
			use core::array::from_fn;
			use rand::{RngExt, distr::Alphanumeric, rng};
			from_fn(|_| rng().sample(Alphanumeric))
		};
		#[cfg(not(feature = "rand"))]
		let id = [0x99; 12];

		Self {
			cookie: Cookie::Magic,
			id,
		}
	}
}
