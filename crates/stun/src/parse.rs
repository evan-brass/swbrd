use zerocopy::{
	AlignedTryCastError, FromBytes, Immutable, KnownLayout, SplitAt, TryFromBytes, Unaligned,
	network_endian::U16,
};

#[cfg(feature = "alloc")]
extern crate alloc;

use crate::{Attr, Stun};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed<V> {
	#[default]
	NotPresent,
	Valid(V),
	Invalid,
}

pub trait Parse<'i>: Sized + Iterator<Item = (&'i Stun, &'i Attr)> {
	fn parse<'s, const T: u16, V: ?Sized + KnownLayout + Immutable + Unaligned + TryFromBytes>(
		self,
		storage: &'s mut Parsed<&'i V>,
	) -> Parser<'i, 's, T, V, Self> {
		Parser {
			storage: Some(storage),
			inner: self,
		}
	}

	#[cfg(feature = "alloc")]
	fn collect_unknown(self) -> alloc::vec::Vec<u16> {
		self.filter_map(|(_, a)| {
			if a.is_optional() {
				return None;
			}
			Some(a.typ)
		})
		.collect()
	}
}
impl<'i, T: Sized + Iterator<Item = (&'i Stun, &'i Attr)>> Parse<'i> for T {}

pub struct Parser<'i, 's, const T: u16, V: ?Sized, I> {
	storage: Option<&'s mut Parsed<&'i V>>,
	inner: I,
}
impl<
	'i,
	const T: u16,
	V: ?Sized + KnownLayout + Immutable + Unaligned + TryFromBytes,
	I: Iterator<Item = (&'i Stun, &'i Attr)>,
> Iterator for Parser<'i, '_, T, V, I>
{
	type Item = (&'i Stun, &'i Attr);
	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let (prefix, attr) = self.inner.next()?;

			// Our attribute
			if attr.typ == T {
				let Some(storage) = self.storage.take() else {
					// Duplicate attribute or attribute followed an integrity attribute: terminate parsing
					break None;
				};
				*storage =
					match V::try_ref_from_bytes(&attr.value).map_err(AlignedTryCastError::from) {
						Ok(v) => Parsed::Valid(v),
						_ => Parsed::Invalid,
					};
				continue;
			}

			break Some((prefix, attr));
		}
	}
}

impl<'i> Iterator for &'i Stun {
	type Item = (Self, &'i Attr);
	fn next(&mut self) -> Option<(Self, &'i Attr)> {
		let offset = self.length.get().get();
		let max_attr_length = Attr::MAX_LENGTH.checked_sub(offset)?;

		let (prefix, rest) = self.split_at(offset as usize >> 2)?.via_into_bytes();
		let attr = Attr::ref_from_bytes(rest.as_flattened()).ok()?;
		let attr_len = attr.length.get();
		if attr_len > max_attr_length {
			return None;
		}

		let (attr, _) =
			Attr::ref_from_prefix_with_elems(rest.as_flattened(), attr_len as usize).unwrap();

		// Increment past this attribute
		let new_len = (offset + 4 + attr_len + 3) & !3;
		self.length.set(U16::new(new_len));

		Some((prefix, attr))
	}
}
