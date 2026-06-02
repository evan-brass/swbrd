use zerocopy::{
	FromBytes, Immutable, KnownLayout, SplitAt, TryFromBytes, Unaligned, network_endian::U16,
};

#[cfg(feature = "alloc")]
extern crate alloc;

use crate::{
	Attr, Iterating, Stun,
	known::{FINGERPRINT, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256},
};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed<V> {
	#[default]
	NotPresent,
	Valid(V),
	Invalid,
}

pub trait Parse<'i>: Sized + Iterator<Item = (&'i Stun<Iterating>, &'i Attr)> {
	fn parse<'s, const T: u16, V: Value<'i, T>>(
		self,
		storage: &'s mut Parsed<V>,
	) -> Parser<'s, T, V, Self> {
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
impl<'i, T: Sized + Iterator<Item = (&'i Stun<Iterating>, &'i Attr)>> Parse<'i> for T {}

pub trait Value<'i, const T: u16>: Sized {
	type Wire: ?Sized + KnownLayout + Immutable + Unaligned + TryFromBytes;
	fn decode(prefix: &Stun<Iterating>, value: &'i Self::Wire) -> Option<Self>;

	// Most attributes must appear before these integrity attributes
	// TODO: I don't like this method of ordering attributes, but I don't have a better pattern yet.
	fn must_precede(typ: u16) -> bool {
		matches!(
			typ,
			FINGERPRINT | MESSAGE_INTEGRITY | MESSAGE_INTEGRITY_SHA256
		)
	}
}

pub struct Parser<'s, const T: u16, V, I> {
	storage: Option<&'s mut Parsed<V>>,
	inner: I,
}
impl<'i, const T: u16, V: Value<'i, T> + 'i, I: Iterator<Item = (&'i Stun<Iterating>, &'i Attr)>>
	Iterator for Parser<'_, T, V, I>
{
	type Item = (&'i Stun<Iterating>, &'i Attr);
	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let (prefix, attr) = self.inner.next()?;

			// Our attribute
			if attr.typ == T {
				let Some(storage) = self.storage.take() else {
					// Duplicate attribute or attribute followed an integrity attribute: terminate parsing
					break None;
				};
				*storage = match V::Wire::try_ref_from_bytes(&attr.value) {
					Ok(value) if let Some(v) = V::decode(prefix, value) => Parsed::Valid(v),
					_ => Parsed::Invalid,
				};
				continue;
			}
			// Any attribute that we must precede in the list
			else if V::must_precede(attr.typ) {
				self.storage = None;
			}

			break Some((prefix, attr));
		}
	}
}

impl<'i> IntoIterator for &'i mut Stun<()> {
	type IntoIter = &'i Stun<Iterating>;
	type Item = (&'i Stun<Iterating>, &'i Attr);
	fn into_iter(self) -> Self::IntoIter {
		let offset = usize::min(self.length.take().get() as usize >> 2, self.body.len());
		// Adding headroom means we cannot continue parsing from rest until we're ready to overwrite the current frame.
		let (trimmed, _rest) = self.split_at(offset).unwrap().via_into_bytes();

		// Transmute the typestate of trimmed from &mut Stun<()> to &Stun<Iterating>
		unsafe { core::mem::transmute(trimmed) }
	}
}

impl<'i> Iterator for &'i Stun<Iterating> {
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
