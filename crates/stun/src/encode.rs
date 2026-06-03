use core::ops::AddAssign;

use crate::{Attr, Stun};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt};

impl Stun {
	pub fn append(&mut self) -> (&mut Self, &mut Attr) {
		let offset = self.length.get_mut().get();
		if !offset.is_multiple_of(4) {
			panic!("Stun length was unaligned")
		}

		let (prefix, rest) = self
			.split_at_mut(offset as usize >> 2)
			.expect("Stun length exceeded the buffer")
			.via_into_bytes();

		let max1 = Attr::MAX_LENGTH
			.checked_sub(offset)
			.expect("No more attributes can fit within our max Stun length");
		let max2 = size_of_val(rest)
			.checked_sub(4)
			.expect("No more attributes can fit in this buffer");

		let (attr, _) = Attr::mut_from_prefix_with_elems(
			rest.as_flattened_mut(),
			usize::min(max1 as usize, max2),
		)
		.unwrap();

		// Clear the length field since it's used by Attr's bytes::BufMut implementation.
		attr.length.set(0);

		(prefix, attr)
	}
	pub fn append_val<V: ?Sized + KnownLayout + Immutable + IntoBytes>(
		&mut self,
		typ: u16,
		val: &V,
	) {
		self.append_once(|_, dst| {
			val.write_to_prefix(&mut dst.value)
				.expect("Value couldn't be written to attribute");
			dst.typ = typ;
			dst.length.set(size_of_val(val) as u16);
		});
	}
	pub fn append_once<F: FnOnce(&Stun, &mut Attr)>(&mut self, f: F) {
		let (prefix, dst) = self.append();
		f(prefix, dst);
		prefix.length.get_mut().add_assign(4 + dst.padded());
	}
}

impl Attr {
	#[inline]
	pub fn padding(&self) -> u16 {
		let length = self.length.get();
		length.wrapping_neg() & 0b11
	}
	#[inline]
	pub fn padded(&self) -> u16 {
		(self.length.get() + 3) & !3
	}
}

#[cfg(feature = "bytes")]
mod bufmut {
	use super::*;
	use bytes::BufMut;

	impl Attr {
		pub(crate) fn available(&mut self) -> &mut [u8] {
			let remain = self.remaining_mut();
			if let Some((_, rest)) = self.value.split_at_mut_checked(self.length.get() as usize) {
				&mut rest[..remain]
			} else {
				&mut []
			}
		}
	}
	unsafe impl BufMut for Attr {
		fn remaining_mut(&self) -> usize {
			let length = self.length.get();
			let length_left = Attr::MAX_LENGTH.saturating_sub(length) as usize;
			let body_left = size_of_val(&self.value).saturating_sub(length as usize);
			usize::min(length_left, body_left)
		}
		unsafe fn advance_mut(&mut self, cnt: usize) {
			self.length += cnt as u16;
		}
		fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
			bytes::buf::UninitSlice::new(self.available())
		}
	}
	impl core::fmt::Write for Attr {
		fn write_str(&mut self, s: &str) -> core::fmt::Result {
			if s.len() > self.remaining_mut() {
				return Err(core::fmt::Error);
			}
			self.put_slice(s.as_bytes());
			Ok(())
		}
	}
}
