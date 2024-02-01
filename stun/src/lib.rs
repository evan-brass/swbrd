use bytes::Buf;

const MAGIC: u32 = 0x2112A442;

pub mod attrs;
pub mod attr;

#[derive(Debug)]
pub struct Stun<T, A> {
	pub typ: u16,
	// length: u16, // The only point of this is to be able to implement decode_length
	pub txid: T,
	pub attrs: A
}
#[derive(Debug)]
pub enum StunDecodeError {
	TooShort(usize),
	TypeOutOfRange,
	UnalignedLength,
	BadMagic,
	BadAttrLength
}
impl<'i, A: attrs::KnownAttrs<'i>> Stun<&'i [u8; 12], A> {
	fn decode_inner(header: &mut [u8; 20], body: &'i [u8], attrs: &mut A) -> Result<u16, StunDecodeError> {
		// Decode the header
		let (typ, length, magic) = {
			let mut header = header.as_slice();
			(header.get_u16(), header.get_u16(), header.get_u32())
		};
		if typ >= 0x4000 { return Err(StunDecodeError::TypeOutOfRange) }
		if length % 4 != 0 { return Err(StunDecodeError::UnalignedLength) }
		if magic != MAGIC { return Err(StunDecodeError::BadMagic) }
		if body.len() < length as usize { return Err(StunDecodeError::TooShort(20 + length as usize)) }

		// Decode the attributes
		let mut i = 0;
		while i < length as usize {
			let (attr_prefix, mut t) = body.split_at(i);
			let attr_typ = t.get_u16();
			let attr_len = t.get_u16();
			if t.remaining() < attr_len as usize { return Err(StunDecodeError::BadAttrLength) }
			let value = &t[..attr_len as usize];

			i += 4 + attr_len as usize;
			while i % 4 != 0 { i += 1 }

			// Modify the length in header
			header[2..4].copy_from_slice(&(i as u16).to_be_bytes());

			attrs.decode_attr(attr_typ, header, attr_prefix, value);
		}

		Ok(typ)
	}
	pub fn decode_mut(buffer: &'i mut [u8], mut attrs: A) -> Result<Self, StunDecodeError> {
		if buffer.len() < 20 { return Err(StunDecodeError::TooShort(20)) }

		let (header, body) = buffer.split_at_mut(20);
		let header: &mut [u8; 20] = header.try_into().unwrap();

		let typ = Self::decode_inner(header, body, &mut attrs)?;

		let txid = header[8..].try_into().unwrap();

		Ok(Self{ typ, txid, attrs })
	}
	pub fn decode(buffer: &'i [u8], mut attrs: A) -> Result<Self, StunDecodeError> {
		if buffer.len() < 20 { return Err(StunDecodeError::TooShort(20)) }

		let (header, body) = buffer.split_at(20);
		let txid = header[8..].try_into().unwrap();
		let mut header: [u8; 20] = header.try_into().unwrap();
		let typ = Self::decode_inner(&mut header, body, &mut attrs)?;

		Ok(Self{ typ, txid, attrs })
	}
}
