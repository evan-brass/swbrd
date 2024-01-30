use bytes::Buf;

const MAGIC: u32 = 0x2112A442;

pub trait StunAttr<'i>: StunAttrEncode {
	const ATTR_TYPE: u16;
	fn decode(header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) -> Option<Self> where Self: Sized;
}
pub trait StunAttrEncode {
	fn header(&self) -> Option<(u16, u16)>;
	fn encode(&self, header:  &[u8; 20], attr_prefix: &[u8], value: &mut [u8]);
}
pub trait KnownStunAttrs<'i> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]);
	fn parse<A>(self, attr: &'i mut Option<A>) -> Parse<'i, A, Self> where Self: Sized {
		Parse { attr, next: self }
	}
}

#[derive(Debug, Default)]
pub struct UnknownAttrs(Vec<u16>);
impl KnownStunAttrs<'_> for UnknownAttrs {
	fn decode_attr(&mut self, attr_typ: u16, _: &[u8; 20], _: &[u8], _: &[u8]) {
		// Append any comprehension required attributes to our list of unknown attributes
		if attr_typ < 0x8000 { self.0.push(attr_typ) }
	}
}
pub struct Parse<'i, A, N> {
	attr: &'i mut Option<A>,
	next: N
}
impl<'i, A: StunAttr<'i>, N: KnownStunAttrs<'i>> KnownStunAttrs<'i> for Parse<'_, A, N> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) {
		if attr_typ == A::ATTR_TYPE {
			if self.attr.is_none() {
				*self.attr = A::decode(header, attr_prefix, value)
			}
		} else {
			self.next.decode_attr(attr_typ, header, attr_prefix, value);
		}
	}
}


#[derive(Debug)]
pub struct Stun<T, A> {
	pub typ: u16,
	pub txid: T,
	attrs: A
}
#[derive(Debug)]
pub enum StunDecodeErr {
	TooShort(usize),
	TypeOutOfRange,
	UnalignedLength,
	BadMagic,
	BadAttrLength
}

impl<'i> Stun<&'i [u8; 12], u16> {
	pub fn decode<A: KnownStunAttrs<'i>>(mut buffer: &'i [u8], known: &mut A) -> Result<Self, StunDecodeErr> {
		// Decode the type and length
		if buffer.remaining() < 4 { return Err(StunDecodeErr::TooShort(4)) }
		let typ = buffer.get_u16();
		if typ >= 0x4000 { return Err(StunDecodeErr::TypeOutOfRange) }
		let length = buffer.get_u16();
		if length % 4 != 0 { return Err(StunDecodeErr::UnalignedLength) }
		let packet_length = 20 + length as usize;
		if buffer.remaining() < (packet_length - 4) { return Err(StunDecodeErr::TooShort(packet_length)) }

		// Decode the rest of the header
		if buffer.get_u32() != MAGIC { return Err(StunDecodeErr::BadMagic) }
		let txid: &[u8; 12] = buffer[..12].try_into().unwrap();
		buffer.advance(12);
		
		// Prep the header for attribute decoding
		let attrs = &buffer[..length as usize];
		let mut header = [0; 20];
		header[0..2].copy_from_slice(&typ.to_be_bytes());
		// Length will be written before parsing each attribute
		header[4..8].copy_from_slice(&MAGIC.to_be_bytes());
		header[8..].copy_from_slice(txid);

		let mut i = 0;
		while i < length as usize {
			// Update the length in header
			header[2..4].copy_from_slice(&(i as u16).to_be_bytes());

			// Decode the type and length of this attribute
			let mut t = &attrs[i..];
			let attr_typ = t.get_u16();
			let attr_len = t.get_u16();
			if attr_typ as usize > t.remaining() { return Err(StunDecodeErr::BadAttrLength) }
			let value = &t[..attr_len as usize];
			known.decode_attr(attr_typ, &header, &attrs[..i], value);
			i += attr_len as usize;
			while i % 4 != 0 { i += 1; }
		}

		Ok(Self { typ, txid, attrs: length })
	}
	pub fn decode_length(&self) -> usize {
		20 + self.attrs as usize
	}
}
