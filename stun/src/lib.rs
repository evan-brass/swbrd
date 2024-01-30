use bytes::Buf;

pub mod attr;

const MAGIC: u32 = 0x2112A442;


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

impl<'i> Stun<&'i [u8; 12], usize> {
	pub fn decode<A: attr::KnownStunAttrs<'i>>(buffer: &'i [u8], known: &mut A) -> Result<Self, StunDecodeErr> {
		if buffer.len() < 20 { return Err(StunDecodeErr::TooShort(20)) }

		let (header, all_attrs) = buffer.split_at(20);

		// Decode the header
		let (typ, length, txid) = {
			let mut header = &*header;
			let typ = header.get_u16();
			if typ >= 0x4000 { return Err(StunDecodeErr::TypeOutOfRange) }
			let length = header.get_u16();
			if length % 4 != 0 { return Err(StunDecodeErr::UnalignedLength) }
			let packet_length = 20 + length as usize;
			if buffer.len() < packet_length { return Err(StunDecodeErr::TooShort(packet_length)) }
			if header.get_u32() != MAGIC { return Err(StunDecodeErr::BadMagic) }
			let txid = header.try_into().unwrap();
			(typ, length, txid)
		};
		let all_attrs = &all_attrs[..length as usize];

		// Decode the attributes
		let mut header: [u8; 20] = header.try_into().unwrap();
		let mut attrs = &*all_attrs;

		let mut length = 0;
		while attrs.has_remaining() {
			let attr_prefix = &all_attrs[..length];
			let attr_typ = attrs.get_u16();
			let attr_length = attrs.get_u16();
			if attrs.remaining() < attr_length as usize { return Err(StunDecodeErr::BadAttrLength) }

			let value = &attrs[..attr_length as usize];
			let mut aligned = attr_length as usize;
			while aligned % 4 != 0 { aligned += 1 }
			
			length += 4;
			length += aligned;
			attrs.advance(aligned);

			header[2..4].copy_from_slice(&(length as u16).to_be_bytes());

			known.decode_attr(attr_typ, &header, attr_prefix, value);
		}

		Ok(Self { typ, txid, attrs: length })
	}
	pub fn decode_length(&self) -> usize {
		20 + self.attrs
	}
}
