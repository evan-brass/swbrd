use bytes::{Buf, BufMut};

pub mod rfc8489;
pub mod attr;
pub mod attrs;

const MAGIC: u32 = 0x2112A442;


pub struct Stun<T, A> {
	pub typ: u16,
	pub txid: T,
	pub attrs: A
}

pub enum StunDecodeError {
	TooSmall(usize),
	TypeOutOfRange,
	UnalignedLength,
	BadMagic,
}

impl<'i> Stun<&'i [u8; 12], > {

}

impl<'i> Stun<'i, &'i [u8]> {
	fn decode(buffer: &'i [u8]) -> Result<Self, StunDecodeError> {
		if buffer.len() < 20 { return Err(StunDecodeError::TooSmall(20)) }

		// Decode the STUN header
		let (mut header, rest) = buffer.split_at(20);
		let typ = header.get_u16();
		let length = header.get_u16();
		let magic = header.get_u32();
		let txid = header.try_into().unwrap();

		if typ >= 0x4000 { return Err(StunDecodeError::TypeOutOfRange) }
		if length % 4 != 0 { return Err(StunDecodeError::UnalignedLength) }
		let packet_length = 20 + length as usize;
		if buffer.len() < packet_length { return Err(StunDecodeError::TooSmall(packet_length)) }
		if magic != MAGIC { return Err(StunDecodeError::BadMagic) }

		let attrs = &rest[..length as usize];

		Ok(Self { typ, txid, attrs })
	}
	fn decode_length(&self) -> usize {
		20 + self.attrs.len()
	}
	fn parse<A: StunAttrs<'i>>(self, mut attrs: A) -> Stun<'i, A> {
		let mut header = [0u8; 20];
		{	// Prep the header
			let mut header = header.as_mut_slice();
			header.put_u16(self.typ);
			header.put_u16(0);
			header.put_u32(MAGIC);
			header.put_slice(self.txid);
		}

		let mut i = 0;
		while i < self.attrs.len() {
			let (prefix, mut rest) = self.attrs.split_at(i);
			let attr_typ = rest.get_u16();
			let attr_len = rest.get_u16();
			if rest.remaining() < attr_len as usize { break }
			let value = &rest[..attr_len as usize];

			i += attr_len as usize;
			while i % 4 != 0 { i += 1; }
			header[2..4].copy_from_slice(&(i as u16).to_be_bytes());

			attrs.decode_attr(&header, prefix, attr_typ, value);
		}
		
		Stun { typ: self.typ, txid: self.txid, attrs }
	}
}
