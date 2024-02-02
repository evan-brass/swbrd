use bytes::Buf;

pub mod rfc8489;

const MAGIC: u32 = 0x2112A442;

pub trait StunAttrs<'i> {
	fn decode(&mut self, typ: u16, header: &[u8; 20], prefix: &[u8], value: &'i [u8]) -> Result<(), StunDecodeError>;
}

type Unknown = Vec<u16>;
impl StunAttrs<'_> for Unknown {
	fn decode(&mut self, typ: u16, _: &[u8; 20], _: &[u8], _: &[u8]) -> Result<(), StunDecodeError>{
		match typ {
			0..=0x7fff => self.push(typ),
			_ => {}
		}
		Ok(())
	}
}

pub struct Stun<'i, A> {
	pub typ: u16,
	pub txid: &'i [u8; 12],
	pub attrs: A
}

pub enum StunDecodeError {
	TooSmall(usize),
	NotStun,
}

impl<'i, A: StunAttrs<'i>> Stun<'i, A> {
	fn decode_attrs(header: &mut [u8; 20], body: &'i [u8], attrs: &mut A) -> Result<u16, StunDecodeError> {


		Ok(())
	}
	pub fn decode(buffer: &[u8], mut attrs: A) -> Result<Self, StunDecodeError> {
		if buffer.len() < 20 { return Err(StunDecodeError::TooSmall(20)) }

		let (header, body) = buffer.split_at(20);
		let mut header: [u8; 20] = header.try_into().unwrap();
		

		let (typ, length, magic, txid) = {
			let mut t = &header;
			(t.get_u16(), t.get_u16(), t.get_u32(), t.try_into().unwrap())
		};
		todo!()
	}
}
