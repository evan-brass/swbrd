use bytes::Buf;
use bytes::Bytes;
use tokio_util::codec::{Decoder, Encoder};
use std::io::Error;

const MAGIC: u32 = 0x2112A442;

#[derive(Debug)]
pub struct Stun {
	typ: u16,
	txid: [u8; 12],
	attrs: Bytes
}

#[derive(Debug, Default)]
pub struct StunCodec {
	header: Option<(u16, u16)>
	// TODO: username resolve
}
impl Decoder for StunCodec {
	type Item = Stun;
	type Error = Error;
	fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
		// Decode the STUN Message length
		let (typ, length) = match self.header.take() {
			Some((typ, len)) => (typ, len),
			None if src.remaining() >= 4 => (src.get_u16(), src.get_u16()),
			_ => return Ok(None)
		};
		if typ >= 0x4000 { return Err(Error::other("STUN: Type out of range")) }
		if length % 4 != 0 { return Err(Error::other("STUN: Unaligned length")) }
		
		let packet_length = 20 + length as usize;
		if src.remaining() < packet_length - 4 {
			src.reserve(packet_length - 4);
			self.header = Some((typ, length)); // Put the header back
			return Ok(None);
		}

		// Decode rest of the header
		if src.get_u32() != MAGIC { return Err(Error::other("STUN: Bad magic")) }
		let mut txid = [0; 12];
		src.copy_to_slice(&mut txid);

		// Decode the attributes
		let attrs = src.copy_to_bytes(length as usize);

		Ok(Some(Stun { typ, txid, attrs }))
	}
}
