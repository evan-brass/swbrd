use bytes::Buf;

use crate::StunDecodeError;


pub trait StunAttrValue<'i> {
	type Error: Into<Option<StunDecodeError>>;
	fn decode(header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) -> Result<Self, Self::Error> where Self: Sized;

	fn length(&self) -> u16;
	fn encode(&self, header: &[u8; 20], attr_prefix: &[u8], value: &mut [u8]);
}

impl<'i> StunAttrValue<'i> for &'i str {
	type Error = std::str::Utf8Error;
	fn decode(_: &[u8; 20], _: &[u8], value: &'i [u8]) -> Result<Self, Self::Error> where Self: Sized {
		std::str::from_utf8(value)
	}

	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, _: &[u8; 20], _: &[u8], value: &mut [u8]) {
		value.copy_from_slice(self.as_bytes());
	}
}

pub struct Fingerprint;
pub enum FingerprintError {
	UnexpectedLength,
	BadChecksum
}
impl StunAttrValue<'_> for Fingerprint {
	type Error = FingerprintError;
	fn decode(header: &[u8; 20], attr_prefix: &[u8], mut value: &'_ [u8]) -> Result<Self, Self::Error> where Self: Sized {
		if value.len() != 4 { return Err(FingerprintError::UnexpectedLength) }
		let actual = value.get_u32();

		let mut check = crc32fast::Hasher::new();
		check.update(header);
		check.update(attr_prefix);
		let expected = check.finalize() ^ 0x5354554e;
		
		if actual == expected {
			Ok(Self)
		} else {
			Err(FingerprintError::BadChecksum)
		}
	}
	fn length(&self) -> u16 {
		4
	}
	fn encode(&self, header: &[u8; 20], attr_prefix: &[u8], value: &mut [u8]) {
		
	}
}
