use std::net::{IpAddr, SocketAddr};
use bytes::{Buf, BufMut};

use super::attr::{StunAttr, StunAttrEncode};

pub struct Mapped(SocketAddr);
pub enum MappedDecodeError {
	UnknownFamily(u8),
	UnexpectedLength
}
impl StunAttr<'_> for Mapped {
	const ATTR_TYPE: u16 = 0x001;
	type Error = MappedDecodeError;

	fn decode(_: &[u8; 20], _: &[u8], mut value: &[u8]) -> Result<Self, Self::Error> where Self: Sized {
		if value.remaining() < 4 { return Err(Self::Error::UnexpectedLength) }
		value.get_u8();
		let family = value.get_u8();
		let port = value.get_u16();
		let ip = match (family, value.remaining()) {
			(0x01, 4) => <[u8; 4]>::try_from(value).unwrap().into(),
			(0x02, 16) => <[u8; 16]>::try_from(value).unwrap().into(),
			(0x01, _) |
			(0x02, _) => return Err(MappedDecodeError::UnexpectedLength),
			_ => return Err(MappedDecodeError::UnknownFamily(family))
		};
		Ok(Self(SocketAddr::new(ip, port)))
	}
}
impl StunAttrEncode for Mapped {
	fn header(&self) -> Option<(u16, u16)> {
		Some((
			Self::ATTR_TYPE,
			match self.0 {
				SocketAddr::V4(_) => 8,
				SocketAddr::V6(_) => 20
			}
		))
	}
	fn encode(&self, _: &[u8; 20], _: &[u8], mut value: &mut [u8]) {
		value.put_u8(0);
		value.put_u16(self.0.port());
		match self.0.ip() {
			IpAddr::V4(v4) => value.put_slice(&v4.octets()),
			IpAddr::V6(v6) => value.put_slice(&v6.octets())
		}
	}
}

pub struct XorMapped(SocketAddr);
impl StunAttrEncode for XorMapped {
	fn header(&self) -> Option<(u16, u16)> {
		Mapped(self.0).header()
	}
	fn encode(&self, header: &[u8; 20], attr_prefix: &[u8], value: &mut [u8]) {
		Mapped(self.0).encode(header, attr_prefix, value);
		for let i = 
	}
}
