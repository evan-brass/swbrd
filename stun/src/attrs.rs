use std::net::{IpAddr, SocketAddr};
use bytes::{Buf, BufMut};
use super::attr::StunAttr;

#[derive(Debug)]
enum AddressDecodeError {
	TooShort,
	UnexpectedLength(usize),
	UnknownFamily(u8)
}
struct MappedAddress(SocketAddr);
impl StunAttr<'_> for MappedAddress {
	const ATTR_TYP: u16 = 0x0001;
	type Context = ();
	type Error = AddressDecodeError;
	fn decode(_: &Self::Context, _: &[u8; 20], _: &[u8], mut value: &'_ [u8]) -> Result<Self, Self::Error> where Self: Sized {
		if value.remaining() < 4 { return Err(AddressDecodeError::TooShort) }
		value.get_u8();
		let family = value.get_u8();
		let port = value.get_u16();
		let ip = match (family, value.remaining()) {
			(0x01, 4) => <[u8; 4]>::try_from(value).unwrap().into(),
			(0x02, 16) => <[u8; 16]>::try_from(value).unwrap().into(),
			(0x01, _) | (0x02, _) => return Err(AddressDecodeError::UnexpectedLength(value.len())),
			_ => return Err(AddressDecodeError::UnknownFamily(family))
		};
		Ok(Self(SocketAddr::new(ip, port)))
	}
	fn length(&self) -> u16 {
		match self.0 {
			SocketAddr::V4(_) => 8,
			SocketAddr::V6(_) => 20
		}
	}
	fn encode(&self, _: &[u8; 20], _: &[u8], mut value: &mut [u8]) {
		value.put_u8(0);
		value.put_u8(match self.0 {
			SocketAddr::V4(_) => 0x01,
			SocketAddr::V6(_) => 0x02
		});
		value.put_u16(self.0.port());
		match self.0.ip() {
			IpAddr::V4(v4) => value.put_slice(&v4.octets()),
			IpAddr::V6(v6) => value.put_slice(&v6.octets()),
		}
	}
}


struct Username<'i>(&'i str);
impl<'i> StunAttr<'i> for Username<'i> {
	const ATTR_TYP: u16 = 0x0006;
	type Context = ();
	type Error = std::str::Utf8Error;
	fn decode(_: &Self::Context, _: &[u8; 20], _: &[u8], value: &'i [u8]) -> Result<Self, Self::Error> where Self: Sized {
		std::str::from_utf8(value).map(Self)
	}
	fn length(&self) -> u16 {
		self.0.len() as u16
	}
	fn encode(&self, _: &[u8; 20], _: &[u8], value: &mut [u8]) {
		value.copy_from_slice(self.0.as_bytes());
	}
}

// TODO: MessageIntegrity

pub struct ErrorCode<'i> {
	reason: 
}
