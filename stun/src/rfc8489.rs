use std::net::SocketAddr;

use bytes::Buf;

use crate::StunAttrs;

pub struct StunError<'i> {
	code: u16,
	reason: &'i str,
	unknown_attrs: Vec<u16>
}

pub struct Rfc8489<'i, N> {
	mapped: Option<SocketAddr>,
	username: &'i str,
	integrity: bool,
	error: Option<StunError<'i>>,
	realm: &'i str,
	nonce: &'i str,
	software: &'i str,
	alternate: Option<(SocketAddr, &'i str)>,
	fingerprint: bool,

	next: N
}
impl<'i, N: StunAttrs<'i>> StunAttrs<'i> for Rfc8489<'i, N> {
	fn decode_attr(&mut self, header: &[u8; 20], attr_prefix: &[u8], attr_typ: u16, mut value: &'i [u8]) {
		match attr_typ {
			0x0001 /* MAPPED-ADDRESS */=> {}
			_ if self.fingerprint => {}, // Ignore all attributes after the fingerprint
			0x8028 /* FINGERPRINT */ => {

				let actual = value.get_u32();
				let mut expected = crc32fast::Hasher::new();
				expected.update(header);
				expected.update(attr_prefix);
				let expected = expected ^ 0x5354554e;

			}
			_ if self.integrity => {}, // Ignore attributes after the integrity (except fingerprint)
			0x0006 /* USERNAME */ => {
				self.username = std::str::from_utf8(value).map_err(Self::Error::NonUtf8Username)?;
			}

			_ => self.next.decode_attr(header, attr_prefix, attr_typ, value)
		}
		Ok(())
	}
}
