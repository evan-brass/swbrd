pub trait KnownAttrs<'i> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]);
}

#[derive(Debug, Default)]
pub struct Unknown(Vec<u16>);
impl KnownAttrs<'_> for Unknown {
	fn decode_attr(&mut self, attr_typ: u16, _: &[u8; 20], _: &[u8], _: &'_ [u8]) {
		match attr_typ {
			0x0000..=0x7FFF => self.0.push(attr_typ),
			_ => {}
		}
	}
}

#[derive(Debug, Default)]
pub struct Rfc8489<T> {
	// TODO: Other attributes
	inner: T
}
impl<'i, T: KnownAttrs<'i>> KnownAttrs<'i> for Rfc8489<T> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) {
		match attr_typ {
			// TODO: ignore attribute after fingerprint or integrity
			// Comprehension Required:
			0x0001 /* MAPPED-ADDRESS */ => {}
			0x0006 /* USERNAME */ => {}
			0x0008 /* MESSAGE-INTEGRITY */ => {}
			0x0009 /* ERROR-CODE */ => {}
			0x000A /* UNKNOWN-ATTRIBUTES */ => {}
			0x0014 /* REALM */ => {}
			0x0015 /* NONCE */ => {}
			0x001C /* MESSAGE-INTEGRITY-SHA256 */ => {}
			0x001D /* PASSWORD-ALGORITHM */ => {}
			0x001E /* USERHASH */ => {}
			0x0020 /* XOR-MAPPED-ADDRESS */ => {}

			// Comprehension Optional
			0x8002 /* PASSWORD-ALGORITHMS */ => {}
			0x8003 /* ALTERNATE-DOMAIN */ => {}
			0x8022 /* SOFTWARE */ => {}
			0x8023 /* ALTERNATE-SERVER */ => {}
			0x8028 /* FINGERPRINT */ => {}

			// Pass everything else to inner
			_ => self.inner.decode_attr(attr_typ, header, attr_prefix, value)
		}
	}
}
