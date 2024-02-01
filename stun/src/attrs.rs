use crate::StunDecodeError;

pub trait KnownAttrs<'i> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) -> Option<StunDecodeError>;
}

#[derive(Debug, Default)]
pub struct Unknown(Vec<u16>);
impl KnownAttrs<'_> for Unknown {
	fn decode_attr(&mut self, attr_typ: u16, _: &[u8; 20], _: &[u8], _: &'_ [u8]) -> Option<StunDecodeError> {
		match attr_typ {
			0x0000..=0x7FFF => self.0.push(attr_typ),
			_ => {}
		}
		None
	}
}

pub trait StunAuth {
	fn get_key(&self, realm: Option<&str>, username: Option<&str>) -> Option<&[u8]>;
}
#[derive(Debug)]
pub struct Auth<T> {
	mgr: T
}
