pub trait StunAttr<'i>: StunAttrEncode {
	const ATTR_TYPE: u16;
	fn decode(header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) -> Option<Self> where Self: Sized;
}
pub trait StunAttrEncode {
	fn header(&self) -> Option<(u16, u16)>;
	fn encode(&self, header:  &[u8; 20], attr_prefix: &[u8], value: &mut [u8]);
}
pub trait KnownStunAttrs<'i> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]);
	fn parse<A>(self, attr: &'i mut Option<A>) -> Parse<'i, A, Self> where Self: Sized {
		Parse { attr, next: self }
	}
}

#[derive(Debug, Default)]
pub struct UnknownAttrs(Vec<u16>);
impl KnownStunAttrs<'_> for UnknownAttrs {
	fn decode_attr(&mut self, attr_typ: u16, _: &[u8; 20], _: &[u8], _: &[u8]) {
		// Append any comprehension required attributes to our list of unknown attributes
		if attr_typ < 0x8000 { self.0.push(attr_typ) }
	}
}
#[derive(Debug)]
pub struct Parse<'i, A, N> {
	attr: &'i mut Option<A>,
	next: N
}
impl<'i, A: StunAttr<'i>, N: KnownStunAttrs<'i>> KnownStunAttrs<'i> for Parse<'_, A, N> {
	fn decode_attr(&mut self, attr_typ: u16, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]) {
		if attr_typ == A::ATTR_TYPE {
			if self.attr.is_none() {
				*self.attr = A::decode(header, attr_prefix, value)
			}
		} else {
			self.next.decode_attr(attr_typ, header, attr_prefix, value);
		}
	}
}
