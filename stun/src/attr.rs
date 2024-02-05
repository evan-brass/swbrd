pub trait StunAttr<'i> {
	const ATTR_TYP: u16;
	type Error;
	type Context;
	fn decode(ctx: &Self::Context, header: &[u8; 20], prefix: &[u8], value: &'i [u8]) -> Result<Self, Self::Error> where Self: Sized;
	fn length(&self) -> u16;
	fn encode(&self, header: &[u8; 20], prefix: &[u8], value: &mut [u8]);
}

pub trait StunAttrObj<'i> {
	fn decode(&mut self, header: &[u8; 20], attr_prefix: &[u8], attr_typ: u16, value: &'i [u8]);
	fn header(&self) -> Option<(u16, u16)>;
	fn encode(&self, header: &[u8; 20], prefix: &[u8], value: &mut [u8]);
}
impl<'i, A: StunAttr<'i, Context = ()>> StunAttrObj<'i> for Option<Result<A, A::Error>> {
	fn decode(&mut self, header: &[u8; 20], prefix: &[u8], attr_typ: u16, value: &'i [u8]) {
		if self.is_none() && attr_typ == A::ATTR_TYP {
			*self = Some(A::decode(&(), header, prefix, value));
		}
	}
	fn header(&self) -> Option<(u16, u16)> {
		match self {
			Some(Ok(a)) => Some((A::ATTR_TYP, a.length())),
			_ => None
		}
	}
	fn encode(&self, header: &[u8; 20], prefix: &[u8], value: &mut [u8]) {
		if let Some(Ok(a)) = self {
			a.encode(header, prefix, value);
		}
	}
}
