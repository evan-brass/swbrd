pub trait StunAttr<'i>: StunAttrEncode {
	const ATTR_TYP: u16;
	type Ctx;
	type Error;
	fn decode(ctx: &'i Self::Ctx, header: &[u8; 20], attr_prefix: &[u8], value: &'i [u8]);
}

pub trait StunAttrEncode {
	fn header(&self) -> Option<(u16, u16)>;
	fn encode(&self, header: &[u8; 20], attr_prefix: &[u8], value: &mut [u8]);
}
