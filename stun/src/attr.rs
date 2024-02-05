
pub trait StunAttrs<'i> {
	fn write(&mut self, attr_typ: u16) -> &mut dyn StunAttrValue<'i>;
	fn read(&mut self, attr_typ: u16) -> Option<&dyn StunAttrValue<'i>>;
}

pub trait StunAttrValue<'i> {
	fn decode(&mut self, header: &[u8; 20], prefix: &[u8], value: &'i [u8]);
	fn header(&self) -> Option<(u16, u16)>;
	fn encode(&self, header: &[u8; 20], prefix: &[u8], value: &mut [u8]);
}
