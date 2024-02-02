use std::net::SocketAddr;

use crate::{StunAttrs, StunDecodeError};

pub struct StunError<'i> {
	code: u16,
	reason: &'i str,
	unknown_attrs: Vec<u16>
}
pub enum StunUser<'i> {
	NoUser,
	ShortTerm {
		username: &'i str
	},
	LongTerm {
		realm: &'i str,
		username: &'i str
	}
}
pub trait StunAuth {
	type Key: AsRef<[u8]>;
	fn key(&self) -> Option<Self::Key>;
}

pub struct Rfc8489<'i, A: StunAuth, N> {
	decode_error: Option<()>,

	authorizer: A,

	mapped: Option<SocketAddr>,
	software: &'i str,

	auth: StunUser<'i>,
	nonce: &'i str,
	integrity: Option<A::Key>,
	fingerprint: bool,
	
	error: Option<StunError<'i>>,
	alternate: Option<(SocketAddr, &'i str)>,

	next: N
}
impl<'i, A: StunAuth, N: StunAttrs<'i>> StunAttrs<'i> for Rfc8489<'i, A, N> {
	fn decode(&mut self, typ: u16, header: &[u8; 20], prefix: &[u8], value: &'i [u8]) -> Result<(), StunDecodeError> {
		todo!()
	}
}
