use std::str::Utf8Error;

use crate::StunAttrs;

pub trait Authentication {
	fn key(&self, realm: &str, username: &str) -> Option<&[u8]>;
}
impl Authentication for () {
	fn key(&self, _: &str, _: &str) -> Option<&[u8]> {
		None
	}
}
impl<K: std::hash::Hash + Eq + std::borrow::Borrow<str>, V: AsRef<[u8]>> Authentication for std::collections::HashMap<K, V> {
	fn key(&self, realm: &str, username: &str) -> Option<&[u8]> {
		if !realm.is_empty() { return None }
		self.get(username).map(AsRef::as_ref)
	}
}

pub struct Auth<'i, A, N> {
	authentication: A,

	// TODO: userhash, password algorithms, integrity-256, and such.
	realm: &'i str,
	username: &'i str,
	nonce: &'i str,
	key: Option<&'i [u8]>,
	fingerprint: bool,

	next: N
}
pub enum AuthError<E> {
	FingerprintFailed,
	UsernameNotUtf(Utf8Error),
	RealmNotUtf(Utf8Error),
	NonceNotUtf(Utf8Error),
	Forbidden,

	Next(E)
}
impl<'i, A: Authentication, N: StunAttrs<'i>> StunAttrs<'i> for Auth<'i, A, N> {
	type Error = AuthError<N::Error>;
	fn decode_attr(&mut self, header: &[u8; 20], attr_prefix: &[u8], attr_typ: u16, value: &'i [u8]) -> Result<(), Self::Error> {
		match attr_typ {
			_ if self.fingerprint => {} // Ignore attributes after the 
			0x8028 /* FINGERPRINT */ => {

			}
			_ if self.key.is_some() => {} // Ignore attributes after the integrity attribute
			0x0006 /* USERNAME */ if self.username.is_empty() => {
				self.username = std::str::from_utf8(value).map_err(AuthError::UsernameNotUtf)?;
			}
			0x0014 /* REALM */ if self.realm.is_empty() => {
				self.realm = std::str::from_utf8(value).map_err(AuthError::RealmNotUtf)?;
			}
			0x0015 /* NONCE */ if self.nonce.is_empty() => {
				self.nonce = std::str::from_utf8(value).map_err(AuthError::NonceNotUtf)?;
			}
			0x0008 /* MESSAGE-INTEGRITY */ => {
				
			}


			_ => self.next.decode_attr(header, attr_prefix, attr_typ, value).map_err(Self::Error::Next)?
		}
		Ok(())
	}
}
