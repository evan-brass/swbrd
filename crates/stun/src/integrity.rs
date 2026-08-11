#![allow(unused)]
#[cfg(feature = "sha1")]
use crate::Authkey;
use crate::Stun;
use zerocopy::{IntoBytes, network_endian::U32};

impl Stun {
	#[cfg(feature = "sha1")]
	pub fn expected_message_integrity(&self, authkey: &Authkey) -> [u8; 20] {
		use sha1::{Digest, Sha1};
		// This is just a manual HMAC
		let mut hash1 = Sha1::new();
		hash1.update(authkey.ipad);
		hash1.update([self.class as u8, self.method as u8]);
		hash1.update(u16::to_be_bytes(size_of_val(&self.body) as u16 + 24));
		hash1.update(self.txid.as_bytes());
		hash1.update(self.body.as_flattened());

		let sum1 = hash1.finalize().0;

		let mut hash2 = Sha1::new();
		hash2.update(authkey.opad);
		hash2.update(sum1);

		hash2.finalize().0
	}

	#[cfg(feature = "crc")]
	pub fn expected_fingerprint(&self) -> U32 {
		use crc::Crc;

		const FINGERPRINT_MAGIC: u32 = 0x5354554e;
		const CRC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

		let mut hash = CRC.digest();
		hash.update(&[self.class as u8, self.method as u8]);
		hash.update(&u16::to_be_bytes(size_of_val(&self.body) as u16 + 8));
		hash.update(self.txid.as_bytes());
		hash.update(self.body.as_flattened());

		U32::new(hash.finalize() ^ FINGERPRINT_MAGIC)
	}
}
