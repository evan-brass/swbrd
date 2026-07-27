//! DTLS client mobility: authenticate a roamed record the way
//! `mbedtls_ssl_check_record` does, so a connection's socket can be re-pointed at
//! the client's new address only when a packet provably belongs to the session.
//!
//! We are always the DTLS server, so the read direction is client→server and the
//! record is protected with the *client* write key.  OpenSSL exposes no read-key
//! export for DTLS 1.2, so we re-derive it from the public handshake secrets
//! (client/server random + master secret) via the TLS 1.2 PRF and run the
//! AES-128-GCM tag check ourselves — in place, without touching OpenSSL's own
//! connection state (replay window, sequence numbers).  The suite is pinned to
//! AES-128-GCM in [`crate::linux::load_config`], so this single record layout is
//! the only one we ever see.

use common::dtls::RecordHeader;
use libc::{c_int, c_void};
use openssl::{
	hash::MessageDigest,
	pkey::{PKey, Private},
	sign::Signer,
	ssl::SslRef,
};
use openssl_sys::{
	EVP_CIPHER_CTX, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new,
	EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_SET_TAG, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
	EVP_DecryptUpdate, EVP_aes_128_gcm,
};
use std::ptr;
use zerocopy::TryFromBytes;

/// The read-direction (client write) AES-128-GCM parameters, derived once at
/// handshake completion and cached on the connection.
#[derive(Clone, Copy)]
pub struct ReadKeys {
	key: [u8; 16],
	/// The 4-byte implicit (fixed) GCM IV; the record carries the 8-byte explicit
	/// nonce.
	iv: [u8; 4],
	/// The read epoch these keys belong to (1 post-handshake; we don't rekey).
	epoch: u16,
}

/// Re-derive the client-write AES-128-GCM key + fixed IV from a finished
/// handshake.  Returns `None` unless the negotiated suite is AES-128-GCM (the
/// pinned suite) with the expected secret sizes.
pub fn export_read_keys(ssl: &SslRef) -> Option<ReadKeys> {
	// Only the pinned AES-128-GCM layout is understood by `check_record`.
	if !ssl.current_cipher()?.name().contains("AES128-GCM") {
		return None;
	}

	let mut client_random = [0u8; 32];
	if ssl.client_random(&mut client_random) != client_random.len() {
		return None;
	}
	let mut server_random = [0u8; 32];
	if ssl.server_random(&mut server_random) != server_random.len() {
		return None;
	}
	let mut master = [0u8; 48];
	if ssl.session()?.master_key(&mut master) != master.len() {
		return None;
	}

	// RFC 5246 6.3: key_block = PRF(master_secret, "key expansion",
	//                               server_random + client_random).
	let mut seed = [0u8; 64];
	seed[..32].copy_from_slice(&server_random);
	seed[32..].copy_from_slice(&client_random);
	// AES-128-GCM, no MAC key: client_key(16) | server_key(16) | client_iv(4) | server_iv(4).
	let mut key_block = [0u8; 40];
	tls12_prf_sha256(&master, b"key expansion", &seed, &mut key_block);

	let mut key = [0u8; 16];
	key.copy_from_slice(&key_block[0..16]);
	let mut iv = [0u8; 4];
	iv.copy_from_slice(&key_block[32..36]);
	Some(ReadKeys { key, iv, epoch: 1 })
}

/// Validate a roamed DTLS record in place, mirroring `mbedtls_ssl_check_record`:
/// parse the header, check the epoch, and AEAD-verify the tag with the read keys
/// — leaving OpenSSL's connection state untouched.  On success returns the
/// record's 64-bit number; the caller uses it to advance the anti-replay
/// watermark and re-`connect` the socket.  The plaintext (written over the
/// ciphertext) is never read and the packet is dropped.
///
/// Anti-replay (the caller-side check `mbedtls_ssl_check_record` leaves out): the
/// record number must strictly exceed `highest_seq`, so a former on-path relay
/// can't replay a stale-but-authentic record to drag the connection back.
pub fn check_record(keys: &ReadKeys, highest_seq: u64, record: &mut [u8]) -> Option<u64> {
	// Parse + validate the 13-byte header (Copy value; the borrow ends here).
	let hdr = RecordHeader::try_read_from_prefix(&*record).ok()?.0;
	if hdr.epoch.get() != keys.epoch {
		return None;
	}
	let body_len = hdr.length.get() as usize;
	// The first record must hold at least an explicit nonce (8) + tag (16), and
	// fit within the datagram (later coalesced records, if any, are ignored).
	if body_len < 8 + 16 || 13 + body_len > record.len() {
		return None;
	}

	// Record number = epoch(16) << 48 | sequence(48) == the 8 bytes at [3..11].
	let mut seq8 = [0u8; 8];
	seq8.copy_from_slice(&record[3..11]);
	let seq_num = u64::from_be_bytes(seq8);
	if seq_num <= highest_seq {
		return None;
	}

	// GCM nonce = fixed client_write_iv(4) || explicit nonce(8) from the record.
	let mut nonce = [0u8; 12];
	nonce[..4].copy_from_slice(&keys.iv);
	nonce[4..].copy_from_slice(&record[13..21]);

	// AEAD additional data (RFC 5246 6.2.3.3):
	//   seq_num(8) || type(1) || version(2) || plaintext_len(2).
	let ct_len = body_len - 8 - 16;
	let mut aad = [0u8; 13];
	aad[..8].copy_from_slice(&seq8);
	aad[8] = record[0]; // content type
	aad[9..11].copy_from_slice(&record[1..3]); // version
	aad[11..13].copy_from_slice(&(ct_len as u16).to_be_bytes());

	// The tag trails the record body.
	let tag_off = 13 + body_len - 16;
	let mut tag = [0u8; 16];
	tag.copy_from_slice(&record[tag_off..tag_off + 16]);

	// Decrypt the ciphertext in place and verify the tag.
	let ct = &mut record[21..tag_off];
	gcm_verify(&keys.key, &nonce, &aad, ct, &tag).then_some(seq_num)
}

/// TLS 1.2 PRF with SHA-256 (RFC 5246 5): writes `PRF(secret, label, seed)` into
/// `out`.  Allocation-free apart from OpenSSL's own HMAC context.
fn tls12_prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
	let pkey = PKey::hmac(secret).expect("hmac key");
	// P_SHA256: A(1) = HMAC(secret, label || seed); A(i) = HMAC(secret, A(i-1)).
	let mut a = hmac(&pkey, &[label, seed]);
	let mut pos = 0;
	while pos < out.len() {
		// block = HMAC(secret, A(i) || label || seed).
		let block = hmac(&pkey, &[&a, label, seed]);
		let n = core::cmp::min(block.len(), out.len() - pos);
		out[pos..pos + n].copy_from_slice(&block[..n]);
		pos += n;
		a = hmac(&pkey, &[&a]);
	}
}

/// HMAC-SHA256 over the concatenation of `parts`, into a fixed stack buffer.
fn hmac(pkey: &PKey<Private>, parts: &[&[u8]]) -> [u8; 32] {
	let mut signer = Signer::new(MessageDigest::sha256(), pkey).expect("hmac signer");
	for p in parts {
		signer.update(p).expect("hmac update");
	}
	let mut out = [0u8; 32];
	let n = signer.sign(&mut out).expect("hmac sign");
	debug_assert_eq!(n, 32);
	out
}

/// AES-128-GCM authenticate-and-decrypt `data` in place (out == in).  Returns
/// `true` iff `tag` authenticates; on success `data` holds the plaintext, which
/// the caller discards.  No Rust heap allocation — only libcrypto's own context,
/// as with any `SSL_read`.
fn gcm_verify(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
	unsafe {
		let ctx = EVP_CIPHER_CTX_new();
		if ctx.is_null() {
			return false;
		}
		let ok = gcm_verify_inner(ctx, key, nonce, aad, data, tag);
		EVP_CIPHER_CTX_free(ctx);
		ok
	}
}

unsafe fn gcm_verify_inner(
	ctx: *mut EVP_CIPHER_CTX,
	key: &[u8; 16],
	nonce: &[u8; 12],
	aad: &[u8],
	data: &mut [u8],
	tag: &[u8; 16],
) -> bool {
	unsafe {
		let mut outl: c_int = 0;
		// Select the cipher, then the (default 12-byte) IV length, then key + nonce.
		if EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), ptr::null_mut(), ptr::null(), ptr::null()) != 1
		{
			return false;
		}
		if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.len() as c_int, ptr::null_mut())
			!= 1
		{
			return false;
		}
		if EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), nonce.as_ptr()) != 1 {
			return false;
		}
		// Additional authenticated data (out == null).
		if EVP_DecryptUpdate(ctx, ptr::null_mut(), &mut outl, aad.as_ptr(), aad.len() as c_int) != 1
		{
			return false;
		}
		// Ciphertext, decrypted in place: the same pointer is both input and output.
		if !data.is_empty() {
			let p = data.as_mut_ptr();
			let n = data.len() as c_int;
			if EVP_DecryptUpdate(ctx, p, &mut outl, p as *const u8, n) != 1 {
				return false;
			}
		}
		// Set the expected tag, then finalize — returns 1 iff the tag authenticates.
		if EVP_CIPHER_CTX_ctrl(
			ctx,
			EVP_CTRL_GCM_SET_TAG,
			tag.len() as c_int,
			tag.as_ptr() as *mut c_void,
		) != 1
		{
			return false;
		}
		let mut fin = [0u8; 16];
		EVP_DecryptFinal_ex(ctx, fin.as_mut_ptr(), &mut outl) == 1
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use openssl::symm::{Cipher, encrypt_aead};

	// RFC-era TLS 1.2 PRF(SHA-256) known-answer vector (widely cited on the IETF
	// TLS list): secret/seed below, label "test label", first 100 output bytes.
	#[test]
	fn prf_known_answer() {
		let secret = [
			0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71,
			0xdb, 0x35,
		];
		let seed = [
			0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5,
			0x19, 0x8c,
		];
		let expected = [
			0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c,
			0xd4, 0x53, 0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95, 0x32, 0x9b, 0x52, 0xd4,
			0xe6, 0x1e, 0xdb, 0x5a, 0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9, 0xc9, 0xa4,
			0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf, 0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
			0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab, 0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d,
			0xef, 0x9b, 0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba, 0xa4, 0x80, 0x82, 0xd1,
			0x22, 0xee, 0x42, 0xc5, 0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01, 0x87, 0x34,
			0x7b, 0x66,
		];
		let mut out = [0u8; 100];
		tls12_prf_sha256(&secret, b"test label", &seed, &mut out);
		assert_eq!(out, expected);
	}

	fn build_record(
		key: &[u8; 16],
		iv: &[u8; 4],
		epoch: u16,
		seq6: [u8; 6],
		explicit: [u8; 8],
		pt: &[u8],
	) -> Vec<u8> {
		let mut nonce = [0u8; 12];
		nonce[..4].copy_from_slice(iv);
		nonce[4..].copy_from_slice(&explicit);
		let mut seq8 = [0u8; 8];
		seq8[..2].copy_from_slice(&epoch.to_be_bytes());
		seq8[2..].copy_from_slice(&seq6);
		let version = [0xfe, 0xfd];
		let mut aad = [0u8; 13];
		aad[..8].copy_from_slice(&seq8);
		aad[8] = 23; // application data
		aad[9..11].copy_from_slice(&version);
		aad[11..13].copy_from_slice(&(pt.len() as u16).to_be_bytes());

		let mut tag = [0u8; 16];
		let ct = encrypt_aead(Cipher::aes_128_gcm(), key, Some(&nonce), &aad, pt, &mut tag).unwrap();

		let body_len = 8 + ct.len() + 16;
		let mut rec = vec![23u8];
		rec.extend_from_slice(&version);
		rec.extend_from_slice(&epoch.to_be_bytes());
		rec.extend_from_slice(&seq6);
		rec.extend_from_slice(&(body_len as u16).to_be_bytes());
		rec.extend_from_slice(&explicit);
		rec.extend_from_slice(&ct);
		rec.extend_from_slice(&tag);
		rec
	}

	#[test]
	fn check_record_roundtrip_and_guards() {
		let key = [0x2a; 16];
		let iv = [1u8, 2, 3, 4];
		let keys = ReadKeys { key, iv, epoch: 1 };
		let pt = b"hello over sctp";

		// A genuine record authenticates and decrypts in place.
		let mut rec = build_record(&key, &iv, 1, [0, 0, 0, 0, 0, 5], [9; 8], pt);
		let seq = check_record(&keys, 0, &mut rec).unwrap();
		assert_eq!(seq, (1u64 << 48) | 5);
		assert_eq!(&rec[21..21 + pt.len()], pt);

		// Replaying it (seq <= highest) is rejected.
		let mut replay = build_record(&key, &iv, 1, [0, 0, 0, 0, 0, 5], [9; 8], pt);
		assert!(check_record(&keys, seq, &mut replay).is_none());

		// A newer record still advances.
		let mut newer = build_record(&key, &iv, 1, [0, 0, 0, 0, 0, 6], [10; 8], pt);
		assert_eq!(check_record(&keys, seq, &mut newer), Some((1u64 << 48) | 6));

		// Wrong epoch is rejected before any crypto.
		let mut wrong_epoch = build_record(&key, &iv, 2, [0, 0, 0, 0, 0, 9], [11; 8], pt);
		assert!(check_record(&keys, 0, &mut wrong_epoch).is_none());

		// A tampered tag fails authentication.
		let mut tampered = build_record(&key, &iv, 1, [0, 0, 0, 0, 0, 7], [12; 8], pt);
		let last = tampered.len() - 1;
		tampered[last] ^= 0xff;
		assert!(check_record(&keys, 0, &mut tampered).is_none());

		// The wrong key fails authentication.
		let other = ReadKeys { key: [0x55; 16], iv, epoch: 1 };
		let mut rec2 = build_record(&key, &iv, 1, [0, 0, 0, 0, 0, 8], [13; 8], pt);
		assert!(check_record(&other, 0, &mut rec2).is_none());
	}
}
