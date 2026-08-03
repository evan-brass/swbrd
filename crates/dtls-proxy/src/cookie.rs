//! Stateless DTLS cookies.
//!
//! Neither OpenSSL (`DTLSv1_listen`) nor mbedTLS will emit a HelloVerifyRequest
//! for a *fragmented* ClientHello, and Chrome fragments its ClientHellos at
//! 1200 bytes.  So cookies are handled manually: [`Keys::inspect`] statelessly
//! parses the first fragment of a ClientHello (the cookie always lands in
//! fragment 0) and either answers with a HelloVerifyRequest or clears the
//! datagram for [`promote`], which is the only place an [`Ssl`] is created.
//!
//! A fresh server Ssl only accepts a ClientHello with message_seq 0, but a
//! post-HelloVerifyRequest retry always has message_seq 1 (RFC 6347 4.2.2) and
//! OpenSSL only accepts that after *it* has sent a HelloVerifyRequest on the
//! same Ssl.  So `promote` walks the new Ssl into that state: it feeds a
//! synthetic empty-cookie ClientHello, captures (and discards) the resulting
//! HelloVerifyRequest — whose cookie, via the generate callback, is byte-equal
//! to the one we already verified — and only then feeds the real, verified,
//! truncated fragment.  Capturing the HelloVerifyRequest doubles as proof that
//! OpenSSL reached the state where any future non-matching ClientHello is
//! rejected, so a parsing disagreement can't leave a virgin Ssl behind as a
//! cookie bypass.

use std::{os::fd::RawFd, sync::LazyLock};

use common::dtls::{
	COOKIE_LEN, ContentType, Fragment, HandshakeHeader, HelloVerifyRequest, RecordHeader, U24,
	Version,
};
use eyre::{Result, ensure, eyre};
use openssl::{
	error::ErrorStack,
	hash::MessageDigest,
	pkey::{PKey, Private},
	sign::Signer,
	ssl::{Ssl, SslContextBuilder, SslContextRef, SslOptions},
};
use zerocopy::{IntoBytes, network_endian::U16};

use crate::ffi::{self, BioPair, SslIo};

type Addr = ([u8; 16], U16);

/// The cookie an Ssl expects, stashed so the cookie callbacks can reach it
static INDEX: LazyLock<openssl::ex_data::Index<Ssl, [u8; COOKIE_LEN]>> =
	LazyLock::new(|| Ssl::new_ex_index().unwrap());

/// Install the cookie callbacks on a server context.  Generation and
/// verification both just reproduce the cookie that was already verified
/// statelessly in [`Keys::inspect`] — by the time OpenSSL sees a ClientHello
/// its cookie has been checked, so verification here is a formality that only
/// re-pins the cookie against fragment-reassembly shenanigans.
pub fn configure(ctx: &mut SslContextBuilder) {
	ctx.set_options(SslOptions::COOKIE_EXCHANGE);
	ctx.set_cookie_generate_cb(|ssl, buf| {
		let cookie = ssl.ex_data(*INDEX).ok_or_else(ErrorStack::get)?;
		buf[..COOKIE_LEN].copy_from_slice(cookie);
		Ok(COOKIE_LEN)
	});
	ctx.set_cookie_verify_cb(|ssl, cookie| {
		ssl.ex_data(*INDEX).is_some_and(|expected| {
			cookie.len() == COOKIE_LEN && openssl::memcmp::eq(expected, cookie)
		})
	});
}

/// A ClientHello fragment whose cookie checked out
pub struct Verified<'a> {
	cookie: [u8; COOKIE_LEN],
	random: [u8; 32],
	/// [`Fragment::truncated`] record + handshake headers for [`Self::body`]
	header: [u8; 25],
	body: &'a [u8],
}

pub enum Verdict<'a> {
	/// Not the start of a ClientHello (or malformed): ignore the datagram
	Drop,
	/// A ClientHello without a valid cookie: answer statelessly, keep no state
	HelloVerify(HelloVerifyRequest),
	/// A ClientHello with a valid cookie: safe to [`promote`]
	Accept(Verified<'a>),
}

pub struct Keys {
	hmac: PKey<Private>,
}
impl Keys {
	pub fn generate() -> Result<Self> {
		let mut key = [0; 32];
		openssl::rand::rand_bytes(&mut key)?;
		Ok(Self {
			hmac: PKey::hmac(&key)?,
		})
	}

	/// HMAC over both src and dst: dst ip+port is our stand-in for DTLS
	/// connection ids, so a cookie must not be portable between destinations.
	fn cookie(&self, src: Addr, dst: Addr) -> Result<[u8; COOKIE_LEN]> {
		let mut signer = Signer::new(MessageDigest::sha256(), &self.hmac)?;
		signer.update(&src.0)?;
		signer.update(src.1.as_bytes())?;
		signer.update(&dst.0)?;
		signer.update(dst.1.as_bytes())?;
		let mut cookie = [0; COOKIE_LEN];
		signer.sign(&mut cookie)?;
		Ok(cookie)
	}

	/// Statelessly judge a datagram from an unknown src/dst pair
	pub fn inspect<'a>(&self, src: Addr, dst: Addr, datagram: &'a [u8]) -> Verdict<'a> {
		let Some(fragment) = Fragment::parse(datagram) else {
			return Verdict::Drop;
		};
		let Some(hello) = fragment.client_hello() else {
			return Verdict::Drop;
		};
		let Ok(cookie) = self.cookie(src, dst) else {
			return Verdict::Drop;
		};
		if hello.cookie.len() == COOKIE_LEN && openssl::memcmp::eq(hello.cookie, &cookie) {
			Verdict::Accept(Verified {
				cookie,
				random: hello.random,
				header: fragment.truncated(),
				body: fragment.body,
			})
		} else {
			Verdict::HelloVerify(HelloVerifyRequest::new(&fragment, cookie))
		}
	}
}

/// A minimal well-formed ClientHello: message_seq 0, empty cookie.  Its only
/// job is to make OpenSSL send a HelloVerifyRequest (which happens before any
/// version/cipher negotiation), so one dummy cipher suite and no extensions.
#[repr(C, packed)]
#[derive(
	Clone, Copy, zerocopy::KnownLayout, zerocopy::Immutable, zerocopy::Unaligned, IntoBytes,
)]
struct SyntheticHello {
	record: RecordHeader,
	handshake: HandshakeHeader,
	version: Version,
	random: [u8; 32],
	session_id_len: u8,
	cookie_len: u8,
	cipher_suites_len: U16,
	cipher_suite: U16,
	compression_len: u8,
	compression: u8,
}
impl SyntheticHello {
	const BODY: usize = 2 + 32 + 1 + 1 + 2 + 2 + 1 + 1;

	fn new(random: [u8; 32]) -> Self {
		Self {
			record: RecordHeader {
				content_type: ContentType::Handshake,
				version: Version::Dtls1_0,
				epoch: U16::new(0),
				sequence: [0; 6],
				length: U16::new((size_of::<HandshakeHeader>() + Self::BODY) as u16),
			},
			handshake: HandshakeHeader {
				typ: HandshakeHeader::CLIENT_HELLO,
				length: U24::new(Self::BODY as u32),
				message_seq: U16::new(0),
				fragment_offset: U24::new(0),
				fragment_length: U24::new(Self::BODY as u32),
			},
			version: Version::Dtls1_2,
			random,
			session_id_len: 0,
			cookie_len: 0,
			cipher_suites_len: U16::new(2),
			cipher_suite: U16::new(0xc02b), // ECDHE-ECDSA-AES128-GCM-SHA256, never actually negotiated
			compression_len: 1,
			compression: 0,
		}
	}
}

/// A caught-up server handshake: an owned [`Ssl`] past the cookie exchange,
/// still driven through an in-memory datagram BIO pair.  Production immediately
/// [`Self::into_established`]s it onto the connected socket; the tests keep
/// driving it in memory via [`Self::feed`] / [`Self::drain_output`].
pub struct Handshake {
	ssl: Ssl,
	pair: BioPair,
}
impl Handshake {
	pub fn is_finished(&self) -> bool {
		self.ssl.is_init_finished()
	}
	/// The datagrams the Ssl has written out so far (handshake flights).
	pub fn drain_output(&self) -> Vec<Vec<u8>> {
		self.pair.drain()
	}
	/// Queue one ciphertext datagram for the Ssl to read.  Only production's
	/// remaining fragments arrive on the socket; the in-memory tests feed here.
	#[cfg(test)]
	pub fn feed(&self, datagram: &[u8]) {
		self.pair.feed(datagram);
	}
	#[cfg(test)]
	pub fn do_handshake(&mut self) -> SslIo {
		ffi::do_handshake(&mut self.ssl)
	}
	/// Read decrypted application data (used by the in-memory tests; production
	/// reads via [`ffi::read`] on the owned Ssl after [`Self::into_established`]).
	#[cfg(test)]
	pub fn read(&mut self, buf: &mut [u8]) -> SslIo {
		ffi::read(&mut self.ssl, buf)
	}
	/// Cut over from the in-memory pair to a dgram BIO on the connected socket
	/// `fd`, returning the owned Ssl.  The caller must have already drained and
	/// sent any pending output; this consumes (and frees) the pair.
	pub fn into_established(self, fd: RawFd) -> Result<Ssl> {
		let Handshake { mut ssl, pair } = self;
		ensure!(ffi::attach_dgram(&mut ssl, fd), "BIO_new_dgram failed");
		drop(pair);
		Ok(ssl)
	}
}

/// The only place an Ssl is created: for a cookie-[`Verified`] ClientHello
/// fragment.  Feeds OpenSSL the synthetic hello, requires the captured
/// HelloVerifyRequest as proof of state, then feeds exactly the verified bytes.
pub fn promote(ctx: &SslContextRef, verified: &Verified) -> Result<Handshake> {
	let mut ssl = Ssl::new(ctx)?;
	ssl.set_ex_data(*INDEX, verified.cookie);
	ssl.set_accept_state();

	let pair = BioPair::new().ok_or_else(|| eyre!("BIO_new_bio_dgram_pair failed"))?;
	ffi::set_bio(&mut ssl, &pair);

	// Walk the Ssl into its post-HelloVerifyRequest state
	pair.feed(SyntheticHello::new(verified.random).as_bytes());
	match ffi::do_handshake(&mut ssl) {
		SslIo::WantRead => {}
		_ => return Err(eyre!("synthetic hello: unexpected handshake result")),
	}
	let captured = pair.drain();
	ensure!(
		captured
			.first()
			.and_then(|d| Fragment::parse(d))
			.is_some_and(|f| f.handshake.typ == HandshakeHeader::HELLO_VERIFY_REQUEST),
		"no hello verify request: {:?}",
		ssl.state_string_long()
	);

	// The verified fragment, and nothing else from its datagram.  If the
	// ClientHello was unfragmented this writes the ServerHello flight (drained
	// by the caller); otherwise OpenSSL buffers the fragment and awaits the rest.
	let mut record = Vec::with_capacity(verified.header.len() + verified.body.len());
	record.extend_from_slice(&verified.header);
	record.extend_from_slice(verified.body);
	pair.feed(&record);
	match ffi::do_handshake(&mut ssl) {
		SslIo::Ok(_) | SslIo::WantRead | SslIo::WantWrite => {}
		SslIo::ZeroReturn => return Err(eyre!("client hello: peer closed")),
		SslIo::Syscall(e) => return Err(eyre!("client hello: syscall {e}")),
		SslIo::Fatal => return Err(eyre!("client hello: fatal handshake result")),
	}

	Ok(Handshake { ssl, pair })
}

#[cfg(test)]
mod tests {
	use super::*;
	use openssl::{
		asn1::Asn1Time,
		ec::{EcGroup, EcKey},
		nid::Nid,
		ssl::{ErrorCode, SslContext, SslMethod, SslStream, SslVerifyMode},
		x509::X509,
	};
	use std::{
		collections::VecDeque,
		io::{Read, Write},
	};

	const SRC: Addr = ([1; 16], U16::new(1111));
	const DST: Addr = ([2; 16], U16::new(2222));

	/// An in-memory datagram BIO for the DTLS *client* side of the tests: one
	/// incoming datagram per read, one outgoing datagram per write.
	#[derive(Default)]
	struct TestBio {
		incoming: VecDeque<Vec<u8>>,
		outgoing: Vec<Vec<u8>>,
	}
	impl TestBio {
		fn feed(&mut self, datagram: &[u8]) {
			self.incoming.push_back(datagram.to_vec());
		}
	}
	impl Read for TestBio {
		fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
			match self.incoming.pop_front() {
				Some(datagram) => {
					let len = datagram.len().min(buf.len());
					buf[..len].copy_from_slice(&datagram[..len]);
					Ok(len)
				}
				None => Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "")),
			}
		}
	}
	impl Write for TestBio {
		fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
			self.outgoing.push(buf.to_vec());
			Ok(buf.len())
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}

	/// A handshake step on the [`Handshake`] server that must not be fatal.
	fn want_read_io(res: SslIo) {
		assert!(
			matches!(res, SslIo::WantRead),
			"expected WANT_READ from server"
		);
	}
	fn is_fatal_io(res: SslIo) -> bool {
		matches!(res, SslIo::Fatal | SslIo::Syscall(_) | SslIo::ZeroReturn)
	}

	fn server_ctx() -> SslContext {
		let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
		let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
		let mut cert = X509::builder().unwrap();
		cert.set_version(2).unwrap();
		cert.set_pubkey(&key).unwrap();
		cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
			.unwrap();
		cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
			.unwrap();
		cert.sign(&key, MessageDigest::sha256()).unwrap();
		let cert = cert.build();

		let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
		ctx.set_certificate(&cert).unwrap();
		ctx.set_private_key(&key).unwrap();
		configure(&mut ctx);
		ctx.build()
	}

	/// `mtu` forces the client to fragment its ClientHello like Chrome does
	fn client(mtu: Option<u32>) -> SslStream<TestBio> {
		let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
		ctx.set_verify(SslVerifyMode::NONE);
		if mtu.is_some() {
			ctx.set_options(SslOptions::NO_QUERY_MTU);
		}
		let ctx = ctx.build();
		let mut ssl = Ssl::new(&ctx).unwrap();
		// Bloat the ClientHello so a small MTU actually fragments it
		ssl.set_hostname(&"padding.".repeat(20)).unwrap();
		if let Some(mtu) = mtu {
			ssl.set_mtu(mtu).unwrap();
		}
		ssl.set_connect_state();
		SslStream::new(ssl, TestBio::default()).unwrap()
	}

	fn want_read<T>(res: Result<T, openssl::ssl::Error>) {
		match res {
			Err(e) if e.code() == ErrorCode::WANT_READ => {}
			Err(e) => panic!("fatal: {e:?}"),
			Ok(_) => panic!("finished early"),
		}
	}

	/// Drive a client through the stateless HelloVerify round and return its
	/// retry flight.  The first flight is fragmented too (a custom BIO can't
	/// answer MTU queries, so OpenSSL falls back to its minimum), and only its
	/// fragment 0 draws a HelloVerifyRequest.
	fn verify_retry(keys: &Keys, client: &mut SslStream<TestBio>) -> Vec<Vec<u8>> {
		want_read(client.do_handshake());
		let flight = std::mem::take(&mut client.get_mut().outgoing);
		let mut hvr = None;
		for (i, datagram) in flight.iter().enumerate() {
			match keys.inspect(SRC, DST, datagram) {
				Verdict::HelloVerify(h) if i == 0 => hvr = Some(h),
				Verdict::Drop if i > 0 => {}
				_ => panic!("wrong verdict for first-flight datagram {i}"),
			}
		}
		client.get_mut().feed(hvr.unwrap().as_bytes());
		want_read(client.do_handshake());
		std::mem::take(&mut client.get_mut().outgoing)
	}

	fn pump(client: &mut SslStream<TestBio>, server: &mut Handshake) {
		for _round in 0..10 {
			if client.ssl().is_init_finished() && server.is_finished() {
				return;
			}
			for datagram in server.drain_output() {
				client.get_mut().feed(&datagram);
			}
			let _ = client.do_handshake();
			for datagram in std::mem::take(&mut client.get_mut().outgoing) {
				server.feed(&datagram);
			}
			let _ = server.do_handshake();
		}
		panic!("handshake did not complete");
	}

	/// The full Chrome-shaped flow: fragmented hello -> stateless verify ->
	/// promote on fragment 0 -> reassembly -> handshake -> application data
	#[test]
	fn fragmented_handshake() {
		let keys = Keys::generate().unwrap();
		let ctx = server_ctx();

		let mut client = client(Some(256));
		let flight = verify_retry(&keys, &mut client);
		assert!(flight.len() > 1, "retry did not fragment");

		// Valid cookie: promote on fragment 0, feed the rest like the
		// Entry::Occupied path (over the connected socket) would
		let mut server = None;
		for (i, datagram) in flight.iter().enumerate() {
			match keys.inspect(SRC, DST, datagram) {
				Verdict::Accept(verified) if i == 0 => {
					server = Some(promote(&ctx, &verified).unwrap());
				}
				Verdict::Drop if i > 0 => {
					let server = server.as_mut().unwrap();
					server.feed(datagram);
					want_read_io(server.do_handshake());
				}
				_ => panic!("wrong verdict for retry datagram {i}"),
			}
		}
		let mut server = server.unwrap();

		pump(&mut client, &mut server);

		// And application data flows
		client.ssl_write(b"ping").unwrap();
		for datagram in std::mem::take(&mut client.get_mut().outgoing) {
			server.feed(&datagram);
		}
		let mut buf = [0; 64];
		let SslIo::Ok(len) = server.read(&mut buf) else {
			panic!("server did not read application data");
		};
		assert_eq!(&buf[..len], b"ping");
	}

	/// The promote -> cutover BIO-ownership dance: swap the in-memory pair for a
	/// real fd-backed dgram BIO and tear everything down without a double free.
	#[test]
	fn promote_then_cutover() {
		use std::os::fd::AsRawFd;

		let keys = Keys::generate().unwrap();
		let ctx = server_ctx();

		let mut client = client(None);
		let flight = verify_retry(&keys, &mut client);
		let Verdict::Accept(verified) = keys.inspect(SRC, DST, &flight[0]) else {
			panic!("expected accept");
		};

		let hs = promote(&ctx, &verified).unwrap();
		// Drain any ServerHello flight before cutover, like production does.
		let _ = hs.drain_output();

		// A connected UDP socket for the dgram BIO to borrow (no real handshake).
		let sock = std::net::UdpSocket::bind("[::1]:0").unwrap();
		let addr = sock.local_addr().unwrap();
		sock.connect(addr).unwrap();

		let ssl = hs.into_established(sock.as_raw_fd()).unwrap();
		// Drop order: Ssl frees the dgram BIO (BIO_NOCLOSE, fd untouched), then the
		// socket closes the fd.
		drop(ssl);
		drop(sock);
	}

	/// Cookies are bound to both src and dst
	#[test]
	fn cookie_binds_addresses() {
		let keys = Keys::generate().unwrap();

		let mut client = client(None);
		let flight = verify_retry(&keys, &mut client);
		let retry = &flight[0];

		assert!(matches!(keys.inspect(SRC, DST, retry), Verdict::Accept(_)));
		// Replay from elsewhere, or to another destination: back to verification
		let other = ([3; 16], U16::new(3333));
		assert!(matches!(
			keys.inspect(other, DST, retry),
			Verdict::HelloVerify(_)
		));
		assert!(matches!(
			keys.inspect(SRC, other, retry),
			Verdict::HelloVerify(_)
		));
		// A different key (e.g. a restarted server): not accepted either
		let fresh = Keys::generate().unwrap();
		assert!(matches!(
			fresh.inspect(SRC, DST, retry),
			Verdict::HelloVerify(_)
		));
	}

	/// Even if the stateless parse were somehow fooled, OpenSSL's cookie
	/// callbacks re-verify: promotion with a cookie that doesn't match the
	/// hello's fails instead of creating usable state
	#[test]
	fn promote_rejects_mismatch() {
		let keys = Keys::generate().unwrap();
		let ctx = server_ctx();

		let mut client = client(None);
		let flight = verify_retry(&keys, &mut client);

		let Verdict::Accept(mut verified) = keys.inspect(SRC, DST, &flight[0]) else {
			panic!("expected accept");
		};
		verified.cookie[0] ^= 1;
		match promote(&ctx, &verified) {
			// Unfragmented hello: rejected inside promote
			Err(_) => {}
			// Fragmented hello: the cookie is re-checked when reassembly
			// completes, before any handshake progress
			Ok(mut server) => {
				let fatal = flight[1..].iter().any(|datagram| {
					server.feed(datagram);
					is_fatal_io(server.do_handshake())
				});
				assert!(fatal, "mismatched cookie was accepted");
				assert!(!server.is_finished());
			}
		}
	}

	#[test]
	fn junk_dropped() {
		let keys = Keys::generate().unwrap();
		assert!(matches!(keys.inspect(SRC, DST, b""), Verdict::Drop));
		assert!(matches!(
			keys.inspect(SRC, DST, b"GET / HTTP/1.1"),
			Verdict::Drop
		));
		// STUN magic doesn't parse as DTLS
		assert!(matches!(
			keys.inspect(
				SRC,
				DST,
				&[
					0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
				]
			),
			Verdict::Drop
		));
	}
}
