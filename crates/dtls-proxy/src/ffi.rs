//! The unsafe boundary: driving an owned [`Ssl`] over native OpenSSL BIOs.
//!
//! The `openssl` crate's `SslStream<S>` owns its `Ssl` privately (a
//! `ManuallyDrop` with no extraction path) and installs its own memory-bridge
//! BIO — it can neither hand the `Ssl` back nor let us swap in OpenSSL's
//! fd-backed dgram BIO.  `SslRef` exposes no read/write/do_handshake either.  So
//! once a connection's cookie handshake is caught up we own the `Ssl` outright
//! and drive it through these raw wrappers: a datagram-preserving in-memory BIO
//! pair for the cookie seed ([`cookie`](crate::cookie)), then a cutover to
//! [`attach_dgram`] over the connected transparent socket.

use std::{io, os::fd::RawFd};

use foreign_types::ForeignType;
use libc::{c_int, c_void};
use openssl::ssl::Ssl;
use openssl_sys::{
	BIO, BIO_free_all, BIO_new_bio_dgram_pair, BIO_read, BIO_write, SSL, SSL_ERROR_NONE,
	SSL_ERROR_SYSCALL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN,
	SSL_do_handshake, SSL_get_error, SSL_read, SSL_set_bio, SSL_write,
};

// Not declared by openssl-sys, but present in the linked libcrypto/libssl
// (exported since OPENSSL_3.0.0).
unsafe extern "C" {
	fn BIO_new_dgram(fd: c_int, close_flag: c_int) -> *mut BIO;
	fn DTLS_get_data_mtu(ssl: *const SSL) -> usize;
}

const BIO_NOCLOSE: c_int = 0;
/// Per-end write buffer for the cookie-phase BIO pair; a handshake flight
/// fragmented at the minimum MTU stays well under this.
const PAIR_BUF: usize = 1 << 16;

/// Outcome of a raw SSL I/O call, classified via `SSL_get_error`.
pub enum SslIo {
	/// `SSL_read`/`SSL_write` moved this many bytes; a handshake step reports `Ok(0)`.
	Ok(usize),
	WantRead,
	WantWrite,
	/// Peer sent close_notify.
	ZeroReturn,
	/// `SSL_ERROR_SYSCALL`: the underlying BIO's syscall failed; errno captured
	/// so callers can match `raw_os_error()` (e.g. `ECONNREFUSED`, `EMSGSIZE`).
	Syscall(io::Error),
	/// A fatal protocol error (`SSL_ERROR_SSL` and friends).
	Fatal,
}

fn classify(ssl: *mut SSL, ret: c_int) -> SslIo {
	if ret > 0 {
		return SslIo::Ok(ret as usize);
	}
	match unsafe { SSL_get_error(ssl, ret) } {
		SSL_ERROR_NONE => SslIo::Ok(0),
		SSL_ERROR_WANT_READ => SslIo::WantRead,
		SSL_ERROR_WANT_WRITE => SslIo::WantWrite,
		SSL_ERROR_ZERO_RETURN => SslIo::ZeroReturn,
		SSL_ERROR_SYSCALL => SslIo::Syscall(io::Error::last_os_error()),
		_ => SslIo::Fatal,
	}
}

pub fn do_handshake(ssl: &mut Ssl) -> SslIo {
	let p = ssl.as_ptr();
	classify(p, unsafe { SSL_do_handshake(p) })
}

pub fn read(ssl: &mut Ssl, buf: &mut [u8]) -> SslIo {
	let p = ssl.as_ptr();
	let len = buf.len().min(c_int::MAX as usize) as c_int;
	classify(p, unsafe {
		SSL_read(p, buf.as_mut_ptr().cast::<c_void>(), len)
	})
}

pub fn write(ssl: &mut Ssl, buf: &[u8]) -> SslIo {
	let p = ssl.as_ptr();
	let len = buf.len().min(c_int::MAX as usize) as c_int;
	classify(p, unsafe {
		SSL_write(p, buf.as_ptr().cast::<c_void>(), len)
	})
}

/// Application-data bytes that fit in one DTLS record at the current link MTU.
pub fn data_mtu(ssl: &Ssl) -> usize {
	unsafe { DTLS_get_data_mtu(ssl.as_ptr().cast_const()) }
}

/// A datagram-preserving in-memory BIO pair.  One end is attached to an `Ssl`
/// (via [`set_bio`]); the other ([`Self::app`]) is written/read by us to inject
/// and extract whole datagrams during the cookie seed — DTLS needs datagram
/// boundaries, which a plain `BIO_s_mem` would not preserve.
pub struct BioPair {
	/// Handed to the `Ssl`; ownership transfers on [`set_bio`] / [`attach_dgram`].
	ssl_end: *mut BIO,
	/// Our end; must be freed with [`Self::free_app`].
	app: *mut BIO,
}

impl BioPair {
	pub fn new() -> Option<Self> {
		let mut ssl_end: *mut BIO = std::ptr::null_mut();
		let mut app: *mut BIO = std::ptr::null_mut();
		let rc = unsafe { BIO_new_bio_dgram_pair(&mut ssl_end, PAIR_BUF, &mut app, PAIR_BUF) };
		if rc != 1 || ssl_end.is_null() || app.is_null() {
			return None;
		}
		Some(Self { ssl_end, app })
	}

	/// Write one datagram into our end (the `Ssl` will read it).
	pub fn feed(&self, datagram: &[u8]) {
		let len = datagram.len().min(c_int::MAX as usize) as c_int;
		unsafe { BIO_write(self.app, datagram.as_ptr().cast::<c_void>(), len) };
	}

	/// Drain the datagrams the `Ssl` has written into the pair, in order, one
	/// `Vec` per datagram (the dgram-pair BIO returns one datagram per read, and
	/// callers must preserve those boundaries when re-sending).
	pub fn drain(&self) -> Vec<Vec<u8>> {
		let mut out = Vec::new();
		let mut buf = [0u8; PAIR_BUF];
		loop {
			let n = unsafe {
				BIO_read(
					self.app,
					buf.as_mut_ptr().cast::<c_void>(),
					buf.len() as c_int,
				)
			};
			if n <= 0 {
				break;
			}
			out.push(buf[..n as usize].to_vec());
		}
		out
	}
}

impl Drop for BioPair {
	/// Free our end of the pair.  The `ssl_end` is owned by the `Ssl` (handed
	/// over by [`set_bio`], freed on `SSL_free` or the next `SSL_set_bio`); the
	/// two ends of a BIO pair free independently.
	fn drop(&mut self) {
		if !self.app.is_null() {
			unsafe { BIO_free_all(self.app) };
			self.app = std::ptr::null_mut();
		}
	}
}

/// Attach the pair's `ssl_end` to `ssl` as both read and write BIO.  Ownership
/// of `ssl_end` passes to the `Ssl`.
pub fn set_bio(ssl: &mut Ssl, pair: &BioPair) {
	unsafe { SSL_set_bio(ssl.as_ptr(), pair.ssl_end, pair.ssl_end) };
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{
		net::{Ipv6Addr, SocketAddrV6},
		os::fd::AsRawFd,
	};

	use socket2::{Domain, Protocol, Socket, Type};

	/// Does `BIO_new_dgram` over an OS-connected UDP socket send correctly
	/// without any explicit connected/peer ctrl?  (On Linux `sendto` with an
	/// address on a connected socket is `EISCONN`, so this probes whether the
	/// dgram BIO uses a plain `send`.)
	#[test]
	fn dgram_bio_write_on_connected_socket() {
		let a = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
		let b = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
		let lo = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
		a.bind(&lo.into()).unwrap();
		b.bind(&lo.into()).unwrap();
		let a_addr = a.local_addr().unwrap();
		let b_addr = b.local_addr().unwrap();
		a.connect(&b_addr).unwrap();
		b.connect(&a_addr).unwrap();

		let bio = unsafe { BIO_new_dgram(a.as_raw_fd(), BIO_NOCLOSE) };
		assert!(!bio.is_null());

		let n = unsafe { BIO_write(bio, b"hello".as_ptr().cast::<c_void>(), 5) };
		assert_eq!(
			n,
			5,
			"BIO_write failed: {}",
			std::io::Error::last_os_error()
		);

		let mut buf = [std::mem::MaybeUninit::new(0u8); 16];
		let got = b.recv(&mut buf).unwrap();
		assert_eq!(got, 5);

		// The handshake ordering: a BIO_read (recvfrom, which records the peer)
		// precedes the write.  Ensure a write still succeeds afterwards — i.e.
		// the BIO does not switch to sendto() and hit EISCONN on the connected fd.
		b.send(b"world").unwrap();
		let mut rbuf = [0u8; 16];
		let r = unsafe { BIO_read(bio, rbuf.as_mut_ptr().cast::<c_void>(), rbuf.len() as c_int) };
		assert_eq!(r, 5, "BIO_read failed: {}", std::io::Error::last_os_error());
		assert_eq!(&rbuf[..5], b"world");

		let n = unsafe { BIO_write(bio, b"again".as_ptr().cast::<c_void>(), 5) };
		assert_eq!(
			n,
			5,
			"BIO_write after read failed: {}",
			std::io::Error::last_os_error()
		);
		assert_eq!(b.recv(&mut buf).unwrap(), 5);

		unsafe { BIO_free_all(bio) };
	}
}

/// Replace the SSL's BIO with a fresh fd-backed dgram BIO, freeing whatever was
/// attached before (the cookie-phase pair's `ssl_end`).  `BIO_NOCLOSE` keeps the
/// BIO from ever closing `fd` — the caller's `socket2::Socket` owns it.  Returns
/// false if the BIO could not be created.
pub fn attach_dgram(ssl: &mut Ssl, fd: RawFd) -> bool {
	let bio = unsafe { BIO_new_dgram(fd as c_int, BIO_NOCLOSE) };
	if bio.is_null() {
		return false;
	}
	unsafe { SSL_set_bio(ssl.as_ptr(), bio, bio) };
	true
}
