//! The DTLS half of the switchboard: everything needed to terminate a browser's
//! DTLS connection without ever letting OpenSSL hold per-client state we didn't
//! ask for.
//!
//! Three pieces, in the order a connection meets them:
//!
//! - [`cookie`] answers a first-contact ClientHello statelessly, and is the only
//!   place an [`openssl::ssl::Ssl`] is created.
//! - [`ffi`] drives that owned `Ssl` over native OpenSSL BIOs — an in-memory
//!   datagram pair during the cookie exchange, then a cutover to the trunk's
//!   connected socket.
//! - [`keys`] re-derives the client's write keys so a record arriving from a new
//!   address can be authenticated, which is what makes client mobility safe.
//!
//! [`fingerprint`] is what the rest of the daemon actually wants out of all
//! this: the peer's certificate fingerprint, which *is* its identity.

pub mod cookie;
pub mod ffi;
pub mod fingerprint;
pub mod keys;
