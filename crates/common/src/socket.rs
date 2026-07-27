//! Socket helpers shared by the socket-side of the proxies (turnserver now,
//! dtls-proxy later).
//!
//! The point of these is connected sockets whose source address is fixed at
//! bind/connect time, plus the two message-based helpers needed to answer off an
//! *unconnected* wildcard socket from the correct local address.  We drive
//! `recvmsg`/`sendmsg` through nix (its `ControlMessageOwned` iterator parses the
//! `IPV6_PKTINFO` cmsg for us) on the raw fd of a `socket2::Socket`.

use core::mem::MaybeUninit;
use std::{
	io::{self, IoSlice, IoSliceMut},
	net::{Ipv6Addr, SocketAddrV6},
	os::fd::AsRawFd,
};

use nix::{
	libc,
	sys::socket::{
		ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg, sendmsg, setsockopt,
		sockopt,
	},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Which non-default option a forked connected UDP socket wants.  turnserver
/// needs `SO_REUSEPORT` so its per-client sockets can share `:3478` with the
/// wildcard socket; dtls-proxy needs `IP_TRANSPARENT` so it can bind to / send
/// from the non-local addresses that show up in TUN packets.
#[derive(Clone, Copy, Debug)]
pub enum UdpOpt {
	ReusePort,
	Transparent,
}

/// Enable `IPV6_RECVPKTINFO` so `recv_with_local` can recover the local address
/// each datagram was sent to.  Call once on the wildcard UDP socket.
pub fn set_recv_pktinfo(sock: &Socket) -> io::Result<()> {
	setsockopt(sock, sockopt::Ipv6RecvPacketInfo, &true).map_err(io::Error::from)
}

/// Receive one datagram, reporting both the client's transport address (`remote`)
/// and the local address it was sent to (`local`, from the `IPV6_PKTINFO` cmsg).
/// The socket must be dual-stack with `IPV6_RECVPKTINFO` enabled
/// ([`set_recv_pktinfo`]); v4 clients arrive v4-mapped and still carry pktinfo.
pub fn recv_with_local(
	sock: &Socket,
	buf: &mut [u8],
) -> io::Result<(usize, SocketAddrV6, Ipv6Addr)> {
	let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
	let mut iov = [IoSliceMut::new(buf)];
	let msg = recvmsg::<SockaddrIn6>(
		sock.as_raw_fd(),
		&mut iov,
		Some(&mut cmsg),
		MsgFlags::empty(),
	)
	.map_err(io::Error::from)?;

	let remote = msg
		.address
		.map(SocketAddrV6::from)
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recvmsg: no source address"))?;

	let mut local = Ipv6Addr::UNSPECIFIED;
	for c in msg.cmsgs().map_err(io::Error::from)? {
		if let ControlMessageOwned::Ipv6PacketInfo(pi) = c {
			local = Ipv6Addr::from(pi.ipi6_addr.s6_addr);
		}
	}

	Ok((msg.bytes, remote, local))
}

/// Send `buf` to `to` from local address `local`, off an *unconnected* socket.
/// Used for stateless Binding replies on the wildcard socket so the reply's
/// source IP matches the address the request was sent to.
pub fn send_from(sock: &Socket, local: Ipv6Addr, to: SocketAddrV6, buf: &[u8]) -> io::Result<usize> {
	let pi = libc::in6_pktinfo {
		ipi6_addr: libc::in6_addr {
			s6_addr: local.octets(),
		},
		ipi6_ifindex: 0,
	};
	let cmsgs = [ControlMessage::Ipv6PacketInfo(&pi)];
	let iov = [IoSlice::new(buf)];
	let addr = SockaddrIn6::from(to);
	sendmsg(
		sock.as_raw_fd(),
		&iov,
		&cmsgs,
		MsgFlags::empty(),
		Some(&addr),
	)
	.map_err(io::Error::from)
}

/// Build a connected, nonblocking, dual-stack UDP socket bound to `local` and
/// connected to `remote`.  The connected 4-tuple outscores a wildcard socket in
/// the kernel UDP demux, so this flow is delivered here while unknown flows keep
/// hitting the wildcard.
pub fn connected_udp(
	local: SocketAddrV6,
	remote: SocketAddrV6,
	opt: UdpOpt,
) -> io::Result<Socket> {
	let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
	sock.set_only_v6(false)?;
	sock.set_reuse_address(true)?;
	match opt {
		UdpOpt::ReusePort => sock.set_reuse_port(true)?,
		UdpOpt::Transparent => setsockopt(&sock, sockopt::IpTransparent, &true).map_err(io::Error::from)?,
	}
	sock.bind(&SockAddr::from(local))?;
	sock.connect(&SockAddr::from(remote))?;
	sock.set_nonblocking(true)?;
	Ok(sock)
}

/// Re-point an already-connected UDP socket at a new peer, keeping its bound
/// local address, fd, and sockopts (`IP_TRANSPARENT`, PMTUDISC) intact.  Used
/// for DTLS client mobility: when an authenticated record arrives from a roamed
/// source, the connection's socket is re-`connect`ed so both the kernel demux
/// and the borrowed dgram BIO's `send`/`recv` follow the client to its new
/// address.  Only the kernel's discovered PMTU resets for the new path.
pub fn reconnect(sock: &Socket, remote: SocketAddrV6) -> io::Result<()> {
	sock.connect(&SockAddr::from(remote))
}

/// Enable IPv6 path-MTU discovery (`IPV6_PMTUDISC_DO`) so an oversized send
/// fails with `EMSGSIZE` instead of being fragmented, and the kernel records the
/// discovered PMTU (readable via [`v6_path_mtu`]).  dtls-proxy sets this on each
/// connected transparent socket so it can react to a shrinking client path.
pub fn set_v6_pmtudisc(sock: &Socket) -> io::Result<()> {
	let val: libc::c_int = libc::IPV6_PMTUDISC_DO;
	let rc = unsafe {
		libc::setsockopt(
			sock.as_raw_fd(),
			libc::IPPROTO_IPV6,
			libc::IPV6_MTU_DISCOVER,
			(&val as *const libc::c_int).cast(),
			size_of::<libc::c_int>() as libc::socklen_t,
		)
	};
	if rc != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

/// The IPv6 path MTU the kernel has discovered for this connected socket
/// (`IPV6_MTU`) — e.g. the value carried by a received ICMPv6 Packet Too Big.
pub fn v6_path_mtu(sock: &Socket) -> io::Result<u32> {
	let mut val: libc::c_int = 0;
	let mut len = size_of::<libc::c_int>() as libc::socklen_t;
	let rc = unsafe {
		libc::getsockopt(
			sock.as_raw_fd(),
			libc::IPPROTO_IPV6,
			libc::IPV6_MTU,
			(&mut val as *mut libc::c_int).cast(),
			&mut len,
		)
	};
	if rc != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(val as u32)
}

/// IPv4 counterpart of [`set_v6_pmtudisc`] (`IP_PMTUDISC_DO`).  Linux governs the
/// two families independently, so a dual-stack socket that may send to v4-mapped
/// clients must set this too — the v6 option does not cover the IPv4 send path.
pub fn set_v4_pmtudisc(sock: &Socket) -> io::Result<()> {
	let val: libc::c_int = libc::IP_PMTUDISC_DO;
	let rc = unsafe {
		libc::setsockopt(
			sock.as_raw_fd(),
			libc::IPPROTO_IP,
			libc::IP_MTU_DISCOVER,
			(&val as *const libc::c_int).cast(),
			size_of::<libc::c_int>() as libc::socklen_t,
		)
	};
	if rc != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

/// IPv4 counterpart of [`v6_path_mtu`] (`IP_MTU`) — the discovered path MTU for a
/// connected socket sending over IPv4 (including a v4-mapped dual-stack socket).
pub fn v4_path_mtu(sock: &Socket) -> io::Result<u32> {
	let mut val: libc::c_int = 0;
	let mut len = size_of::<libc::c_int>() as libc::socklen_t;
	let rc = unsafe {
		libc::getsockopt(
			sock.as_raw_fd(),
			libc::IPPROTO_IP,
			libc::IP_MTU,
			(&mut val as *mut libc::c_int).cast(),
			&mut len,
		)
	};
	if rc != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(val as u32)
}

/// `MSG_PEEK` into an initialized `&mut [u8]`, returning how many bytes are
/// available without consuming them. Wraps socket2's `MaybeUninit`-typed `peek`;
/// only the initialized prefix is ever read back, so the cast is sound.
pub fn peek(sock: &Socket, buf: &mut [u8]) -> io::Result<usize> {
	let uninit =
		unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<MaybeUninit<u8>>(), buf.len()) };
	sock.peek(uninit)
}

/// How many more bytes can be handed to the kernel for this TCP socket right now:
/// `SO_SNDBUF` minus the bytes still queued (`SIOCOUTQ`) minus a safety margin.
/// Callers use this to decide whether a whole STUN frame fits before writing —
/// there is no partial-write buffer, so a frame that does not fit is dropped.
pub fn tcp_send_space(sock: &Socket) -> io::Result<usize> {
	const MARGIN: usize = 2048;
	let sndbuf = sock.send_buffer_size()?;
	let mut outq: libc::c_int = 0;
	// SIOCOUTQ == TIOCOUTQ (0x5411) on Linux: unsent bytes in the send queue.
	let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::TIOCOUTQ as _, &mut outq) };
	if rc != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(sndbuf
		.saturating_sub(outq as usize)
		.saturating_sub(MARGIN))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// `reconnect` re-points a connected UDP socket at a new peer: sends and
	/// receives follow the client to its new address, and the old peer no longer
	/// receives.
	#[test]
	fn reconnect_follows_new_peer() {
		let lo = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
		let a = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
		let b1 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
		let b2 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
		a.bind(&lo.into()).unwrap();
		b1.bind(&lo.into()).unwrap();
		b2.bind(&lo.into()).unwrap();
		let b1_addr = to_v6(b1.local_addr().unwrap());
		let b2_addr = to_v6(b2.local_addr().unwrap());

		a.connect(&SockAddr::from(b1_addr)).unwrap();
		a.send(b"one").unwrap();
		let mut buf = [MaybeUninit::new(0u8); 16];
		assert_eq!(b1.recv(&mut buf).unwrap(), 3);

		reconnect(&a, b2_addr).unwrap();
		a.send(b"two").unwrap();
		assert_eq!(b2.recv(&mut buf).unwrap(), 3);

		// The old peer gets nothing more.
		b1.set_nonblocking(true).unwrap();
		assert!(b1.recv(&mut buf).is_err());
	}

	fn to_v6(addr: SockAddr) -> SocketAddrV6 {
		match addr.as_socket().unwrap() {
			std::net::SocketAddr::V6(v6) => v6,
			other => panic!("expected v6, got {other}"),
		}
	}
}
