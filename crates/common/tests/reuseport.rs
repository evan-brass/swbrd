//! Linchpin smoke test for the turnserver rewrite (§10.1 of the plan): with a
//! wildcard `[::]:P` UDP socket and a *connected* socket for one client sharing
//! the port via `SO_REUSEPORT`, the client's flow must be delivered to its
//! connected socket (the more-specific 4-tuple wins the kernel UDP demux) while
//! unknown flows keep landing on the wildcard.
#![cfg(target_os = "linux")]

use std::{
	io::ErrorKind,
	net::{Ipv6Addr, SocketAddrV6},
	thread::sleep,
	time::Duration,
};

use common::socket::{UdpOpt, connected_udp, recv_with_local, set_recv_pktinfo};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

fn wildcard() -> (Socket, u16) {
	let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
	s.set_only_v6(false).unwrap();
	s.set_reuse_address(true).unwrap();
	s.set_reuse_port(true).unwrap();
	set_recv_pktinfo(&s).unwrap();
	s.bind(&SockAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
		.unwrap();
	s.set_nonblocking(true).unwrap();
	let port = s.local_addr().unwrap().as_socket_ipv6().unwrap().port();
	(s, port)
}

fn client_to(port: u16) -> Socket {
	let c = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
	c.set_only_v6(false).unwrap();
	c.bind(&SockAddr::from(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)))
		.unwrap();
	c.connect(&SockAddr::from(SocketAddrV6::new(
		Ipv6Addr::LOCALHOST,
		port,
		0,
		0,
	)))
	.unwrap();
	c
}

/// Poll `sock` for up to ~250ms; return the (len, remote, local) of one datagram
/// or `None` if nothing arrived.
fn try_recv(sock: &Socket) -> Option<(usize, SocketAddrV6, Ipv6Addr)> {
	let mut buf = [0u8; 1500];
	for _ in 0..25 {
		match recv_with_local(sock, &mut buf) {
			Ok(v) => return Some(v),
			Err(e) if e.kind() == ErrorKind::WouldBlock => sleep(Duration::from_millis(10)),
			Err(e) => panic!("recv error: {e}"),
		}
	}
	None
}

#[test]
fn reuseport_demux() {
	let (wild, port) = wildcard();

	// First contact: the client's datagram lands on the wildcard socket, and we
	// recover the local address it was sent to via IPV6_PKTINFO.
	let client = client_to(port);
	client.send(b"hello").unwrap();
	let (n, remote, local) = try_recv(&wild).expect("wildcard should get first datagram");
	assert_eq!(n, 5);

	// Fork a connected socket bound to that local address, sharing the port.
	let conn = connected_udp(
		SocketAddrV6::new(local, port, 0, 0),
		remote,
		UdpOpt::ReusePort,
	)
	.expect("connected_udp");

	// Subsequent datagrams from the same client must now demux to the connected
	// socket, NOT the wildcard.
	client.send(b"again").unwrap();
	let on_conn = try_recv(&conn);
	let on_wild = try_recv(&wild);
	assert!(
		on_conn.is_some(),
		"connected socket must receive the established flow"
	);
	assert!(
		on_wild.is_none(),
		"wildcard must NOT receive the connected flow (got {on_wild:?})"
	);

	// A different client (new source port) still hits the wildcard.
	let other = client_to(port);
	other.send(b"newbie").unwrap();
	let on_wild2 = try_recv(&wild);
	assert!(
		on_wild2.is_some(),
		"wildcard must receive an unknown flow's datagram"
	);
}
