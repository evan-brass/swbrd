use std::net::SocketAddr;

use eyre::Result;

fn main() -> Result<()> {
	let sock = std::net::UdpSocket::bind("[::]:3478")?;

	let mut buffer = [0; 4096];
	loop {
		let Ok((packet_length, sender)) = sock.recv_from(&mut buffer) else { continue };
		// Canonicalize the ipv6 ip address
		let sender = match sender {
			SocketAddr::V6(v6) => SocketAddr::new(v6.ip().to_canonical(), v6.port()),
			_ => sender
		};
		let packet = &buffer[..packet_length];
		let msg = stun::Stun::decode(packet, stun::attrs::Unknown::default());
		println!("{sender} {msg:?}");
	}
}
