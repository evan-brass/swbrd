use eyre::Result;
use tokio_stream::StreamExt;

pub mod stun;

#[tokio::main]
async fn main() -> Result<()> {
	let sock = tokio::net::UdpSocket::bind("[::]:3478").await?;
	let mut framed = tokio_util::udp::UdpFramed::new(sock, stun::StunCodec::default());
	while let Some(frame) = framed.next().await {
		println!("{frame:?}");
	}
	Ok(())
}
