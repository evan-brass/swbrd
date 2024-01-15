use std::{time::{SystemTime, Duration}, ops::Add, collections::HashMap};
use base64::prelude::*;

use eyre::Result;
use tokio::net::UdpSocket;
use webrtc::{api::setting_engine::SettingEngine, ice::udp_mux::{UDPMuxParams, UDPMuxDefault}, stun::{message::{Message, METHOD_BINDING, CLASS_REQUEST, MessageType}, textattrs::TextAttribute, attributes::ATTR_USERNAME}, peer_connection::{certificate::RTCCertificate, configuration::RTCConfiguration}};
use webrtc_dtls::crypto::Certificate;

#[tokio::main]
async fn main() -> Result<()> {
	// Listen for broadcasts on :3478/udp
	let sock = UdpSocket::bind("0.0.0.0:3478").await?;

	// Configure a WebRTC api
	let mut settings = SettingEngine::default();
	settings.set_udp_network(webrtc::ice::udp_network::UDPNetwork::Muxed(
		UDPMuxDefault::new(UDPMuxParams::new(
			// TODO: Pick a port here, and also EXPOSE that port so that we can kick off the TURN server while keeping the connection
			UdpSocket::bind("0.0.0.0:80").await?
		))
	));
	settings.set_lite(true);

	// Get our own certificate and its prints

	let cert = Certificate::generate_self_signed(vec!["Switchboard Bind Server".into()])?;
	let rtc_cert = RTCCertificate::from_existing(cert, SystemTime::now().add(Duration::from_secs(9000)));
	let own_ids: Vec<String> = rtc_cert.get_fingerprints()
		.iter()
		.map(|f| Vec::from_iter(f.value.split(':').map(|s| u8::from_str_radix(s, 16).unwrap())))
		.map(|bytes| base64::prelude::Engine::encode(&BASE64_URL_SAFE_NO_PAD, bytes))
		.collect();
	println!("{own_ids:?}");

	let api = webrtc::api::APIBuilder::new()
		.with_setting_engine(settings)
		.build();

	// Store a map of id strings -> RTCPeerConnections
	let mut conns = HashMap::new();
	let mut pc_config = RTCConfiguration::default();
	pc_config.certificates = vec![rtc_cert];

	// Parse broadcasted connection tests
	let mut buf = [0u8; 1024];
	let mut msg = Message::new();
	loop {
		let sender = tokio::select! {
			Ok((read, sender)) = sock.recv_from(&mut buf) => {
				match msg.unmarshal_binary(&buf[..read]) {
					Ok(_) => sender,
					Err(e) => { eprint!("{e}"); continue }
				}
			},
			_ = tokio::signal::ctrl_c() => return Ok(()),
			else => continue
		};
		if (msg.typ != MessageType { method: METHOD_BINDING, class: CLASS_REQUEST}) { continue }
		let Ok(username) = TextAttribute::get_from_as(&msg, ATTR_USERNAME) else { continue };
		let Some((dst, src)) = username.text.split_once(':') else { continue };

		println!("{sender}:{src}->{dst}");
		
		// Check if this is a connection test for us (and we don't already have a PeerConnection for this peer)
		if own_ids.iter().any(|id| id == dst) && conns.get(src).is_none() {
			let conn = api.new_peer_connection(pc_config.clone()).await?;
			conn.

			// TODO: Signal the connection

			conns.insert(src.to_string(), conn);
		}
		// Check if this a connection test for a peer with whom we have an RTCPeerConnection
		else if let Some(_pc) = conns.get(dst) {
			// TODO: Tell the peer that someone is trying to connect to them
		}
	}
}
