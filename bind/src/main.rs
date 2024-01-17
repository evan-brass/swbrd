use base64::prelude::*;
use std::fmt::Write;
use std::sync::Arc;
use std::{
	collections::HashMap,
	ops::Add,
	sync::RwLock,
	time::{Duration, SystemTime},
};
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use eyre::Result;
use tokio::net::UdpSocket;
use webrtc::{
	api::setting_engine::SettingEngine,
	dtls_transport::dtls_role::DTLSRole,
	// ice::udp_mux::{UDPMuxDefault, UDPMuxParams},
	peer_connection::certificate::RTCCertificate,
	stun::{
		attributes::ATTR_USERNAME,
		message::{Message, MessageType, CLASS_REQUEST, METHOD_BINDING},
		textattrs::TextAttribute,
	},
};
use webrtc_dtls::crypto::Certificate;

#[tokio::main]
async fn main() -> Result<()> {
	// Listen for broadcasts on :3478/udp
	let sock = UdpSocket::bind("0.0.0.0:3478").await?;

	// Get our own certificate and its prints
	let cert = Certificate::generate_self_signed(vec!["Switchboard Bind Server".into()])?;
	let rtc_cert =
		RTCCertificate::from_existing(cert, SystemTime::now().add(Duration::from_secs(9000)));
	let own_ids: Vec<String> = rtc_cert
		.get_fingerprints()
		.iter()
		.map(|f| {
			Vec::from_iter(
				f.value
					.split(':')
					.map(|s| u8::from_str_radix(s, 16).unwrap()),
			)
		})
		.map(|bytes| base64::prelude::Engine::encode(&BASE64_URL_SAFE_NO_PAD, bytes))
		.collect();
	println!("{own_ids:?}");

	// Configure a WebRTC api
	let mut settings = SettingEngine::default();
	// settings.set_udp_network(webrtc::ice::udp_network::UDPNetwork::Muxed(
	// 	UDPMuxDefault::new(UDPMuxParams::new(UdpSocket::bind("0.0.0.0:80").await?)),
	// ));
	settings.set_ice_credentials(
		own_ids.get(0).unwrap().into(),
		"the/ice/password/constant".into(),
	);
	settings.set_answering_dtls_role(DTLSRole::Server)?;

	// Create an API that we can use to answer connections
	let api = webrtc::api::APIBuilder::new()
		.with_setting_engine(settings)
		.build();

	// Store a map of id strings -> RTCPeerConnections
	let mut conns = HashMap::new();
	let dcs = Arc::new(RwLock::new(HashMap::new()));

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
			_ = tokio::signal::ctrl_c() => return Ok(()), // TODO: close all open RTCPeerConnections?
			else => continue
		};
		if (msg.typ
			!= MessageType {
				method: METHOD_BINDING,
				class: CLASS_REQUEST,
			}) {
			continue;
		}
		let Ok(username) = TextAttribute::get_from_as(&msg, ATTR_USERNAME) else {
			continue;
		};
		let Some((dst, src)) = username.text.split_once(':') else {
			continue;
		};

		println!("{sender}:{src}->{dst}");

		if src.contains('"') || dst.contains('"') {
			// TODO: Make sure that the src and dst are JSON string safe
			continue;
		}

		// Check if this is a connection test for us (and we don't already have a PeerConnection for this peer)
		if own_ids.iter().any(|id| id == dst) && conns.get(src).is_none() {
			let Ok(fingerprint) = base64::Engine::decode(&BASE64_URL_SAFE_NO_PAD, &src) else {
				continue;
			};
			if fingerprint.len() != 32 {
				continue;
			}
			let mut fingerprint_sdp = "a=fingerprint:sha-256 ".to_string();
			for (i, b) in fingerprint.iter().enumerate() {
				if i != 0 {
					fingerprint_sdp.push(':');
				}
				fingerprint_sdp.write_fmt(format_args!("{b:02X}"))?;
			}

			println!("Answering this connection");

			// Create a connection and answer the connection
			let conn = api
				.new_peer_connection(RTCConfiguration {
					certificates: vec![rtc_cert.clone()],
					..Default::default()
				})
				.await?;

			// Add a handler to receive incoming datachannels
			conn.on_data_channel({
				let dcs = dcs.clone();
				let src = src.to_string();
				Box::new(move |dc| {
					let dcs = dcs.clone();
					let src = src.clone();
					Box::pin(async move {
						println!("incoming datachannel: {}", dc.label());
						if dc.label() != "bind" {
							let _ = dc.close().await;
						} else {
							let mut l = dcs.write().unwrap();
							l.insert(src, dc);
						}
					})
				})
			});

			// Something's fucked, so time to log every error we can find
			conn.on_peer_connection_state_change(Box::new(|state| {
				println!("pc state: {state}");
				Box::pin(std::future::ready(()))
			}));
			conn.sctp().on_error(Box::new(|e| {
				eprintln!("sctp err: {e}");
				Box::pin(std::future::ready(()))
			}));
			println!("dtls local: {:?}", conn.sctp().transport().get_local_parameters());
			conn.sctp().transport().on_state_change(Box::new(|state| {
				println!("dtls state: {state}");
				Box::pin(std::future::ready(()))
			}));
			conn.sctp().transport().ice_transport().on_selected_candidate_pair_change(Box::new(|selected| {
				println!("selected pair: {selected}");
				Box::pin(std::future::ready(()))
			}));
			conn.sctp().transport().ice_transport().on_connection_state_change(Box::new(|state| {
				println!("ice state: {state}");
				Box::pin(std::future::ready(()))
			}));

			// Signal the connection
			let offer_sdp = [
				"v=0",
				"o=- 20 0 IN IP4 0.0.0.0",
				"s=-",
				"t=0 0",
				"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
				&fingerprint_sdp,
				"c=IN IP4 0.0.0.0",
				&format!("a=ice-ufrag:{src}"),
				"a=ice-pwd:the/ice/password/constant",
				&format!(
					"a=candidate:foundation 1 udp 1 {} {} typ host",
					sender.ip(),
					sender.port()
				),
				"a=sctp-port:5000",
				"",
			]
			.join("\n");
			println!("{offer_sdp:#?}");
			conn.set_remote_description(RTCSessionDescription::offer(offer_sdp)?)
			.await?;
			let answer = conn.create_answer(None).await?;
			conn.set_local_description(answer).await?;

			conns.insert(src.to_string(), conn);
			println!("Conn inserted.");
		}
		// Check if this is a connection test for a peer with whom we have a bind datachannel
		else if let Some(dc) = dcs.read().unwrap().get(dst).cloned() {
			let json = format!(
				r#"{{ "src": {{ "ufrag": "{src}", "ip": "{}", "port": {} }}, "dst": "{dst}" }}"#,
				sender.ip(),
				sender.port()
			);
			println!("{json}");
			// Tell the peer that someone is trying to connect to them
			let _ = dc.send_text(json).await;
		}
	}
}
