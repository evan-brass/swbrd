use base64::prelude::*;
use std::sync::Arc;
use std::{
	collections::HashMap,
	ops::Add,
	sync::RwLock,
	time::{Duration, SystemTime},
};

use eyre::Result;
use tokio::net::UdpSocket;
use webrtc::{
	api::setting_engine::SettingEngine,
	dtls_transport::{
		dtls_fingerprint::RTCDtlsFingerprint, dtls_parameters::DTLSParameters, dtls_role::DTLSRole,
	},
	ice::udp_mux::{UDPMuxDefault, UDPMuxParams},
	ice_transport::{
		ice_candidate::RTCIceCandidate, ice_gatherer::RTCIceGatherOptions,
		ice_parameters::RTCIceParameters, ice_role::RTCIceRole,
	},
	peer_connection::{
		certificate::RTCCertificate, policy::ice_transport_policy::RTCIceTransportPolicy,
	},
	sctp_transport::sctp_transport_capabilities::SCTPTransportCapabilities,
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
	settings.set_udp_network(webrtc::ice::udp_network::UDPNetwork::Muxed(
		UDPMuxDefault::new(UDPMuxParams::new(UdpSocket::bind("0.0.0.0:80").await?)),
	));
	settings.set_lite(true);
	settings.set_ice_credentials(own_ids.get(0).unwrap().into(), "the/ice/password/constant".into());

	// Create an API that we can use to answer connections
	let api = webrtc::api::APIBuilder::new()
		.with_setting_engine(settings)
		.build();
	let gatherer = Arc::new(api.new_ice_gatherer(RTCIceGatherOptions {
		ice_servers: vec![],
		ice_gather_policy: RTCIceTransportPolicy::All,
	})?);

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
			_ = tokio::signal::ctrl_c() => return Ok(()),
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

		if src.contains('"') || dst.contains('"') { // TODO: Make sure that the src and dst are JSON string safe
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
			let fingerprint = {
				use std::fmt::Write;
				let mut value = String::new();
				for (i, b) in fingerprint.iter().enumerate() {
					if i != 0 { value.push(':'); }
					write!(&mut value, "{b:X}")?;
				}
				println!("{value}");
				RTCDtlsFingerprint {
					algorithm: "sha-256".into(),
					value,
				}
			};

			println!("Answering this connection");

			// ORTC because SDP sucks
			let ice_transport = Arc::new(api.new_ice_transport(gatherer.clone()));
			let dtls_transport =
				Arc::new(api.new_dtls_transport(ice_transport.clone(), vec![rtc_cert.clone()])?);
			let sctp_transport = Arc::new(api.new_sctp_transport(dtls_transport.clone())?);
			conns.insert(src.to_string(), sctp_transport.clone());
			// TODO: Remove from conns when the connection closes

			let src = src.to_string();
			let dcs = dcs.clone();
			tokio::spawn(async move {
				let res: Result<()> = async {
					let ice_params = RTCIceParameters {
						username_fragment: src.clone(),
						password: String::from("the/ice/password/constant"),
						ice_lite: false,
					};
	
					// Handle Datachannels on this connection
					sctp_transport.on_data_channel(Box::new(move |dc| {
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
					}));
	
					tokio::try_join!(
						ice_transport.start(
							&ice_params,
							Some(RTCIceRole::Controlled),
						),
						ice_transport.add_remote_candidate(Some(RTCIceCandidate {
							address: sender.ip().to_string(),
							port: sender.port(),
							typ: webrtc::ice_transport::ice_candidate_type::RTCIceCandidateType::Relay,
							protocol: webrtc::ice_transport::ice_protocol::RTCIceProtocol::Udp,
							foundation: "foundation".into(),
							component: 1,
							..Default::default()
						})),
						dtls_transport.start(DTLSParameters {
							role: DTLSRole::Server,
							fingerprints: vec![fingerprint],
						}),
						sctp_transport.start(SCTPTransportCapabilities {
							max_message_size: 65535,
						})
					)?;
					Ok(())
				}.await;
				println!("{res:?}");
			});
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
			let _ = dc
				.send_text(json)
				.await;
		}
	}
}
