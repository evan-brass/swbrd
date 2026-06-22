use std::{
	io::{ErrorKind, IoSlice},
	net::{Ipv6Addr, SocketAddrV6},
	os::fd::AsRawFd,
	str::{FromStr, from_utf8},
};

use common::{DcepOpenHeader, Ip6};
use eyre::{Result, eyre};

use clap::Parser;
use ipnet::Ipv6Net;
// use libc::{
// 	CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE, IPPROTO_SCTP, MSG_EOR, MSG_TRUNC,
// 	cmsghdr, msghdr, recvmsg, sendmsg, sockaddr_storage, socklen_t,
// };
use libc::MSG_EOR;
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use sctp::{
	DataNotif, Notif, SCTP_ALL_ASSOC, SCTP_ASSOC_CHANGE, SCTP_COMM_UP,
	SCTP_ENABLE_CHANGE_ASSOC_REQ, SCTP_ENABLE_RESET_ASSOC_REQ, SCTP_ENABLE_RESET_STREAM_REQ,
	SCTP_FUTURE_ASSOC, SCTP_PR_SCTP_RTX, SCTP_SENDALL, SCTP_SHUTDOWN_EVENT,
	SCTP_STREAM_RESET_INCOMING, SCTP_STREAM_RESET_OUTGOING, SCTP_UNORDERED, Sctp, sctp_assoc_value,
	sctp_event, sctp_prinfo, sctp_rcvinfo, sctp_reset_streams, sctp_sndinfo, write_control,
};
use socket2::MsgHdr;
use tracing::{error, info, trace, warn};
use tracing_subscriber::EnvFilter;
use tun_rs::DeviceBuilder;
use zerocopy::{
	FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Unaligned,
	network_endian::{I32, U16},
	transmute,
};

#[derive(Parser)]
#[command(version, about)]
struct Args {
	#[arg(long, short, default_value_t = 5000)]
	port: u16,

	#[arg(long, short)]
	subnet: String,

	#[arg(long, short)]
	if_name: Option<String>,
}

#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
struct AssocIp {
	prefix: [u8; 12],
	assoc_id: I32,
}

const TUN: Token = Token(usize::MAX);
const SCTP: Token = Token(usize::MAX - 1);

#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
struct SockToken {
	unused: [u8; 2],
	assoc_id: I32,
	stream: U16,
}
// struct SubSocket {
// 	socket: Sock,
// 	pr_info: sctp_prinfo,
// }

type Never = core::convert::Infallible;
pub(crate) fn main() -> Result<Never> {
	// Enable logging
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::from_default_env())
		.init();

	// Parse command line arguments
	let args = Args::try_parse()?;

	// Parse the subnet into a prefix
	let subnet = Ipv6Net::from_str(&args.subnet)?;
	if subnet.prefix_len() != 96 {
		return Err(eyre!(
			"The subnet must be a /96 since we use exactly 32 bits to store the associd."
		));
	}
	let AssocIp {
		prefix,
		assoc_id: _,
	} = transmute!(subnet.network().octets());

	// Setup the TAP interface
	let network = {
		let mut builder = DeviceBuilder::new();

		if let Some(if_name) = args.if_name {
			builder = builder.name(if_name);
		}

		builder.build_sync()?
	};
	network.set_nonblocking(true)?;

	// Bind the SCTP socket
	let socket = Sctp::one_to_many()?;
	socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, args.port, 0, 0).into())?;
	socket.listen(128)?;
	socket.set_nonblocking(true)?;

	// Set SCTP Specific socket options
	socket.set_recv_rcv_info(&1)?;
	socket.set_reconfig_supported(&sctp_assoc_value {
		assoc_id: SCTP_FUTURE_ASSOC,
		assoc_value: 1,
	})?;
	socket.set_enable_stream_reset(&sctp_assoc_value {
		assoc_id: SCTP_FUTURE_ASSOC,
		assoc_value: (SCTP_ENABLE_RESET_STREAM_REQ
			| SCTP_ENABLE_RESET_ASSOC_REQ
			| SCTP_ENABLE_CHANGE_ASSOC_REQ),
	})?;
	socket.set_event(&sctp_event {
		se_assoc_id: SCTP_ALL_ASSOC,
		se_type: SCTP_ASSOC_CHANGE,
		se_on: 1,
	})?;
	socket.set_event(&sctp_event {
		se_assoc_id: SCTP_ALL_ASSOC,
		se_type: SCTP_SHUTDOWN_EVENT,
		se_on: 1,
	})?;

	let mut events = Events::with_capacity(128);
	let mut poll = Poll::new()?;
	poll.registry()
		.register(&mut SourceFd(&network.as_raw_fd()), TUN, Interest::READABLE)?;
	poll.registry()
		.register(&mut SourceFd(&socket.as_raw_fd()), SCTP, Interest::READABLE)?;

	let mut buffer = vec![0; 4096];
	// let mut subsockets: BTreeMap<(u32, u16), Socket> = BTreeMap::new();

	loop {
		for e in events.into_iter() {
			match e.token() {
				TUN => loop {
					let Ok(length) = network.recv(&mut buffer) else {
						break;
					};
					if length < size_of::<Ip6>() {
						panic!("WAT?");
					}
					let (ip, _) = Ip6::ref_from_prefix(buffer.as_slice()).unwrap();
					let dst = Ipv6Addr::from_octets(ip.dst);
					let aip: AssocIp = transmute!(ip.dst);

					let assoc_id;
					let mut snd_flags = SCTP_UNORDERED;
					if dst.is_multicast() {
						assoc_id = SCTP_ALL_ASSOC;
						snd_flags |= SCTP_SENDALL;
					} else if aip.prefix == prefix {
						assoc_id = aip.assoc_id.get();
					} else {
						trace!(?dst, "Non-multicast IP outside our subnet..");
						continue;
					};

					// Tunnel the packet
					let mut control = nix::cmsg_space!(sctp_sndinfo, sctp_prinfo);
					control.truncate(0);
					write_control(
						&mut control,
						&[
							&sctp_sndinfo {
								snd_sid: 1,
								snd_flags,
								snd_ppid: 53u32.to_be(),
								snd_context: 0,
								snd_assoc_id: assoc_id,
							},
							&sctp_prinfo {
								pr_policy: SCTP_PR_SCTP_RTX,
								pr_value: 0,
							},
						],
					);

					let iov = [IoSlice::new(&buffer[..length])];
					let msg = MsgHdr::new().with_control(&control).with_buffers(&iov);
					match socket.sendmsg(&msg, MSG_EOR) {
						Ok(_) => {}
						Err(e) if e.kind() == ErrorKind::WouldBlock => {}
						Err(e) => error!(?e, "sendmsg failed"),
					}
				},
				SCTP => loop {
					let mut rcvinfo = sctp_rcvinfo::default();
					match socket.recvmsg(&mut buffer, &mut [&mut rcvinfo], 0) {
						Ok(DataNotif::Notif(Notif::AssocChange(change))) => {
							trace!(?change, "assoc change");
							if change.sac_state != SCTP_COMM_UP {
								continue;
							}

							// Open a datachannel
							let assoc_id = change.sac_assoc_id;
							let aip = AssocIp {
								prefix,
								assoc_id: I32::new(assoc_id),
							};
							let dst = Ipv6Addr::from_octets(transmute!(aip));
							let label = format!("{dst}");
							let protocol = "IP6";
							let dcep = DcepOpenHeader {
								msg_typ: 0x03,         /* DCEP_CHANNEL_OPEN */
								channel_typ: 0x81,     /* CHANNEL_TYPE_PARTIAL_RELIABLE_REXMIT_UNORDERED */
								priority: 1024.into(), /* extra high */
								reliability_parameter: 0.into(),
								label_len: (label.len() as u16).into(),
								protocol_len: (protocol.len() as u16).into(),
							};

							let iov = [
								IoSlice::new(dcep.as_bytes()),
								IoSlice::new(label.as_bytes()),
								IoSlice::new(protocol.as_bytes()),
							];
							let mut control = nix::cmsg_space!(sctp_sndinfo);
							control.truncate(0);
							write_control(
								&mut control,
								&[&sctp_sndinfo {
									snd_sid: 1,
									snd_flags: 0,
									snd_ppid: 50u32.to_be(),
									snd_context: 0,
									snd_assoc_id: change.sac_assoc_id,
								}],
							);
							let msg = MsgHdr::new().with_buffers(&iov).with_control(&control);

							match socket.sendmsg(&msg, MSG_EOR) {
								Ok(_) => {}
								Err(e) if e.kind() == ErrorKind::WouldBlock => {}
								Err(e) => trace!(?e, "sendmsg (dcep) failed"),
							}
						}
						Ok(DataNotif::Notif(Notif::ShutdownEvent(shutdown))) => {
							trace!(?shutdown, "shutdown");
						}
						Ok(DataNotif::Notif(_n)) => {
							trace!("Other SCTP notification");
						}
						Ok(DataNotif::Data(flags, data)) => {
							if flags.is_truncated() {
								error!("recvmsg truncated");
								continue;
							}
							if !flags.is_end_of_record() {
								error!("incomplete message received");
								continue;
							}
							let stream = rcvinfo.rcv_sid;
							let ppid = u32::from_be(rcvinfo.rcv_ppid);

							let aip = AssocIp {
								prefix,
								assoc_id: I32::new(rcvinfo.rcv_assoc_id),
							};

							let fb = data.first();
							match (ppid, stream) {
								(50, _) if fb == Some(&2) => {
									trace!(?aip, ?stream, ?data, "DCEP Ack")
								}
								(50, _) if fb == Some(&3) => {
									if let Some((open, label, proto)) = DcepOpenHeader::parse(&data)
									{
										info!(?aip, ?stream, ?open, ?label, ?proto, "DCEP Open");
										if !proto.starts_with(':') || !proto.ends_with("/tcp") {
											let mut rs =
												sctp_reset_streams::new_box_zeroed_with_elems(1)
													.unwrap();
											rs.srs_flags = SCTP_STREAM_RESET_INCOMING
												| SCTP_STREAM_RESET_OUTGOING;
											rs.srs_assoc_id = rcvinfo.rcv_assoc_id;
											rs.srs_number_streams = rs.srs_stream_list.len() as u16;
											rs.srs_stream_list[0] = stream;
											socket.set_reset_streams(&rs)?;
											continue;
										}

										// TODO: Parse the protocol and label and bind the socket
									} else {
										warn!(?aip, ?stream, ?data, "Malformed DCEP Open");
										continue;
									}
								}
								(50, _) => {
									warn!(?aip, ?stream, ?data, "Unrecognized DCEP Message");
								}
								(51, _) => {
									let Ok(data) = from_utf8(&data) else {
										continue;
									};
									// I'm expecting that most commands will come as JSON messages.
									// TODO: Retrieve the peer's UDP encapsulation port?

									trace!(?aip, ?stream, ?data, "String message");
								}
								// VPN traffic
								(53, 1) => {
									let Ok((ip, _)) = Ip6::ref_from_prefix(&data) else {
										continue;
									};
									if ip.src != aip.as_bytes() {
										trace!(?ip, "Wrong IP6 src");
										continue;
									}
									let _ = network.send(&data);
								}
								_ => trace!(?aip, ?stream, ?ppid, ?data, "Other message"),
							}
						}
						Err(e) if e.kind() == ErrorKind::WouldBlock => break,
						Err(e) => {
							error!(?e, "recvmsg failed");
							continue;
						}
					};
				},
				Token(t) => {
					// TODO:
					let SockToken {
						unused: [0, 0],
						assoc_id,
						stream,
					} = transmute!(t)
					else {
						unreachable!("Unrecognized Token");
					};
					trace!(?assoc_id, ?stream, "TODO Sockets")
				}
			}
		}

		poll.poll(&mut events, None)?;
	}
}
