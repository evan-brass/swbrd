#![allow(non_camel_case_types, unused_parens)]
// Raw bindings from <linux/sctp.h>
// Yes, some of this is available in the libc crate, but they are target_os locked and I'm tired.

use core::ffi::c_int;
use libc::{CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE, IPPROTO_SCTP, cmsghdr};
use socket2::{Domain, MaybeUninitSlice, MsgHdrMut, Protocol, RecvFlags, Socket, Type, socklen_t};
use std::{
	alloc::Layout,
	mem::{MaybeUninit, zeroed},
	ops::{Deref, DerefMut},
	ptr::{NonNull, copy_nonoverlapping, from_ref, read_unaligned, write_unaligned},
	slice,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

// Who's the genius that decided to linearize the control buffer?
pub trait ControlMsgDec {
	const LEVEL: c_int;
	const TYPE: c_int;
}
pub trait ControlMsg {
	#[doc(hidden)]
	fn write(&self, control: &mut Vec<u8>);
	#[doc(hidden)]
	unsafe fn read(&mut self, msg: NonNull<cmsghdr>) -> bool;
	#[doc(hidden)]
	fn space(&self) -> usize;
}
impl<T: ControlMsgDec + Sized> ControlMsg for T {
	fn write(&self, control: &mut Vec<u8>) {
		let clen = size_of_val(self) as libc::socklen_t;
		let empty = control.spare_capacity_mut();
		let space_len = unsafe { CMSG_SPACE(clen) } as usize;
		let Some((space, _rest)) = empty.split_at_mut_checked(space_len) else {
			panic!(
				"This control message is too big to fit in the control buffer's spare capacity."
			);
		};
		// Zero the space so that our struct's padding will still be initialized
		space.fill(MaybeUninit::new(0));

		unsafe {
			let cmsg: *mut cmsghdr = space.as_mut_ptr().cast();
			write_unaligned(
				cmsg,
				cmsghdr {
					#[cfg(target_os = "macos")]
					cmsg_len: CMSG_LEN(clen),
					#[cfg(not(target_os = "macos"))]
					cmsg_len: CMSG_LEN(clen) as usize,
					cmsg_level: Self::LEVEL,
					cmsg_type: Self::TYPE,
				},
			);
			copy_nonoverlapping(self, CMSG_DATA(cmsg).cast(), 1);
			control.set_len(control.len() + space_len);
		}
	}
	unsafe fn read(&mut self, cmsg_ptr: NonNull<cmsghdr>) -> bool {
		let cmsg = unsafe { cmsg_ptr.read_unaligned() };
		if cmsg.cmsg_type != Self::TYPE || cmsg.cmsg_level != Self::LEVEL {
			return false;
		}
		assert_eq!(cmsg.cmsg_len as socklen_t, unsafe {
			CMSG_LEN(size_of_val(self) as socklen_t)
		});
		*self = unsafe { read_unaligned(CMSG_DATA(cmsg_ptr.as_ptr()).cast()) };
		true
	}
	fn space(&self) -> usize {
		unsafe { CMSG_SPACE(size_of_val(self) as socklen_t) as usize }
	}
}
pub fn write_control(control_buffer: &mut Vec<u8>, msgs: &[&dyn ControlMsg]) {
	for m in msgs {
		m.write(control_buffer);
	}
}
pub fn read_control(control_buffer: &mut Vec<u8>, msgs: &mut [&mut dyn ControlMsg]) {
	unsafe {
		let mut tmp: libc::msghdr = zeroed();
		tmp.msg_control = control_buffer.as_mut_ptr().cast();
		#[cfg(target_os = "macos")]
		{
			tmp.msg_controllen = control_buffer.len() as socklen_t;
		}
		#[cfg(not(target_os = "macos"))]
		{
			tmp.msg_controllen = control_buffer.len();
		}

		let mut cmsg = CMSG_FIRSTHDR(&tmp);
		while let Some(ptr) = NonNull::new(cmsg) {
			for msg in msgs.iter_mut() {
				if msg.read(ptr) {
					break;
				}
			}
			// TODO: Add warning message for unexpected control messages?
			cmsg = CMSG_NXTHDR(&tmp, cmsg);
		}
	}
}

pub struct Sctp(Socket);
impl Sctp {
	pub fn one_to_one() -> std::io::Result<Self> {
		let inner = Socket::new(
			Domain::IPV6,
			Type::STREAM,
			Some(Protocol::from(libc::IPPROTO_SCTP)),
		)?;
		Ok(Self(inner))
	}
	pub fn one_to_many() -> std::io::Result<Self> {
		let inner = Socket::new(
			Domain::IPV6,
			Type::SEQPACKET,
			Some(Protocol::from(libc::IPPROTO_SCTP)),
		)?;
		Ok(Self(inner))
	}
}
impl Deref for Sctp {
	type Target = Socket;
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}
impl DerefMut for Sctp {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

type sctp_assoc_t = i32;

pub const SCTP_FUTURE_ASSOC: sctp_assoc_t = 0;
pub const SCTP_CURRENT_ASSOC: sctp_assoc_t = 1;
pub const SCTP_ALL_ASSOC: sctp_assoc_t = 2;

use nix::errno::Errno;
/**
 * SCTP socket options
 * Only some of the SCTP options are compatible with the GetSockOpt trait because SCTP options often require providing input in the response struct.  Namely we have to specify the assoc_id to query.
 */
macro_rules! sctp_sockoptions {
	(@impl get _ $code:literal $val:ty) => {};
	(@impl get $name:ident $code:literal $val:ty) => {
		impl Sctp {
			pub fn $name(&self, res: &mut $val) -> Result<libc::socklen_t, Errno> {
				let mut out_len = size_of_val(res) as libc::socklen_t;
				nix::errno::Errno::result(unsafe {
					libc::getsockopt(
						std::os::fd::AsRawFd::as_raw_fd(&self.0),
						libc::IPPROTO_SCTP,
						$code,
						core::ptr::from_mut(res).cast(),
						&mut out_len,
					)
				})?;
				Ok(out_len)
			}
		}
	};
	(@impl set _ $code:literal $val:ty) => {};
	(@impl set $name:ident $code:literal $val:ty) => {
		impl Sctp {
			pub fn $name(&self, val: &$val) -> Result<(), Errno> {
				nix::errno::Errno::result(unsafe {
					libc::setsockopt(
						std::os::fd::AsRawFd::as_raw_fd(&self.0),
						libc::IPPROTO_SCTP,
						$code,
						core::ptr::from_ref(val).cast(),
						size_of_val(val) as libc::socklen_t
					)
				})?;
				Ok(())
			}
		}
	};
	($($code:literal $get_name:tt $set_name:tt $val:ty)+) => {
		$(
			sctp_sockoptions!(@impl get $get_name $code $val);
			sctp_sockoptions!(@impl set $set_name $code $val);
		)+
	};
}
sctp_sockoptions! {
	// TODO: Revise these names, especially for getonly/setonly.  For instance set_auth_delete_key should probably just be delete_auth_key
	0 get_rto_info set_rto_info sctp_rtoinfo
	1 get_assoc_info set_assoc_info sctp_assocparams
	2 get_init_msg set_init_msg sctp_initmsg
	3 get_nodelay set_nodelay c_int // TODO: support bool
	4 get_autoclose_sec set_autoclose_sec c_int // Seconds, sysctl_net.sctp.max_autoclose
	5 _ set_peer_primary_addr sctp_setpeerprim
	6 _ set_primary_addr sctp_prim
	7 get_adaptation_layer set_adaptation_layer sctp_setadaptation
	8 get_disable_fragments set_disable_fragments c_int
	9 get_peer_addr_params set_peer_addr_params sctp_paddrparams
	// SCTP_DEFAULT_SEND_PARAM is deprecated, use SCTP_DEFAULT_SNDINFO
	// SCTP_EVENTS is deprecated, use SCTP_EVENT
	12 get_want_mapped_v4 set_want_mapped_v4 c_int
	13 get_maxseg set_maxseg sctp_assoc_value
	14 get_status _ sctp_status
	15 get_peer_addr_info _ sctp_paddrinfo
	16 get_delayed_ack_time_ms set_delayed_ack_time_ms sctp_sack_info // Milliseconds
	// SCTP_DELAYED_ACK is an alias for SCTP_DELAYED_ACK_TIME
	// SCTP_DELAYED_SACK is an alias for SCTP_DELAYED_ACK_TIME
	17 get_context set_context sctp_assoc_value
	18 get_fragment_interleave set_fragment_interleave c_int
	19 get_partial_delivery_point set_partial_delivery_point u32
	20 get_max_burst set_max_burst sctp_assoc_value
	21 _ set_auth_chunk sctp_authchunk
	22 get_hmac_ident set_hmac_ident sctp_hmacalgo
	23 _ set_auth_key sctp_authkey
	24 _ set_auth_active_key sctp_authkeyid
	25 _ set_auth_delete_key sctp_authkeyid
	26 get_peer_auth_chunks _ sctp_authchunks
	27 get_local_auth_chunks _ sctp_authchunks
	28 get_assoc_number _ u32
	29 get_assoc_id_list _ sctp_assoc_ids
	30 get_auto_asconf set_auto_asconf c_int
	// SCTP_PEER_ADDR_THLDS is deprecated
	32 get_recv_rcv_info set_recv_rcv_info c_int // TODO: support bool
	33 get_recv_nxt_info set_recv_nxt_info c_int // TODO: support bool
	34 get_default_snd_info set_default_snd_info sctp_sndinfo
	35 _ set_auth_deactivate_key sctp_authkeyid
	36 get_reuse_port set_reuse_port c_int // TODO: support bool
	37 get_peer_addr_thlds_v2 set_peer_addr_thlds_v2 sctp_paddrthlds_v2
	// 38-101 ???
	// TODO: SCTP_SOCKOPT_PEELOFF
	// 103 ???
	// 104-106 deprecated options
	// SCTP_SOCKOPT_CONNECTX_OLD
	108 get_peer_addrs _ sctp_getaddrs
	109 get_local_addrs _ sctp_getaddrs
	// 110-111
	112 get_assoc_stats _ sctp_assoc_stats
	113 get_pr_supported set_pr_supported sctp_assoc_value
	114 get_default_pr_info set_default_pr_info sctp_default_prinfo
	115 get_pr_assoc_status _ sctp_prstatus
	116 get_pr_stream_status _ sctp_prstatus
	117 get_reconfig_supported set_reconfig_supported sctp_assoc_value
	118 get_enable_stream_reset set_enable_stream_reset sctp_assoc_value
	119 _ set_reset_streams sctp_reset_streams
	120 _ set_reset_assoc sctp_assoc_t
	121 _ set_add_streams sctp_add_streams
	// TODO: SCTP_SOCKOPT_PEELOFF_FLAGS
	123 get_stream_scheduler set_stream_scheduler sctp_assoc_value
	124 get_stream_scheduler_value set_stream_scheduler_value sctp_assoc_value
	125 get_interleaving_support set_interleaving_support sctp_assoc_value
	// SCTP_SENDMSG_CONNECT Not sure what this does
	127 get_event set_event sctp_event
	128 get_asconf_supported set_asconf_supported sctp_assoc_value
	129 get_auth_supported set_auth_supported sctp_assoc_value
	130 get_ecn_support set_ecn_support sctp_assoc_value
	131 get_expose_potentially_failed_state set_expose_potentially_failed_state sctp_assoc_value
	// SCTP_EXPOSE_PF_STATE is an alias of SCTP_EXPOSE_POTENTIALLY_FAILED_STATE
	132 get_remote_udp_encaps_port set_remote_udp_encaps_port sctp_udpencaps
	133 get_plpmtud_probe_interval_ms set_plpmtud_probe_interval_ms sctp_probeinterval // Milliseconds?
}

pub const SCTP_PR_SCTP_NONE: u16 = 0x0000;
pub const SCTP_PR_SCTP_TTL: u16 = 0x0010;
pub const SCTP_PR_SCTP_RTX: u16 = 0x0020;
pub const SCTP_PR_SCTP_PRIO: u16 = 0x0030;
pub const SCTP_PR_SCTP_MASK: u16 = 0x0030;

pub const SCTP_ENABLE_RESET_STREAM_REQ: u32 = 0x01;
pub const SCTP_ENABLE_RESET_ASSOC_REQ: u32 = 0x02;
pub const SCTP_ENABLE_CHANGE_ASSOC_REQ: u32 = 0x04;

pub const SCTP_STREAM_RESET_INCOMING: u16 = 0x01;
pub const SCTP_STREAM_RESET_OUTGOING: u16 = 0x02;

macro_rules! enum_to_const {
	($orig:ident: $repr:ty; $($var:ident $(= $disc:expr)?,)+) => {
		#[repr(C)]
		enum $orig {
			$($var $(= $disc)?,)+
		}
		$(
			pub const $var: $repr = $orig::$var as $repr;
		)+
	};
}
enum_to_const! {
	sctp_msg_flags: c_int;
	MSG_NOTIFICATION = 0x8000,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_initmsg {
	pub sinit_num_ostreams: u16,
	pub sinit_max_instreams: u16,
	pub sinit_max_attempts: u16,
	pub sinit_max_init_timeo: u16,
}
impl ControlMsgDec for sctp_initmsg {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_INIT;
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_sndrcvinfo {
	pub sinfo_stream: u16,
	pub sinfo_ssn: u16,
	pub sinfo_flags: u16,
	pub sinfo_ppid: u32,
	pub sinfo_context: u32,
	pub sinfo_timetolive: u32,
	pub sinfo_tsn: u32,
	pub sinfo_cumtsn: u32,
	pub sinfo_assoc_id: sctp_assoc_t,
}
impl ControlMsgDec for sctp_sndrcvinfo {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_SNDRCV;
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_sndinfo {
	pub snd_sid: u16,
	pub snd_flags: u16,
	pub snd_ppid: u32,
	pub snd_context: u32,
	pub snd_assoc_id: sctp_assoc_t,
}
impl ControlMsgDec for sctp_sndinfo {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_SNDINFO;
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_rcvinfo {
	pub rcv_sid: u16,
	pub rcv_ssn: u16,
	pub rcv_flags: u16,
	pub rcv_ppid: u32,
	pub rcv_tsn: u32,
	pub rcv_cumtsn: u32,
	pub rcv_context: u32,
	pub rcv_assoc_id: sctp_assoc_t,
}
impl ControlMsgDec for sctp_rcvinfo {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_RCVINFO;
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_nxtinfo {
	pub nxt_sid: u16,
	pub nxt_flags: u16,
	pub nxt_ppid: u32,
	pub nxt_length: u32,
	pub nxt_assoc_id: sctp_assoc_t,
}
impl ControlMsgDec for sctp_nxtinfo {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_NXTINFO;
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_prinfo {
	pub pr_policy: u16,
	pub pr_value: u32,
}
impl ControlMsgDec for sctp_prinfo {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_PRINFO;
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_authinfo {
	pub auth_keynumber: u16,
}
impl ControlMsgDec for sctp_authinfo {
	const LEVEL: c_int = IPPROTO_SCTP;
	const TYPE: c_int = SCTP_AUTHINFO;
}

// TODO: repr(transparent) struct wrappers for in(6)_addr that we can implement the SCTP_DSTADDRV4 and SCTP_DSTADDRV6 control messages.

pub const SCTP_UNORDERED: u16 = (1 << 0);
pub const SCTP_ADDR_OVER: u16 = (1 << 1);
pub const SCTP_ABORT: u16 = (1 << 2);
pub const SCTP_SACK_IMMEDIATELY: u16 = (1 << 3);
pub const SCTP_SENDALL: u16 = (1 << 6);
pub const SCTP_PR_SCTP_ALL: u16 = (1 << 7);
pub const SCTP_NOTIFICATION: u16 = MSG_NOTIFICATION as u16;
pub const SCTP_EOF: u16 = 0x200 /* libc::MSG_FIN */;

enum_to_const! {
	sctp_cmsg_type: i32;
	SCTP_INIT,
	SCTP_SNDRCV,
	SCTP_SNDINFO,
	SCTP_RCVINFO,
	SCTP_NXTINFO,
	SCTP_PRINFO,
	SCTP_AUTHINFO,
	SCTP_DSTADDRV4,
	SCTP_DSTADDRV6,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable, FromBytes)]
pub struct sctp_assoc_change {
	pub sac_type: u16,
	pub sac_flags: u16,
	pub sac_length: u32,
	pub sac_state: u16,
	pub sac_error: u16,
	pub sac_outbound_streams: u16,
	pub sac_inbound_streams: u16,
	pub sac_assoc_id: sctp_assoc_t,
	pub sac_info: [u8],
}

enum_to_const! {
	sctp_sac_state: u16;
	SCTP_COMM_UP,
	SCTP_COMM_LOST,
	SCTP_RESTART,
	SCTP_SHUTDOWN_COMP,
	SCTP_CANT_STR_ASSOC,
}

#[repr(C, packed(4))]
#[derive(KnownLayout)]
pub struct sctp_paddr_change {
	pub spc_type: u16,
	pub spc_flags: u16,
	pub spc_length: u32,
	pub spc_aaddr: socket2::SockAddrStorage,
	pub spc_state: c_int,
	pub spc_error: c_int,
	pub spc_assoc_id: sctp_assoc_t,
}

enum_to_const! {
	sctp_spc_state: c_int;
	SCTP_ADDR_AVAILABLE,
	SCTP_ADDR_UNREACHABLE,
	SCTP_ADDR_REMOVED,
	SCTP_ADDR_ADDED,
	SCTP_ADDR_MADE_PRIM,
	SCTP_ADDR_CONFIRMED,
	SCTP_ADDR_POTENTIALLY_FAILED,
}
pub const SCTP_ADDR_PF: c_int = SCTP_ADDR_POTENTIALLY_FAILED;

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_remote_error {
	pub sre_type: u16,
	pub sre_flags: u16,
	pub sre_length: u32,
	pub sre_error: u16, // Big-Endian
	pub sre_assoc_id: sctp_assoc_t,
	pub sre_data: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_send_failed_event {
	pub ssf_type: u16,
	pub ssf_flags: u16,
	pub ssf_length: u32,
	pub ssf_error: u32,
	pub ssfe_info: sctp_sndinfo,
	pub ssf_assoc_id: sctp_assoc_t,
	pub ssf_data: [u8; 0],
}

enum_to_const! {
	sctp_ssf_flags: c_int;
	SCTP_DATA_UNSENT,
	SCTP_DATA_SENT,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_shutdown_event {
	pub sse_type: u16,
	pub sse_flags: u16,
	pub sse_length: u32,
	pub sse_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_adaptation_event {
	pub sai_type: u16,
	pub sai_flags: u16,
	pub sai_length: u32,
	pub sai_adaptation_ind: u32,
	pub sai_assoc_id: sctp_assoc_t,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_pdapi_event {
	pub pdapi_type: u16,
	pub pdapi_flags: u16,
	pub pdapi_length: u32,
	pub pdapi_indication: u32,
	pub pdapi_assoc_id: sctp_assoc_t,
	pub pdapi_stream: u32,
	pub pdapi_seq: u32,
}

pub const SCTP_PARTIAL_DELIVERY_ABORTED: c_int = 0;

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_authkey_event {
	pub auth_type: u16,
	pub auth_flags: u16,
	pub auth_length: u32,
	pub auth_keynumber: u16,
	pub auth_altkeynumber: u16,
	pub auth_indication: u32,
	pub auth_assoc_id: sctp_assoc_t,
}

pub const SCTP_AUTH_NEW_KEY: c_int = 0;
pub const SCTP_AUTH_FREE_KEY: c_int = 1;
pub const SCTP_AUTH_NO_AUTH: c_int = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_sender_dry_event {
	pub sender_dry_type: u16,
	pub sender_dry_flags: u16,
	pub sender_dry_length: u32,
	pub sender_dry_assoc_id: sctp_assoc_t,
}

pub const SCTP_STREAM_RESET_INCOMING_SSN: u16 = 0x0001;
pub const SCTP_STREAM_RESET_OUTGOING_SSN: u16 = 0x0002;
pub const SCTP_STREAM_RESET_DENIED: u16 = 0x0004;
pub const SCTP_STREAM_RESET_FAILED: u16 = 0x0008;
#[repr(C)]
#[derive(Debug, KnownLayout, Immutable, FromBytes)]
pub struct sctp_stream_reset_event {
	pub strreset_type: u16,
	pub strreset_flags: u16,
	pub strreset_length: u32,
	pub strreset_assoc_id: sctp_assoc_t,
	pub strreset_stream_list: [u16],
}

pub const SCTP_ASSOC_RESET_DENIED: u16 = 0x0004;
pub const SCTP_ASSOC_RESET_FAILED: u16 = 0x0008;
#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_assoc_reset_event {
	pub assocreset_type: u16,
	pub assocreset_flags: u16,
	pub assocreset_length: u32,
	pub assocreset_assoc_id: sctp_assoc_t,
	pub assocreset_local_tsn: u32,
	pub assocreset_remote_tsn: u32,
}

pub const SCTP_ASSOC_CHANGE_DENIED: u16 = 0x0004;
pub const SCTP_ASSOC_CHANGE_FAILED: u16 = 0x0008;
pub const SCTP_STREAM_CHANGE_DENIED: u16 = SCTP_ASSOC_CHANGE_DENIED;
pub const SCTP_STREAM_CHANGE_FAILED: u16 = SCTP_ASSOC_CHANGE_FAILED;
#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_stream_change_event {
	pub strchange_type: u16,
	pub strchange_flags: u16,
	pub strchange_length: u32,
	pub strchange_assoc_id: sctp_assoc_t,
	pub strchange_instrms: u16,
	pub strchange_outstrms: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sn_header {
	pub sn_type: u16,
	pub sn_flags: u16,
	pub sn_length: u32,
}

enum_to_const! {
	sctp_sn_type: u16;
	SCTP_DATA_IO_EVENT = (1 << 15),
	SCTP_ASSOC_CHANGE,
	SCTP_PEER_ADDR_CHANGE,
	SCTP_SEND_FAILED, // TODO: Deprecated, use SEND_FAILED_EVENT which doesn't use sndrcvinfo
	SCTP_REMOTE_ERROR,
	SCTP_SHUTDOWN_EVENT,
	SCTP_PARTIAL_DELIVERY_EVENT,
	SCTP_ADAPTATION_INDICATION,
	SCTP_AUTHENTICATION_EVENT,
	SCTP_SENDER_DRY_EVENT,
	SCTP_STREAM_RESET_EVENT,
	SCTP_ASSOC_RESET_EVENT,
	SCTP_STREAM_CHANGE_EVENT,
	SCTP_SEND_FAILED_EVENT,
}

pub enum Notif<'i> {
	Other(sn_header),
	AssocChange(&'i sctp_assoc_change),
	AddrChange(&'i sctp_paddr_change),
	RemoteError(&'i sctp_remote_error),
	ShutdownEvent(&'i sctp_shutdown_event),
	AdaptationEvent(&'i sctp_adaptation_event),
	PdapiEvent(&'i sctp_pdapi_event),
	AuthkeyEvent(&'i sctp_authkey_event),
	SenderDryEvent(&'i sctp_sender_dry_event),
	StreamReset(&'i sctp_stream_reset_event),
	AssocReset(&'i sctp_assoc_reset_event),
	StreamChange(&'i sctp_stream_change_event),
	SendFailedEvent(&'i sctp_send_failed_event),
}
pub enum DataNotif<'i> {
	Data(RecvFlags, &'i [u8]),
	Notif(Notif<'i>),
}
impl Sctp {
	pub fn recvmsg<'i>(
		&self,
		buffer: &'i mut [u8],
		control: &mut [&mut dyn ControlMsg],
		flags: c_int,
	) -> Result<DataNotif<'i>, std::io::Error> {
		let mut control_buffer = Vec::with_capacity(control.iter().map(|c| c.space()).sum());
		let mut buffers = [MaybeUninitSlice::new(unsafe {
			slice::from_raw_parts_mut(buffer.as_mut_ptr().cast(), buffer.len())
		})];
		let mut msg = MsgHdrMut::new()
			.with_buffers(&mut buffers)
			.with_control(control_buffer.spare_capacity_mut());

		// Call recvmsg
		let res = self.0.recvmsg(&mut msg, flags)?;

		// TODO: socket2 doesn't yield the raw flags and socket2::RecvFlags doesn't have accessors for the fields we need... however, MsgHdrMut is currently repr(transparent) around a libc::msghdr, so if we take a pointer, cast it to libc::msghdr, then we can read the flags field directly.
		const _: () = {
			let a = Layout::new::<MsgHdrMut>();
			let b = Layout::new::<libc::msghdr>();
			assert!(a.size() == b.size() && a.align() == b.align());
		};
		let raw_msghdr: *const libc::msghdr = from_ref(&msg).cast();
		let raw_flags = unsafe { (*raw_msghdr).msg_flags };

		// Update the buffers (control and normal)
		let ret = msg.flags();
		let data: &'i [u8] = &buffer[..usize::min(res, buffer.len())];
		let clen = usize::min(msg.control_len(), control_buffer.capacity());
		unsafe {
			// TODO: Handle MSG_TRUNC and I think there's a CMSG_TRUNC flag as well
			control_buffer.set_len(clen);
		}

		if raw_flags & MSG_NOTIFICATION != 0 {
			// Figure out what type of message this is
			assert!(res >= size_of::<sn_header>());
			let (h, _) = sn_header::read_from_prefix(data).unwrap();
			Ok(DataNotif::Notif(match h.sn_type {
				SCTP_ASSOC_CHANGE => Notif::AssocChange(FromBytes::ref_from_bytes(data).unwrap()),
				SCTP_PEER_ADDR_CHANGE => {
					// TODO: Find a solution to use FromBytes with SockAddrStorage
					Notif::AddrChange(unsafe { &*data.as_ptr().cast() })
				}
				SCTP_REMOTE_ERROR => Notif::RemoteError(FromBytes::ref_from_bytes(data).unwrap()),
				SCTP_SHUTDOWN_EVENT => {
					Notif::ShutdownEvent(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_ADAPTATION_INDICATION => {
					Notif::AdaptationEvent(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_AUTHENTICATION_EVENT => {
					Notif::AuthkeyEvent(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_PARTIAL_DELIVERY_EVENT => {
					Notif::PdapiEvent(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_SENDER_DRY_EVENT => {
					Notif::SenderDryEvent(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_STREAM_RESET_EVENT => {
					Notif::StreamReset(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_ASSOC_RESET_EVENT => {
					Notif::AssocReset(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_STREAM_CHANGE_EVENT => {
					Notif::StreamChange(FromBytes::ref_from_bytes(data).unwrap())
				}
				SCTP_SEND_FAILED_EVENT => {
					Notif::SendFailedEvent(FromBytes::ref_from_bytes(data).unwrap())
				}
				_ => Notif::Other(h),
			}))
		} else {
			read_control(&mut control_buffer, control);

			Ok(DataNotif::Data(ret, data))
		}
	}
}

enum_to_const! {
	sctp_sn_error: c_int;
	SCTP_FAILED_THRESHOLD,
	SCTP_RECEIVED_SACK,
	SCTP_HEARTBEAT_SUCCESS,
	SCTP_RESPONSE_TO_USER_REQ,
	SCTP_INTERNAL_ERROR,
	SCTP_SHUTDOWN_GUARD_EXPIRES,
	SCTP_PEER_FAULTY,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_rtoinfo {
	pub srto_assoc_id: sctp_assoc_t,
	pub srto_initial: u32,
	pub srto_max: u32,
	pub srto_min: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_assocparams {
	pub sasoc_assoc_id: sctp_assoc_t,
	pub sasoc_asocmaxrxt: u16,
	pub sasoc_number_peer_destinations: u16,
	pub sasoc_peer_rwnd: u32,
	pub sasoc_local_rwnd: u32,
	pub sasoc_cookie_life: u32,
}

#[repr(C, packed(4))]
pub struct sctp_setpeerprim {
	pub sspp_assoc_id: sctp_assoc_t,
	pub sspp_addr: socket2::SockAddrStorage,
}

#[repr(C, packed(4))]
pub struct sctp_prim {
	pub ssp_assoc_id: sctp_assoc_t,
	pub ssp_addr: socket2::SockAddrStorage,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_setadaptation {
	pub ssb_adaptation_ind: u32,
}

enum_to_const! {
	sctp_spp_flags: u32;
	SPP_HB_ENABLE = 1 << 0,
	SPP_HB_DISABLE = 1 << 1,
	SPP_HB_DEMAND = 1 << 2,
	SPP_PMTUD_ENABLE = 1 << 3,
	SPP_PMTUD_DISABLE = 1 << 4,
	SPP_SACKDELAY_ENABLE = 1 << 5,
	SPP_SACKDELAY_DISABLE = 1 << 6,
	SPP_HB_TIME_IS_ZERO = 1 << 7,
	SPP_IPV6_FLOWLABEL = 1 << 8,
	SPP_DSCP = 1 << 9,
}

#[repr(C, packed(4))]
#[derive(KnownLayout)]
pub struct sctp_paddrparams {
	pub spp_assoc_id: sctp_assoc_t,
	pub spp_address: socket2::SockAddrStorage,
	pub spp_hbinterval: u32,
	pub spp_pathmaxrxt: u16,
	pub spp_pathmtu: u32,
	pub spp_sackdelay: u32,
	pub spp_flags: u32,
	pub spp_ipv6_flowlabel: u32,
	pub spp_dscp: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_authchunk {
	pub sauth_chunk: u8,
}

pub const SCTP_AUTH_HMAC_ID_SHA1: c_int = 1;
pub const SCTP_AUTH_HMAC_ID_SHA256: c_int = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_hmacalgo {
	pub shmac_num_idents: u32,
	pub shmac_idents: [u16; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_authkey {
	pub sca_assoc_id: sctp_assoc_t,
	pub sca_keynumber: u16,
	pub sca_keylength: u16,
	pub sca_key: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_authkeyid {
	pub scact_assoc_id: sctp_assoc_t,
	pub scact_keynumber: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_sack_info {
	pub sack_assoc_id: sctp_assoc_t,
	pub sack_delay: u32,
	pub sack_freq: u32,
}
#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_assoc_value {
	pub assoc_id: sctp_assoc_t,
	pub assoc_value: u32,
}
#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_stream_value {
	pub assoc_id: sctp_assoc_t,
	pub stream_id: u16,
	pub stream_value: u16,
}

#[repr(C, packed(4))]
#[derive(KnownLayout)]
pub struct sctp_paddrinfo {
	pub spinfo_assoc_id: sctp_assoc_t,
	pub spinfo_address: socket2::SockAddrStorage,
	pub spinfo_state: i32,
	pub spinfo_cwnd: u32,
	pub spinfo_srtt: u32,
	pub spinfo_rto: u32,
	pub spinfo_mtu: u32,
}

enum_to_const! {
	sctp_spinfo_state: c_int;
	SCTP_INACTIVE,
	SCTP_PF,
	SCTP_ACTIVE,
	SCTP_UNCONFIRMED,
	SCTP_UNKNOWN = 0xffff,
}

#[repr(C)]
#[derive(KnownLayout)]
pub struct sctp_status {
	pub sstat_assoc_id: sctp_assoc_t,
	pub sstat_state: i32,
	pub sstat_rwnd: u32,
	pub sstat_unackdata: u16,
	pub sstat_penddata: u16,
	pub sstat_instrms: u16,
	pub sstat_outstrms: u16,
	pub sstat_fragmentation_point: u32,
	pub sstat_primary: sctp_paddrinfo,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_authchunks {
	pub gauth_assoc_id: sctp_assoc_t,
	pub gauth_number_of_chunks: u32,
	pub gauth_chunks: [u8; 0],
}

enum_to_const! {
	sctp_sstat_state: c_int;
	SCTP_EMPTY = 0,
	SCTP_CLOSED = 1,
	SCTP_COOKIE_WAIT = 2,
	SCTP_COOKIE_ECHOED = 3,
	SCTP_ESTABLISHED = 4,
	SCTP_SHUTDOWN_PENDING = 5,
	SCTP_SHUTDOWN_SENT = 6,
	SCTP_SHUTDOWN_RECEIVED = 7,
	SCTP_SHUTDOWN_ACK_SENT = 8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_assoc_ids {
	pub gaids_number_of_ids: u32,
	pub gaids_assoc_id: [sctp_assoc_t; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_getaddrs {
	pub assoc_id: sctp_assoc_t,
	pub addr_num: u32,
	pub addrs: [u8; 0],
}

#[repr(C)]
#[derive(Debug, KnownLayout)]
pub struct sctp_assoc_stats {
	pub sas_assoc_id: sctp_assoc_t,
	pub sas_obs_rto_ipaddr: socket2::SockAddrStorage,
	pub sas_maxrto: u64,
	pub sas_isacks: u64,
	pub sas_osacks: u64,
	pub sas_opackets: u64,
	pub sas_ipackets: u64,
	pub sas_rtxchunks: u64,
	pub sas_outofseqtsns: u64,
	pub sas_idupchunks: u64,
	pub sas_gapcnt: u64,
	pub sas_ouodchunks: u64,
	pub sas_iuodchunks: u64,
	pub sas_oodchunks: u64,
	pub sas_iodchunks: u64,
	pub sas_octrlchunks: u64,
	pub sas_ictrlchunks: u64,
}

#[repr(C)]
#[derive(Debug, KnownLayout)]
pub struct sctp_paddrthlds {
	pub spt_assoc_id: sctp_assoc_t,
	pub spt_address: socket2::SockAddrStorage,
	pub spt_pathmaxrxt: u16,
	pub spt_pathpfthld: u16,
}

#[repr(C)]
#[derive(Debug, KnownLayout)]
pub struct sctp_paddrthlds_v2 {
	pub spt_assoc_id: sctp_assoc_t,
	pub spt_address: socket2::SockAddrStorage,
	pub spt_pathmaxrxt: u16,
	pub spt_pathpfthld: u16,
	pub spt_pathcpthld: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_prstatus {
	pub sprstat_assoc_id: sctp_assoc_t,
	pub sprstat_sid: u16,
	pub sprstat_policy: u16,
	pub sprstat_abandoned_unsent: u64,
	pub sprstat_abandoned_sent: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_default_prinfo {
	pub pr_assoc_id: sctp_assoc_t,
	pub pr_value: u32,
	pub pr_policy: u16,
}

#[repr(C)]
#[derive(Debug, KnownLayout)]
pub struct sctp_info {
	pub sctpi_tag: u32,
	pub sctpi_state: u32,
	pub sctpi_rwnd: u32,
	pub sctpi_unackdata: u16,
	pub sctpi_penddata: u16,
	pub sctpi_instrms: u16,
	pub sctpi_outstrms: u16,
	pub sctpi_fragmentation_point: u32,
	pub sctpi_inqueue: u32,
	pub sctpi_outqueue: u32,
	pub sctpi_overall_error: u32,
	pub sctpi_max_burst: u32,
	pub sctpi_maxseg: u32,
	pub sctpi_peer_rwnd: u32,
	pub sctpi_peer_tag: u32,
	pub sctpi_peer_capable: u8,
	pub sctpi_peer_sack: u8,
	__reserved1: u16,

	pub sctpi_isacks: u64,
	pub sctpi_osacks: u64,
	pub sctpi_opackets: u64,
	pub sctpi_ipackets: u64,
	pub sctpi_rtxchunks: u64,
	pub sctpi_outofseqtsns: u64,
	pub sctpi_idupchunks: u64,
	pub sctpi_gapcnt: u64,
	pub sctpi_ouodchunks: u64,
	pub sctpi_iuodchunks: u64,
	pub sctpi_oodchunks: u64,
	pub sctpi_iodchunks: u64,
	pub sctpi_octrlchunks: u64,
	pub sctpi_ictrlchunks: u64,

	pub sctpi_p_address: socket2::SockAddrStorage,
	pub sctpi_p_state: i32,
	pub sctpi_p_cwnd: u32,
	pub sctpi_p_srtt: u32,
	pub sctpi_p_rto: u32,
	pub sctpi_p_hbinterval: u32,
	pub sctpi_p_pathmaxrxt: u32,
	pub sctpi_p_sackdelay: u32,
	pub sctpi_p_sackfreq: u32,
	pub sctpi_p_ssthresh: u32,
	pub sctpi_p_partial_bytes_acked: u32,
	pub sctpi_p_flight_size: u32,
	pub sctpi_p_error: u16,
	__reserved2: u16,

	pub sctpi_s_autoclose: u32,
	pub sctpi_s_adaptation_ind: u32,
	pub sctpi_s_pd_point: u32,
	pub sctpi_s_nodelay: u8,
	pub sctpi_s_disable_fragments: u8,
	pub sctpi_s_v4mapped: u8,
	pub sctpi_s_frag_interleave: u8,
	pub sctpi_s_type: u32,
	__reserved3: u32,
}

#[repr(C)]
#[derive(Debug, KnownLayout, Immutable, FromBytes)]
pub struct sctp_reset_streams {
	pub srs_assoc_id: sctp_assoc_t,
	pub srs_flags: u16,
	pub srs_number_streams: u16,
	pub srs_stream_list: [u16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct sctp_add_streams {
	pub sas_assoc_id: sctp_assoc_t,
	pub sas_instrms: u16,
	pub sas_outstrms: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, FromBytes)]
pub struct sctp_event {
	pub se_assoc_id: sctp_assoc_t,
	pub se_type: u16,
	pub se_on: u8,
}

#[repr(C)]
#[derive(Debug, KnownLayout)]
pub struct sctp_udpencaps {
	pub sue_assoc_id: sctp_assoc_t,
	pub sue_address: socket2::SockAddrStorage,
	pub sue_port: u16,
}

enum_to_const! {
	sctp_sched_type: c_int;
	SCTP_SS_FCFS,
	SCTP_SS_PRIO,
	SCTP_SS_RR,
	SCTP_SS_FC,
	SCTP_SS_WFQ,
}

#[repr(C)]
#[derive(Debug, KnownLayout)]
pub struct sctp_probeinterval {
	pub spi_assoc_id: sctp_assoc_t,
	pub spi_address: socket2::SockAddrStorage,
	pub spi_interval: u32,
}
