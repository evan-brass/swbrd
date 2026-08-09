#![doc = include_str!("../README.md")]

use nix::{
	getsockopt_impl, sockopt_impl,
	sys::socket::{GetSockOpt, SetSockOpt, sockopt::Ipv6DontFrag},
};
pub use socket2;
use std::{io, os::fd::AsFd};

pub trait SocketQueueExt {
	/// Queries how much data is queued into the send buffer.
	/// Includes both unsent, and sent but unacked data.
	/// On linux this ioctl is available on both UDP and TCP sockets
	/// On MacOS, I don't know.
	fn send_queue_len(&self) -> io::Result<usize>;
}

pub trait SocketMtuExt {
	/// Gets the OS path MTU estimate
	fn path_mtu(&self) -> io::Result<u32>;
	/// Whether the OS should fragment over sized packets or expose the PMTU as send errors.
	fn set_path_mtu_discovery(&self, discover: bool) -> io::Result<()>;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ip6_mtuinfo {
	pub ip6m_addr: libc::sockaddr_in6,
	pub ip6m_mtu: u32,
}

#[cfg(target_os = "linux")]
mod linux {
	use crate::*;
	use nix::setsockopt_impl;
	use socket2::Domain;
	use std::os::fd::AsRawFd;

	nix::ioctl_read_bad!(ioctl_tiocoutq, libc::TIOCOUTQ, std::ffi::c_int);
	impl SocketQueueExt for socket2::SockRef<'_> {
		fn send_queue_len(&self) -> io::Result<usize> {
			let mut ret = 0;
			assert_eq!(
				unsafe { ioctl_tiocoutq(self.as_raw_fd(), &mut ret) }?,
				0,
				"TIOCOUTQ returned nonzero"
			);
			Ok(ret as usize)
		}
	}
	sockopt_impl!(
		Ip6MtuInfo,
		GetOnly,
		libc::IPPROTO_IPV6,
		libc::IPV6_PATHMTU,
		ip6_mtuinfo
	);
	sockopt_impl!(
		IpMtuDiscover,
		Both,
		libc::IPPROTO_IP,
		libc::IP_MTU_DISCOVER,
		std::ffi::c_int
	);
	impl SocketMtuExt for socket2::SockRef<'_> {
		fn path_mtu(&self) -> io::Result<u32> {
			let info = Ip6MtuInfo.get(&self.as_fd())?;
			Ok(info.ip6m_mtu)
		}
		fn set_path_mtu_discovery(&self, discover: bool) -> io::Result<()> {
			IpMtuDiscover.set(
				&self.as_fd(),
				if discover {
					&libc::IP_PMTUDISC_DO
				} else {
					&libc::IP_PMTUDISC_WANT
				},
			)?;
			if Domain::IPV6 == self.domain()? {
				Ipv6DontFrag.set(&self.as_fd(), &discover)?;
			}
			Ok(())
		}
	}
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod macos {
	use crate::*;
	use std::io::Error;

	sockopt_impl!(
		SoNWrite,
		GetOnly,
		libc::SOL_SOCKET,
		libc::SO_NWRITE,
		std::ffi::c_int // TODO: Verify usize vs c_int as the value (nix might even make those the same thing internally?)
	);
	// Not present in the libc crate, because __APPLE_USE_RFC_3542 must be defined
	const IPV6_PATHMTU: std::ffi::c_int = 44;
	sockopt_impl!(
		Ip6MtuInfo,
		GetOnly,
		libc::IPPROTO_IPV6,
		IPV6_PATHMTU,
		ip6_mtuinfo
	);
	impl SocketQueueExt for socket2::SockRef<'_> {
		fn send_queue_len(&self) -> io::Result<usize> {
			let ret = SoNWrite
				.get(&self.as_fd())
				.map_err(|_| Error::last_os_error())?;
			Ok(ret as usize)
		}
	}
	impl SocketMtuExt for socket2::SockRef<'_> {
		fn path_mtu(&self) -> io::Result<u32> {
			let mtu_info = Ip6MtuInfo.get(&self.as_fd())?;
			Ok(mtu_info.ip6m_mtu)
		}
		fn set_path_mtu_discovery(&self, discover: bool) -> io::Result<()> {
			Ipv6DontFrag.set(&self.as_fd(), &discover)?;
			Ok(())
		}
	}
}
