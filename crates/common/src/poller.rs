use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use std::{
	io::{Error, ErrorKind},
	mem::ManuallyDrop,
	os::fd::RawFd,
	rc::{Rc, Weak},
	time::Duration,
};

const _: () = assert!(
	usize::BITS == 64,
	"Poller Tokens assume 64-bit pointers with a clear most-significant bit"
);

/// Set in a Token that carries a Static id rather than a Weak<T>.  Heap pointers are
/// user-space (bit 63 clear), so this never collides with a real Weak.
const STATIC: usize = 1 << (usize::BITS - 1);
/// The Flag lives in the alignment bits of the Weak<T> pointer.
const FLAG_MASK: usize = 0b11;

/// Which of an object's sources produced an event.  Stored in T's alignment bits, so
/// T must be aligned to at least 4.  Give the variants meaning at the call site:
/// `const RELAY: Flag = Flag::A;`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Flag {
	A = 0,
	B = 1,
	C = 2,
	D = 3,
}

/// A Token that isn't a Weak<T>: listening sockets, the TUN device, etc.  Derived
/// PartialEq/Eq make `const TUN: Static = Static(0);` usable directly as a pattern.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Static(pub u8);
impl From<Static> for Token {
	fn from(Static(id): Static) -> Self {
		Token(STATIC | id as usize)
	}
}

/// Resolves (object, flag) to the fd registered under it.  None means this flag has
/// no source right now: a socket that isn't open yet, or one already taken away.
pub trait Sourced {
	fn fd(&self, flag: Flag) -> Option<RawFd>;
}

/// Poller is a wrapper that handles the Token(usize) -> (Flag, Weak<T>) registration/deregistration
pub struct Poller<T> {
	poll: Poll,
	deregistered: Vec<Weak<T>>,
}
impl<T: Sourced> Poller<T> {
	const ALIGN: () = assert!(
		align_of::<T>() > FLAG_MASK,
		"Poller stores the Flag in T's alignment bits, so T must be aligned to at least 4"
	);
	pub fn new(poll: Poll) -> Self {
		Self {
			poll,
			deregistered: Vec::new(),
		}
	}
	/// Register an fd that isn't owned by a T.  `get` reports it as Err(id).
	pub fn register_static(&self, fd: RawFd, id: Static, interest: Interest) -> Result<(), Error> {
		self.poll
			.registry()
			.register(&mut SourceFd(&fd), id.into(), interest)
	}
	/// Must be paired with exactly one deregister(client, flag) per successful call.
	pub fn register(&self, client: &Rc<T>, flag: Flag, interest: Interest) -> Result<(), Error> {
		let () = Self::ALIGN;
		let Some(fd) = client.fd(flag) else {
			return Err(Error::new(ErrorKind::NotFound, "no fd for this Flag"));
		};
		let weak = Rc::downgrade(client).into_raw();
		debug_assert!(weak as usize & (STATIC | FLAG_MASK) == 0);
		let token = Token(weak as usize | flag as usize);
		if let Err(reason) = self
			.poll
			.registry()
			.register(&mut SourceFd(&fd), token, interest)
		{
			// If registration fails, reconstruct the Weak immediately
			unsafe {
				Weak::from_raw(weak);
			}
			Err(reason)
		} else {
			Ok(())
		}
	}
	/// Deregister must happen *before* the flag's socket is dropped or replaced: once
	/// fd() reports None we skip the epoll_ctl and leave the loaned Weak outstanding,
	/// which pins the allocation forever.
	pub fn deregister(&mut self, client: &Rc<T>, flag: Flag) -> Result<(), Error> {
		// A flag with no fd was never registered, and so never loaned out a Weak
		let Some(fd) = client.fd(flag) else {
			return Ok(());
		};
		let temp = Rc::downgrade(client);
		// Reconstruct the Weak we loaned to the OS as the Token, then keep it in our list for final disposal immediately before re-polling
		self.deregistered
			.push(unsafe { Weak::from_raw(temp.as_ptr()) });

		self.poll.registry().deregister(&mut SourceFd(&fd))
	}
	pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> Result<(), Error> {
		// The Token Weak is released right before we poll, since it will no longer appear in any future Event
		self.deregistered.clear();
		self.poll.poll(events, timeout)
	}
	/// Classify any Token: a Static id, a released client (Ok(None)), or the flag +
	/// object that registered it.
	pub fn get(&self, token: Token) -> Result<Option<(Flag, Rc<T>)>, Static> {
		let () = Self::ALIGN;
		if token.0 & STATIC != 0 {
			return Err(Static(token.0 as u8));
		}
		let flag = match token.0 & FLAG_MASK {
			0 => Flag::A,
			1 => Flag::B,
			2 => Flag::C,
			_ => Flag::D,
		};
		let ptr = (token.0 & !FLAG_MASK) as *const T;
		// Attempt to upgrade our *shared* Weak (multiple copies between the registry, and multiple Event's), without decrementing the weak ptr.
		let t = ManuallyDrop::new(unsafe { Weak::from_raw(ptr) });
		// Upgrade takes &self, therefore the ManuallyDrop<Weak<T>> survives past this call.
		Ok(t.upgrade().map(|rc| (flag, rc)))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::{
		io::{PipeReader, PipeWriter, Write, pipe},
		os::fd::AsRawFd,
	};

	/// Two sources on one object, plus a u64 to force align 8
	struct Client {
		a: PipeReader,
		b: Option<PipeReader>,
		_align: u64,
	}
	impl Sourced for Client {
		fn fd(&self, flag: Flag) -> Option<RawFd> {
			match flag {
				Flag::A => Some(self.a.as_raw_fd()),
				Flag::B => self.b.as_ref().map(AsRawFd::as_raw_fd),
				_ => None,
			}
		}
	}
	fn client() -> Result<(Rc<Client>, PipeWriter, PipeWriter), Error> {
		let (ar, aw) = pipe()?;
		let (br, bw) = pipe()?;
		Ok((
			Rc::new(Client {
				a: ar,
				b: Some(br),
				_align: 0,
			}),
			aw,
			bw,
		))
	}
	fn poller() -> Result<(Poller<Client>, Events), Error> {
		Ok((Poller::new(Poll::new()?), Events::with_capacity(8)))
	}

	#[test]
	fn two_flags_one_object() -> Result<(), Error> {
		let (mut poll, mut events) = poller()?;
		let (client, mut aw, mut bw) = client()?;
		poll.register(&client, Flag::A, Interest::READABLE)?;
		poll.register(&client, Flag::B, Interest::READABLE)?;
		aw.write_all(b"a")?;
		bw.write_all(b"b")?;

		let mut seen = Vec::new();
		while seen.len() < 2 {
			poll.poll(&mut events, Some(Duration::from_secs(1)))?;
			for e in events.iter() {
				let Ok(Some((flag, got))) = poll.get(e.token()) else {
					panic!("expected a client event")
				};
				assert!(Rc::ptr_eq(&got, &client));
				seen.push(flag);
			}
		}
		seen.sort_by_key(|f| *f as usize);
		assert_eq!(seen, [Flag::A, Flag::B]);

		poll.deregister(&client, Flag::A)?;
		poll.deregister(&client, Flag::B)?;
		Ok(())
	}

	#[test]
	fn static_passthrough() -> Result<(), Error> {
		const ID: Static = Static(7);
		let (mut poll, mut events) = poller()?;
		let (r, mut w) = pipe()?;
		poll.register_static(r.as_raw_fd(), ID, Interest::READABLE)?;
		w.write_all(b"!")?;

		poll.poll(&mut events, Some(Duration::from_secs(1)))?;
		let e = events.iter().next().expect("no event");
		assert!(matches!(poll.get(e.token()), Err(ID)));
		Ok(())
	}

	#[test]
	fn released_client() -> Result<(), Error> {
		let (mut poll, mut events) = poller()?;
		let (client, mut aw, _bw) = client()?;
		poll.register(&client, Flag::A, Interest::READABLE)?;
		aw.write_all(b"a")?;
		poll.poll(&mut events, Some(Duration::from_secs(1)))?;
		let token = events.iter().next().expect("no event").token();

		// Deregistering is what releases the loaned Weak, but not until the next poll
		poll.deregister(&client, Flag::A)?;
		drop(client);
		assert!(matches!(poll.get(token), Ok(None)));

		// ...and the release itself must not double free
		poll.poll(&mut events, Some(Duration::from_millis(10)))?;
		Ok(())
	}

	#[test]
	fn static_round_trip() {
		let poll: Poller<Client> = Poller::new(Poll::new().unwrap());
		for id in [0, 1, 42, u8::MAX] {
			let Err(got) = poll.get(Static(id).into()) else {
				panic!("Static token decoded as a Weak")
			};
			assert_eq!(got, Static(id));
		}
	}
}
