use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use std::{
	io::Error,
	mem::ManuallyDrop,
	os::fd::AsRawFd,
	rc::{Rc, Weak},
	time::Duration,
};

/// Poller is a wrapper that handles the Token(usize) -> Weak<T> registration/deregistration
pub struct Poller<T> {
	poll: Poll,
	deregistered: Vec<Weak<T>>,
}
impl<T: AsRawFd> Poller<T> {
	pub fn new(poll: Poll) -> Self {
		Self {
			poll,
			deregistered: Vec::new(),
		}
	}
	pub fn register(&self, client: &Rc<T>, interest: Interest) -> Result<(), Error> {
		let fd = client.as_raw_fd();
		let weak = Rc::downgrade(client).into_raw();
		let token = Token(weak as usize);
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
	pub fn deregister(&mut self, client: Rc<T>) -> Result<(), Error> {
		let fd = client.as_raw_fd();
		let temp = Rc::downgrade(&client);
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
	/// This method must only be called with Tokens that were registered using the Poller *not* on Poll directly, prior to constructing the Poller
	pub fn get(&self, token: Token) -> Option<Rc<T>> {
		let ptr = token.0 as *const T;
		// Attempt to upgrade our *shared* Weak (multiple copies between the registry, and multiple Event's), without decrementing the weak ptr.
		let t = ManuallyDrop::new(unsafe { Weak::from_raw(ptr) });
		// Upgrade takes &self, therefore the ManuallyDrop<Weak<T>> survives past this call.
		t.upgrade()
	}
}
