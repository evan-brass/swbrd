use eyre::Result;
use std::{
	collections::{hash_map::Entry, HashMap},
	net::{IpAddr, SocketAddr},
	ops::DerefMut,
	sync::Arc,
};

use tokio::{
	io::AsyncWriteExt,
	net::{tcp::OwnedWriteHalf, TcpListener, TcpStream},
	sync::{Mutex, RwLock},
	io::BufWriter,
	io::BufReader
};

mod turn;
use turn::{TurnReq, TurnRes};

// TODO: Switch from reading / writing to the TcpStream directly to using a buffered reader / writer
async fn handle(
	stream: TcpStream,
	addr: SocketAddr,
	writers: Arc<RwLock<HashMap<SocketAddr, Mutex<BufWriter<OwnedWriteHalf>>>>>,
) {
	// Canonicalize the addr
	let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());

	let lifetime = 3600;

	let (reader, writer) = stream.into_split();
	// Buffer our reads / writes
	let (mut reader, writer) = (BufReader::new(reader), BufWriter::new(writer));

	match writers.write().await.entry(addr) {
		Entry::Occupied(..) => {
			eprintln!("Multiple TCP Streams from the same address???: {addr}");
			return;
		}
		Entry::Vacant(v) => {
			v.insert(Mutex::new(writer));
		}
	}

	loop {
		let req = match TurnReq::read(&mut reader).await {
			Err(e) => {
				eprintln!("{e}");
				break;
			}
			Ok(v) => v,
		};

		let (res, dst) = match req {
			TurnReq::Allocate { txid } => (
				TurnRes::Allocate {
					txid,
					lifetime,
					relayed: addr,
				},
				addr,
			),
			TurnReq::Permission { txid, .. } => (TurnRes::Permission { txid }, addr),
			TurnReq::Refresh { txid } => (TurnRes::Refresh { txid, lifetime }, addr),
			TurnReq::BindChannel { .. } => continue,
			TurnReq::Send { txid, peer, data } => (
				TurnRes::Data {
					txid,
					peer: addr,
					data,
				},
				peer,
			),
			TurnReq::ChannelData { .. } => break,
		};
		// Canonicalize dst (we canonicalize both addr and dst so that our hashmap works properly with socketaddr keys)
		let dst = SocketAddr::new(dst.ip().to_canonical(), dst.port());

		let writers = writers.read().await;

		// Send the response to dst (dst might be a broadcast address, in which case we send it to all the writable sockets)
		if dst.ip() == IpAddr::from([255, 255, 255, 255]) {
			for writable in writers.values() {
				let mut writable = writable.lock().await;
				let _ = res.write(writable.deref_mut()).await;
				let _ = writable.flush().await;
			}
		} else if let Some(writable) = writers.get(&dst) {
			let mut writable = writable.lock().await;
			let _ = res.write(writable.deref_mut()).await;
			let _ = writable.flush().await;
		} else {
			eprintln!("[Send Failed] {dst} {res:?}");
		}
	}

	writers.write().await.remove(&addr);
}

#[tokio::main]
async fn main() -> Result<()> {
	let listener = TcpListener::bind("[::]:3478").await?;
	let writers = Arc::new(RwLock::new(HashMap::new()));

	loop {
		let Ok((stream, addr)) = listener.accept().await else {
			continue;
		};
		tokio::spawn(handle(stream, addr, writers.clone()));
	}
}
