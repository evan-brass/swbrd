use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
#[allow(unused)]
pub enum TurnReq {
	Allocate {
		txid: [u8; 12],
	},
	Refresh {
		txid: [u8; 12],
	},
	Permission {
		txid: [u8; 12],
		peer: SocketAddr,
	},
	Send {
		txid: [u8; 12],
		peer: SocketAddr,
		data: Vec<u8>,
	},
	BindChannel {
		txid: [u8; 12],
		peer: SocketAddr,
		channel: u16,
	},
	ChannelData {
		channel: u16,
		data: Vec<u8>,
	},
}
#[derive(Debug)]
#[allow(unused)]
pub enum TurnRes {
	Allocate {
		txid: [u8; 12],
		lifetime: u32,
		relayed: SocketAddr,
		// mapped: SocketAddr // We use the mapped address as the relayed address
	},
	Refresh {
		txid: [u8; 12],
		lifetime: u32,
	},
	Permission {
		txid: [u8; 12],
	},
	Data {
		txid: [u8; 12],
		peer: SocketAddr,
		data: Vec<u8>,
	},
	BindChannel {
		txid: [u8; 12],
	},
	ChannelData {
		channel: u16,
		data: Vec<u8>,
	},
}

impl TurnReq {
	pub async fn read<T: AsyncReadExt + Unpin>(io: &mut T) -> Result<Self, Error> {
		let typ = io.read_u16().await?;
		let length = io.read_u16().await?;
		let mut txid = [0; 12];
		let mut peer = None;
		let mut data = None;
		let mut channel = None;
		if typ < 0x4000 {
			if length % 4 != 0 {
				return Err(Error::other("STUN Packet length is unaligned"));
			}
			let magic = io.read_u32().await?;
			if magic != 0x2112A442 {
				return Err(Error::other("STUN bad magic"));
			}
			io.read_exact(&mut txid).await?;

			let xor_bytes: [u8; 16] = std::array::from_fn(|i| match i {
				0..=3 => 0x2112A442u32.to_be_bytes()[i],
				_ => txid[i - 4],
			});

			// Parse the attributes
			let mut i = 0;
			while i < length {
				let attr_type = io.read_u16().await?;
				let attr_length = io.read_u16().await?;
				i += 4;

				let mut next_i = i + attr_length;
				// Pad out attribute to 4-byte boundary
				while next_i % 4 != 0 {
					next_i += 1;
				}
				// If the attribute length pushes us past the length of the packet then error
				if next_i > length {
					return Err(Error::other("STUN attribute surpasses message length"));
				}

				match attr_type {
					0x000C /* Channel Number */ if channel.is_none() => {
						if attr_length != 4 { return Err(Error::other("TURN ChannelNumber attribute was the wrong length")); }
						let num = io.read_u16().await?;
						io.read_u16().await?;
						i += 4;

						if !(0x4000..=0x7ffe).contains(&num) { return Err(Error::other("TURN ChannelNumber attribute's value was outside the valid range for TURN Channel numbers")); }
						channel = Some(num);
					},
					0x0012 /* Peer Address */ if peer.is_none() => {
						if attr_length < 8 { return Err(Error::other("TURN PeerAddress attribute was too short")); }
						io.read_u8().await?;
						let family = io.read_u8().await?;
						let port = io.read_u16().await? ^ 0x2112;
						i += 4;
						let ip = match family {
							0x01 => {
								let mut bytes = [0; 4];
								io.read_exact(&mut bytes).await?;
								i += 4;
								IpAddr::V4(Ipv4Addr::from(std::array::from_fn(|i| bytes[i] ^ xor_bytes[i])))
							},
							0x02 => {
								let mut bytes = [0; 16];
								io.read_exact(&mut bytes).await?;
								i += 16;
								IpAddr::V6(Ipv6Addr::from(std::array::from_fn(|i| bytes[i] ^ xor_bytes[i])))
							},
							_ => { return Err(Error::other("TURN PeerAddress attribute had unknown family")); }
						};
						peer = Some(SocketAddr::new(ip, port));
					},
					0x0013 /* Data */ if data.is_none() => {
						let mut ret = vec![0; attr_length as usize];
						io.read_exact(&mut ret).await?;
						i += ret.len() as u16;
						data = Some(ret);
					},
					_ => {}
				}

				while i < next_i {
					io.read_u8().await?;
					i += 1;
				}
			}
		}
		Ok(match typ {
			0x003 /* Allocate */ => {
				TurnReq::Allocate { txid }
			},
			0x004 /* Refresh */ => {
				TurnReq::Refresh { txid }
			},
			0x0016 /* Send Indication (0x006 | IND)*/ => {
				TurnReq::Send {
					txid,
					peer: peer.ok_or(Error::other("TURN Send was missing a PeerAddress attribute"))?,
					data: data.ok_or(Error::other("TURN Send was missing a Data attribute"))?
				}
			},
			0x008 /* Permission */ => {
				TurnReq::Permission {
					txid,
					peer: peer.ok_or(Error::other("TURN Permission was missing a PeerAddress attribute"))?
				}
			},
			0x009 /* ChannelBind */ => {
				TurnReq::BindChannel {
					txid,
					peer: peer.ok_or(Error::other("TURN BindChannel was missing a PeerAddress attribute"))?,
					channel: channel.ok_or(Error::other("TURN BindChannel was missing a ChannelNumber attribute"))?
				}
			},
			0x4000..=0x7ffe /* ChannelData */ => {
				let channel = typ;
				let mut data = vec![0; length as usize];
				io.read_exact(&mut data).await?;

				// Pad the packet out to 4 bytes
				let mut length = length;
				while length % 4 > 0 {
					io.read_u8().await?;
					length += 1;
				}

				TurnReq::ChannelData { channel, data }
			},
			_ => return Err(Error::other(format!("TURN unexpected type {typ}")))
		})
	}
}
impl TurnRes {
	pub async fn write<T: AsyncWriteExt + Unpin>(&self, io: &mut T) -> Result<(), Error> {
		#[allow(clippy::unusual_byte_groupings)]
		const SUC: u16 = 0b00_00000_1_000_0_0000;
		#[allow(clippy::unusual_byte_groupings)]
		const IND: u16 = 0b00_00000_0_000_1_0000;

		let typ = match self {
			TurnRes::Allocate { .. } => SUC | 0x003,
			TurnRes::Refresh { .. } => SUC | 0x004,
			TurnRes::Permission { .. } => SUC | 0x008,
			TurnRes::BindChannel { .. } => SUC | 0x009,
			TurnRes::Data { .. } => IND | 0x007,
			TurnRes::ChannelData { channel, .. } => *channel,
		};
		io.write_u16(typ).await?;

		let (length, txid) = match self {
			TurnRes::ChannelData { data, .. } => {
				io.write_u16(data.len() as u16).await?;
				io.write_all(data).await?;

				// Pad the message out to 4-bytes
				let mut pad = data.len();
				while pad % 4 != 0 {
					io.write_u8(0).await?;
					pad += 1;
				}

				return Ok(());
			}
			TurnRes::Allocate { relayed, txid, .. } => (
				8 + 2 * if relayed.ip().to_canonical().is_ipv4() {
					12
				} else {
					24
				},
				txid,
			),
			TurnRes::Permission { txid } => (0, txid),
			TurnRes::Refresh { txid, .. } => (8, txid),
			TurnRes::BindChannel { txid } => (0, txid),
			TurnRes::Data { peer, data, txid } => {
				let mut data_len = 4 + data.len() as u16;
				while data_len % 4 != 0 {
					data_len += 1;
				}
				(
					data_len
						+ if peer.ip().to_canonical().is_ipv4() {
							12
						} else {
							24
						},
					txid,
				)
			}
		};
		io.write_u16(length).await?;
		io.write_u32(0x2112A442).await?;
		io.write_all(txid).await?;

		let xor_bytes: [u8; 16] = std::array::from_fn(|i| match i {
			0..=3 => 0x2112A442u32.to_be_bytes()[i],
			_ => txid[i - 4],
		});

		// Helper function for writing xaddr attributes (This function will write the attribute length, but you must have written the attribute type)
		async fn write_xaddr<T: AsyncWriteExt + Unpin>(
			addr: &SocketAddr,
			xor_bytes: &[u8; 16],
			io: &mut T,
		) -> Result<(), Error> {
			let ip = addr.ip().to_canonical();
			// Write the relayed address
			io.write_u16(if ip.is_ipv4() { 8 } else { 20 }).await?;
			io.write_u8(0).await?;
			match ip {
				IpAddr::V4(v4) => {
					io.write_u8(0x01).await?;
					io.write_u16(addr.port() ^ 0x2112).await?;
					let bytes = v4.octets();
					io.write_all(&std::array::from_fn::<u8, 4, _>(|i| {
						bytes[i] ^ xor_bytes[i]
					}))
					.await?;
				}
				IpAddr::V6(v6) => {
					io.write_u8(0x02).await?;
					io.write_u16(addr.port() & 0x2112).await?;
					let bytes = v6.octets();
					io.write_all(&std::array::from_fn::<u8, 16, _>(|i| {
						bytes[i] ^ xor_bytes[i]
					}))
					.await?;
				}
			};
			Ok(())
		}

		// Write the attributes
		match self {
			TurnRes::Allocate {
				lifetime, relayed, ..
			} => {
				// Write the lifetime
				io.write_u16(0x000D).await?;
				io.write_u16(4).await?;
				io.write_u32(*lifetime).await?;

				// Write the xmapped address
				io.write_u16(0x0020).await?;
				write_xaddr(relayed, &xor_bytes, io).await?;

				// Write the relayed address
				io.write_u16(0x0016).await?;
				write_xaddr(relayed, &xor_bytes, io).await?;
			}
			TurnRes::Refresh { lifetime, .. } => {
				// Write the lifetime
				io.write_u16(0x000D).await?;
				io.write_u16(4).await?;
				io.write_u32(*lifetime).await?;
			}
			TurnRes::Data { peer, data, .. } => {
				// Write the peer address
				io.write_u16(0x0012).await?;
				write_xaddr(peer, &xor_bytes, io).await?;
				// Write the data
				io.write_u16(0x0013).await?;
				io.write_u16(data.len() as u16).await?;
				io.write_all(data).await?;

				let mut padded = data.len();
				while padded % 4 != 0 {
					io.write_u8(0).await?;
					padded += 1;
				}
			}
			_ => {}
		}

		Ok(())
	}
}
