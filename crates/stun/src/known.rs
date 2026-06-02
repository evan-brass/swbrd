use zerocopy::network_endian::{U32, U64};

use crate::Value;

macro_rules! known {
	($($rfc:literal $typ:literal $name:ident)+) => {
		$(
			#[doc = concat!("Defined by ", $rfc)]
			pub const $name: u16 = u16::to_be($typ);
		)+
	};
}

known! {
//	0x0000-0x7FFF Comprehension Required
	"RFC8489" 0x0006 USERNAME
	"RFC8489" 0x0008 MESSAGE_INTEGRITY
	"RFC8489" 0x0009 ERROR_CODE
	"RFC8489" 0x000A UNKNOWN_ATTRIBUTES
	"RFC8656" 0x000C CHANNEL_NUMBER
	"RFC8656" 0x000D LIFETIME
	"RFC8656" 0x0012 XOR_PEER_ADDRESS
	"RFC8656" 0x0013 DATA
	"RFC8489" 0x0014 REALM
	"RFC8489" 0x0015 NONCE
	"RFC8656" 0x0016 XOR_RELAYED_ADDRESS
	"RFC8656" 0x0019 REQUESTED_TRANSPORT
	"RFC8489" 0x001C MESSAGE_INTEGRITY_SHA256
	"RFC8489" 0x0020 XOR_MAPPED_ADDRESS
	"RFC8445" 0x0024 PRIORITY
	"RFC8445" 0x0025 USE_CANDIDATE
//	0x4000-0x7FFF Private Use
//	0x8000-0xFFFF Comprehension Optional
	"RFC8656" 0x8004 ICMP
	"RFC8489" 0x8022 SOFTWARE
	"RFC8489" 0x8023 ALTERNATE_SERVER
	"RFC8489" 0x8028 FINGERPRINT
	"RFC8445" 0x8029 ICE_CONTROLLED
	"RFC8445" 0x802A ICE_CONTROLLING
//	0xC000-0xFFFF Private Use
}

macro_rules! text {
	($($typ:ident),+) => {
		$(
			impl<'i> Value<'i, $typ> for &'i str {
				type Wire = str;
				fn decode(_: &crate::Stun<crate::Iterating>, value: &'i Self::Wire) -> Option<Self> {
					Some(value)
				}
			}
		)+
	};
}
text!(USERNAME, REALM, NONCE, SOFTWARE);

macro_rules! num_attr {
	($($typ:ident $wire:ty:$num:ty)+) => {
		$(
			impl Value<'_, $typ> for $num {
				type Wire = $wire;
				fn decode(_: &crate::Stun<crate::Iterating>, value: &Self::Wire) -> Option<Self> {
					Some(value.get())
				}
			}
		)+
	};
}
num_attr! {
	LIFETIME U32:u32
	PRIORITY U32:u32
	ICE_CONTROLLED U64:u64
	ICE_CONTROLLING U64:u64
}
