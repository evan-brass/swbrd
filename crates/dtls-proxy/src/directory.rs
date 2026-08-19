//! The directory: which extension a datachannel is patched to.
//!
//! Read from `/etc/swbrd/directory.d/*.toml` in lexical order.  First match
//! wins; a channel that matches nothing has its stream reset.

use std::{
	fs,
	path::{Path, PathBuf},
};

use eyre::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
	/// Framed: one frame per SCTP message, carrying ppid and flags.
	#[default]
	Message,
	/// Raw bytes, no framing.  For tunnelling byte-stream services.
	Stream,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Extension {
	pub name: String,
	/// Matched against the datachannel's DCEP protocol.  `*` matches any run of
	/// characters, so `:*/tcp` works.
	pub protocol: String,
	pub socket: PathBuf,
	#[serde(default)]
	pub mode: Mode,
	/// Base36 peer ids allowed to use this extension, or `["*"]` for any.
	///
	/// WebRTC certificates are self-signed and anyone can mint one, so a
	/// fingerprint is a trust-on-first-use identifier rather than an
	/// authenticated principal.  This is coarse authorization; an extension
	/// still owns its own notion of who a peer is.
	#[serde(default)]
	pub allow: Vec<String>,
	/// Relative weight for the SCTP stream scheduler.
	#[serde(default)]
	pub priority: u16,
	/// How long a channel may make no progress before its circuit is torn down.
	#[serde(default = "default_stall_ms")]
	pub stall_ms: u64,
}

fn default_stall_ms() -> u64 {
	5_000
}

#[derive(Debug, Default, Deserialize)]
struct File {
	#[serde(default)]
	extension: Vec<Extension>,
}

#[derive(Debug, Default)]
pub struct Directory {
	extensions: Vec<Extension>,
}

impl Directory {
	/// Load every `*.toml` under `dir`, in lexical order.  A missing directory
	/// is an empty directory: the daemon still runs, it just patches nothing.
	pub fn load(dir: &Path) -> Result<Self> {
		let mut paths: Vec<PathBuf> = match fs::read_dir(dir) {
			Ok(entries) => entries
				.filter_map(|e| e.ok())
				.map(|e| e.path())
				.filter(|p| p.extension().is_some_and(|e| e == "toml"))
				.collect(),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
				tracing::warn!(dir = %dir.display(), "no directory: nothing will be patched");
				return Ok(Self::default());
			}
			Err(e) => return Err(e).wrap_err_with(|| format!("reading {}", dir.display())),
		};
		paths.sort();

		let mut extensions = Vec::new();
		for path in paths {
			let text = fs::read_to_string(&path)
				.wrap_err_with(|| format!("reading {}", path.display()))?;
			let file: File =
				toml::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?;
			extensions.extend(file.extension);
		}
		for e in &extensions {
			tracing::info!(name = %e.name, protocol = %e.protocol, socket = %e.socket.display(), "extension");
		}
		Ok(Self { extensions })
	}

	/// The extension serving `protocol` for `peer`, if any.  First match wins,
	/// and a match whose ACL excludes the peer does not fall through to a later
	/// entry -- that would let a broad rule quietly grant what a narrow one
	/// denied.
	pub fn lookup(&self, protocol: &str, peer: &str) -> Option<&Extension> {
		let matched = self
			.extensions
			.iter()
			.find(|e| glob(&e.protocol, protocol))?;
		matched.permits(peer).then_some(matched)
	}
}

impl Extension {
	pub fn permits(&self, peer: &str) -> bool {
		self.allow.iter().any(|a| a == "*" || a == peer)
	}
}

/// `*` matches any run of characters, including none.  Everything else is
/// literal.  Deliberately not a regex: these patterns come from a config file
/// an operator writes by hand.
fn glob(pattern: &str, text: &str) -> bool {
	let mut parts = pattern.split('*');
	let Some(first) = parts.next() else {
		return pattern == text;
	};
	let Some(mut rest) = text.strip_prefix(first) else {
		return false;
	};
	let Some(last) = parts.next_back() else {
		// No '*' at all: the prefix had to be the whole string.
		return rest.is_empty();
	};
	for part in parts {
		let Some(at) = rest.find(part) else {
			return false;
		};
		rest = &rest[at + part.len()..];
	}
	// The final literal has to land at the end, without overlapping what the
	// middle parts already consumed.
	rest.len() >= last.len() && rest.ends_with(last)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn exact_patterns() {
		assert!(glob("chat.v1", "chat.v1"));
		assert!(!glob("chat.v1", "chat.v2"));
		assert!(!glob("chat.v1", "chat.v1x"));
		assert!(!glob("chat.v1", "xchat.v1"));
	}

	#[test]
	fn wildcards() {
		assert!(glob("*", ""));
		assert!(glob("*", "anything"));
		assert!(glob("chat.*", "chat.v1"));
		assert!(glob("*.v1", "chat.v1"));
		assert!(glob("chat.*", "chat."));
		assert!(!glob("chat.*", "chatx"));
	}

	/// The pattern the existing swbrd code reaches for.
	#[test]
	fn port_tcp_pattern() {
		assert!(glob(":*/tcp", ":8080/tcp"));
		assert!(glob(":*/tcp", ":1/tcp"));
		assert!(!glob(":*/tcp", ":8080/udp"));
		assert!(!glob(":*/tcp", "8080/tcp"));
	}

	/// A literal must not be matched twice by overlapping with the prefix.
	#[test]
	fn overlapping_literals() {
		assert!(!glob("ab*ba", "aba"));
		assert!(glob("ab*ba", "abba"));
		assert!(glob("ab*ba", "abXba"));
	}

	#[test]
	fn acl_defaults_to_denying() {
		let ext = Extension {
			name: "chat".into(),
			protocol: "chat.v1".into(),
			socket: "/run/swbrd/ext/chat.sock".into(),
			mode: Mode::Message,
			allow: Vec::new(),
			priority: 0,
			stall_ms: 5000,
		};
		// An extension that lists nobody serves nobody: safer than the reverse
		// for a config file where a missing key is easy to overlook.
		assert!(!ext.permits("anyone"));
	}

	#[test]
	fn acl_matches_wildcard_and_exact() {
		let mut ext = Extension {
			name: "chat".into(),
			protocol: "chat.v1".into(),
			socket: "/run/swbrd/ext/chat.sock".into(),
			mode: Mode::Message,
			allow: vec!["*".into()],
			priority: 0,
			stall_ms: 5000,
		};
		assert!(ext.permits("whoever"));
		ext.allow = vec!["abc".into(), "def".into()];
		assert!(ext.permits("abc"));
		assert!(ext.permits("def"));
		assert!(!ext.permits("ghi"));
	}

	/// A denied match must not fall through to a broader later rule.
	#[test]
	fn denied_match_does_not_fall_through() {
		let directory = Directory {
			extensions: vec![
				Extension {
					name: "private".into(),
					protocol: "chat.v1".into(),
					socket: "/run/a.sock".into(),
					mode: Mode::Message,
					allow: vec!["alice".into()],
					priority: 0,
					stall_ms: 5000,
				},
				Extension {
					name: "public".into(),
					protocol: "*".into(),
					socket: "/run/b.sock".into(),
					mode: Mode::Message,
					allow: vec!["*".into()],
					priority: 0,
					stall_ms: 5000,
				},
			],
		};
		assert_eq!(
			directory.lookup("chat.v1", "alice").unwrap().name,
			"private"
		);
		assert!(directory.lookup("chat.v1", "bob").is_none());
		assert_eq!(directory.lookup("other", "bob").unwrap().name, "public");
	}

	#[test]
	fn parses_a_directory_file() {
		let file: File = toml::from_str(
			r#"
			[[extension]]
			name = "chat"
			protocol = "chat.v1"
			socket = "/run/swbrd/ext/chat.sock"
			allow = ["*"]

			[[extension]]
			name = "vpn"
			protocol = "IP6"
			socket = "/run/swbrd/ext/vpn.sock"
			mode = "message"
			priority = 1024
			stall_ms = 1000
			allow = ["abc"]
			"#,
		)
		.unwrap();
		assert_eq!(file.extension.len(), 2);
		assert_eq!(file.extension[0].mode, Mode::Message);
		assert_eq!(file.extension[0].stall_ms, 5000);
		assert_eq!(file.extension[1].priority, 1024);
	}
}
