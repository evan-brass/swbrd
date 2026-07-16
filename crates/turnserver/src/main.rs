#[cfg(not(target_os = "linux"))]
fn main() {
	eprintln!("We've been trying to reach you about your car's extended warranty.");
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::main;
