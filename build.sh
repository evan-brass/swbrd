# Cross compile binaries.  I have to `sudo apt install crossbuild-essential-amd64` to get the linker that is specified in .cargo/config.toml.
cargo install --target x86_64-unknown-linux-gnu --root opt/amd64 --path crates/ice-dissolve
cargo install --target x86_64-unknown-linux-gnu --root opt/amd64 --path crates/turnserver

# Cross compile deno scripts
deno compile --target x86_64-unknown-linux-gnu --allow-read --allow-write -o opt/amd64/bin/cert-rotate ./scripts/cert-rotate.js

# My systemd files assume these binaries are placed into /opt/
scp opt/amd64/bin/* root@turn.evan-brass.net:/opt/
