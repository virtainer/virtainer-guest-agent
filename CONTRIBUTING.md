# Contributing

## Build and test

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.95.0 with the
`x86_64-unknown-linux-musl` target); rustup installs it on first use. The
agent ISO is built with `tools/build-iso.sh` (needs `python3` and `xorriso`).

The end-to-end suite boots real cloud images under Cloud Hypervisor. Run
`cargo build --release` first, then `e2e/run.py` (`--only name,name` for a
subset, `--list` for the images). Prerequisites are in the docstring of
`e2e/run.py` and in the README's Test section. The `vga-e2e` password in the
suite is for throwaway test VMs only.

## Windows checks

The platform-independent FAT12 reader, provision schema and state machine,
hostname completion gate, DHCP selection plan, service startup/rollback decisions,
update suppression checkpoints, installed-version updater staging, preservation
of the installed executable during backup, deferred removal decisions and Windows command
table run in the normal Linux test suite. Windows API calls
are isolated under `src/windows/`; the Linux runtime remains behind its own
`target_os = "linux"` modules. Do not add dependencies for Windows seed parsing.

Run Cargo commands sequentially on the shared development machine:

```sh
CARGO_NET_OFFLINE=true cargo check --target x86_64-pc-windows-gnu
CARGO_NET_OFFLINE=true cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings
CARGO_NET_OFFLINE=true cargo test --locked
CARGO_NET_OFFLINE=true cargo clippy --all-targets --locked -- -D warnings
```

Check/Clippy require the installed GNU Windows Rust target, but do not link an
executable. Build a release executable with a Windows linker/toolchain, for
example on Windows with `cargo build --release --locked --target
x86_64-pc-windows-msvc`. An actual Windows guest must verify service start/stop,
host-only hybrid vsock (hundreds of short connections with no failures, and a
service stop while idle and while a client is connected), specialize timing (the
hostname is set there; networking, accounts and keys follow in the service
phase), account/key/timezone/network changes,
script failure/reboot recovery, raw seed unplug and executable update/rollback.
Include a service restart before the specialize reboot, a replacement that
exits during initialization, repeated boots with the failed seed still attached,
a reboot between the backup copy and atomic replacement,
a MAC-selected DHCP reset of an adapter with stale static IPv6 addressing, and
uninstall from the installed executable followed by its deferred removal reboot.

## Third-party code and licences

- This project is Apache-2.0. Do not add GPL code to it.
- **No QEMU source may be added.** The QEMU Guest Agent is GPL-2.0-or-later;
  behaviour is matched from the published QGA documentation and from observing
  qemu-ga, never by copying or translating its source (including the QAPI
  schema file).
- Code adapted from another project needs a compatible licence, its original
  copyright lines kept in the file header, a statement of what changed, and an
  entry in `THIRD_PARTY_NOTICES.md`.
- When `Cargo.lock` changes, run `tools/third-party-licenses.sh` (needs
  `cargo-about` 0.9.2) and commit the updated `LICENSES/THIRD-PARTY-RUST.txt`;
  CI fails if it is stale. CI also runs `cargo deny check licenses advisories`
  against `deny.toml`.

## Source headers

Every source file starts with:

```rust
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Virtainer authors
```

A file adapted from another project keeps the original copyright lines too
(see `src/autoonline.rs`).

## Sign-off

`Signed-off-by:` lines (`git commit -s`) are welcome but not required. By
submitting a contribution you agree it is licensed under Apache-2.0.

## Security issues

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).
