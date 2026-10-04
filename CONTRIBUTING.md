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
