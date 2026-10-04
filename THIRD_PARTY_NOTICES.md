# Third-party notices

Virtainer guest agent is licensed under the Apache License 2.0. It contains
code adapted from the open-source project below, also used under the Apache
License 2.0, and statically links the runtime code listed after it.

The binary carries this file and the licence texts under `LICENSES/` inside
it (`virtainer-guest-agent licenses` prints them), so they travel with it
however it reaches a guest. `tools/build-iso.sh` also puts them on the agent
ISO.

## Kata Containers

- Project: https://github.com/kata-containers/kata-containers
- Version: 4.2.0 (tag `4.2.0`)
- License: Apache License 2.0 (`LICENSES/Apache-2.0.txt`). Version 4.2.0 has
  no NOTICE file.
- Copyright (c) 2019 Ant Financial (the only copyright line in both source
  files below)

| File in this repository | Adapted from | Changes |
| --- | --- | --- |
| `src/autoonline.rs` | `src/agent/src/uevent.rs` (uevent parsing, the `NETLINK_KOBJECT_UEVENT` listener); `src/agent/src/sandbox.rs` (`online_resources`: onlining offline CPUs and memory blocks through sysfs) | Rewritten without tokio, netlink-sys or slog. No sandbox state or watchers. A hot-added CPU or memory block is onlined on its own `add` uevent instead of on an `OnlineCPUMem` request. Only messages from the kernel are accepted. |

`src/autoonline.rs` keeps the original copyright line, carries an
`SPDX-License-Identifier: Apache-2.0` header and states that it was modified.
The rest of this repository is not derived from Kata Containers.

## Not copied: QEMU

The QEMU Guest Agent (`qga/` in QEMU) is licensed GPL-2.0-or-later. None of
its code is in this repository, and the QAPI schema file itself is not
distributed. This agent implements the same wire protocol and command set,
written from the published QGA documentation and from observing qemu-ga's
behaviour. Command names, argument names, error strings and the freeze
allow-list are interface facts reproduced for wire compatibility. QEMU 11.1
was the behavioural reference, and the end-to-end tests compare replies with
the qemu-ga that each test image ships.

## Statically linked runtime code

The binary is built for `x86_64-unknown-linux-musl` and links the following,
all under permissive licenses. Each licence text and copyright notice is
reproduced in the files named below.

| Component | License | Notices |
| --- | --- | --- |
| Rust standard library (1.95.0), LLVM libunwind | MIT OR Apache-2.0; Apache-2.0 WITH LLVM-exception | `LICENSES/RUST-STD.txt` |
| musl libc 1.2.5 (bundled with the Rust musl target) | MIT | `LICENSES/MUSL-COPYRIGHT.txt` |
| `serde`, `serde_core`, `serde_json`, `indexmap`, `equivalent`, `hashbrown`, `itoa`, `base64`, `libc` | MIT OR Apache-2.0 | `LICENSES/THIRD-PARTY-RUST.txt` |
| `memchr` | Unlicense OR MIT | `LICENSES/THIRD-PARTY-RUST.txt` |
| `zmij` (float formatting in `serde_json`) | MIT | `LICENSES/THIRD-PARTY-RUST.txt` |

`LICENSES/THIRD-PARTY-RUST.txt` is generated from `Cargo.lock` by
`tools/third-party-licenses.sh`. It also lists the build-time proc-macro
crates (`serde_derive`, `syn`, `quote`, `proc-macro2`, `unicode-ident`),
which are not linked into the binary. `cargo tree -e normal --target
x86_64-unknown-linux-musl` shows the dependency graph.
