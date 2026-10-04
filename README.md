# Virtainer guest agent

[Virtainer](https://virtainer.io) is a virtualization platform; this is its guest
component for classic VMs. It is a QEMU Guest Agent (QGA) compatible agent for
x86_64 Linux VMs on Cloud Hypervisor: one static binary (about 1 MB, no
runtime dependencies), reached by the host over vsock, that installs itself in
systemd and OpenRC guests.

It replaces installing `qemu-guest-agent` in every guest, which needs internet
access at first boot, per-distro package names, unit overrides and SELinux
policy. On Cloud Hypervisor qemu-ga also needs a vsock override, because
Cloud Hypervisor's virtio-console has no named virtio-serial ports.

## What it speaks

- **Transport:** AF_VSOCK, port **100**, any CID. Only the host (CID 2) may
  connect; local and nested-VM callers are dropped (see [Security](#security)).
  On the host side this is Cloud Hypervisor's hybrid vsock socket:
  `CONNECT 100\n` → `OK <n>\n`, then the byte stream.
- **Protocol:** QGA's wire format, matching qemu-ga's observable behaviour:
  the JSON stream (no newline required), the `0xFF` resync byte,
  `guest-sync-delimited`, `id` echo, QAPI error classes and texts, no reply to
  a successful `guest-shutdown`, and QEMU's JSON spelling (`{"return": {}}`,
  ASCII-only). The end-to-end suite diffs ten read-only commands against the
  qemu-ga that each guest image ships (see [Test](#test)); the rest is checked
  against the QGA documentation, not against a reference run.
- **Commands:** every Linux command of QEMU 11.1's `qga/qapi-schema.json`,
  except the three `guest-suspend-*` commands, which behave badly on Cloud
  Hypervisor (see [Differences from qemu-ga](#differences-from-qemu-ga)).

| Group | Commands |
| --- | --- |
| Session | `guest-sync`, `guest-sync-delimited`, `guest-ping`, `guest-info` |
| Snapshots | `guest-fsfreeze-status`, `-freeze`, `-freeze-list`, `-thaw`, `guest-fstrim` |
| Identity | `guest-get-osinfo`, `guest-get-host-name`, `guest-get-timezone`, `guest-get-users` |
| Network | `guest-network-get-interfaces`, `guest-network-get-route` |
| Storage | `guest-get-fsinfo`, `guest-get-disks` (PCI address, serial, device node, NVMe SMART) |
| Power and time | `guest-shutdown`, `guest-get-time`, `guest-set-time` |
| Exec and files | `guest-exec`, `guest-exec-status`, `guest-file-open/read/write/seek/flush/close` |
| Accounts | `guest-set-user-password`, `guest-ssh-get/add/remove-authorized-keys` |
| Hotplug | `guest-get/set-vcpus`, `guest-get/set-memory-blocks`, `guest-get-memory-block-info` |
| Stats | `guest-get-load`, `guest-get-cpustats`, `guest-get-diskstats` |
| Virtainer | `__io.virtainer_shell` (below) |

Beyond qemu-ga:

- **Shell:** `__io.virtainer_shell` turns the connection into an
  interactive terminal: the chosen user's login shell on a pseudo-terminal,
  live resize, up to 8 sessions at once, apart from the 16 QGA connections.
  Closing the connection hangs the shell up, like closing an SSH session.
  The protocol is under [Shell protocol](#shell-protocol).
  Guest owners who don't want it add the command to `block-rpcs`; blocking
  `guest-exec` blocks the Shell too.
- **Hot-added vCPUs and memory are onlined by the agent.** The kernel does not
  online a hot-added CPU by itself; that is normally a udev rule's job, and
  most images do not ship one for virtual machines. Of the images the e2e
  suite covers, only RHEL, AlmaLinux and Rocky 9-10 (`40-redhat*.rules`) and
  openSUSE/SLES (`80-hotplug-cpu-mem.rules`) ship rules that online a
  hot-added CPU. Ubuntu's `40-vm-hotadd.rules` matches only Hyper-V and Xen
  DMI vendors; Debian, Fedora, Arch and Alpine have none, so without the agent
  a live resize leaves the new vCPUs offline there. Memory is onlined by the
  kernel's default policy on Ubuntu, Debian 13, Fedora and Arch, but not on
  Debian 12 or Alpine. The agent listens for the kernel's `add` uevents and
  onlines the new CPU or memory block itself; devices present at start are
  left alone.
- **Auto-thaw watchdog:** if no thaw arrives within `freeze-timeout`
  (default 10 minutes; `0` disables auto-thaw), the agent thaws the
  filesystems itself, so a guest never stays frozen forever. A host that
  compares the freeze and thaw counts sees them differ (thaw returns 0), so an
  early thaw cannot pass for a quiesced snapshot.
- **`guest-set-time` without hwclock(8):** the agent sets the clock through
  system calls and the RTC device, so it works on images that don't ship
  `hwclock` (Ubuntu 24.04 and Debian 13 cloud images don't). With an explicit
  `time` it also works without an RTC; without `time` and without an RTC it
  returns an error, because there is nothing to read the time from. Under
  Cloud Hypervisor v53 the guests we booted had no usable RTC.

## Differences from qemu-ga

| Area | qemu-ga (observed with 10.2.2) | This agent |
| --- | --- | --- |
| Concurrency | One connection at a time | Up to 16 at once |
| `guest-set-time` | Fails when `hwclock` is missing | Works without `hwclock`; with an explicit `time` also without an RTC |
| Files created by `guest-file-open` | Mode 0666 | Mode 0644 |
| IPv6 route `metric`/`flags` | Sign-extension bug (`-1`, `18446744071564165121`) | The kernel's unsigned values |
| `guest-network-get-route` without IPv6 | Error | IPv4 routes only |
| `guest-get-users` | utmp only | utmp if present, otherwise logind session files |
| `guest-exec` tracking | Unbounded | Bounded (see [Limits](#limits)) |
| `guest-suspend-*` | Present | Absent |
| `guest-info` `version` | QEMU's version | This agent's version |

**Why there is no `guest-suspend-*`.** Cloud Hypervisor's ACPI tables offer
only S0 (running) and S5 (off). Observed with qemu-ga 10.2.2 on Fedora 44
under Cloud Hypervisor v53: `guest-suspend-ram` reported success, fell back
to suspend-to-idle and never woke; `guest-suspend-disk` reported success but
wrote the hibernation image to zram, which lives in the guest's own RAM, so
the next start was a cold boot; `guest-suspend-hybrid` failed with "unknown
guest suspend mode". These are observations on that one setup, not a claim
about every guest or hypervisor version.

## Limits

| Limit | Value |
| --- | --- |
| Concurrent QGA connections | 16 |
| Concurrent Shell sessions (not counted against the 16) | 8 |
| `guest-exec` processes tracked until their status is collected | 128 |
| Captured output per `guest-exec` stream | 16 MiB |
| Captured output retained across all `guest-exec` processes | 256 MiB |
| Open `guest-file-open` handles | 256 |
| `guest-file-read` count | 48 MiB |
| Maximum size of one QGA message | 1 MiB; 64 MiB for `guest-file-write` |
| Idle connection timeout | 600 s |
| Write timeout (a host that stops reading) | 60 s |
| Shell frame, data, host to guest | 64 KiB |
| Shell frame, data, guest to host | chunks of up to 16 KiB |
| Shell frame, control | 4 KiB |

A Shell frame larger than the limit ends the session with a protocol error.
Past the limits above, the agent answers with a QGA error or closes the
connection; it does not queue.

## Shell protocol

The host connects to port 100, syncs as usual, and sends:

```json
{"execute": "__io.virtainer_shell",
 "arguments": {"user": "debian", "rows": 40, "cols": 120, "term": "xterm-256color"}}
```

`user` is required (`root` has to be asked for by name); `rows`/`cols`
(1-9999, default 24 x 80) and `term` (default `xterm-256color`) are optional.
On success the agent replies `{"return": {"pid": N}}`, and from the next byte
on the connection carries Shell frames in both directions instead of QGA
messages. On failure it replies with a normal QGA error and the connection
stays a QGA connection, so the host must wait for the reply before it sends a
frame.

Each frame is a 1-byte type, a 4-byte little-endian payload length, and the
payload:

| Type | Payload | Direction |
| --- | --- | --- |
| 0, data | Raw terminal bytes (at most 64 KiB host → guest; chunks of at most 16 KiB guest → host) | host → guest: keystrokes; guest → host: output |
| 1, control | One JSON object (at most 4 KiB) | host → guest: `{"resize": [rows, cols]}`; guest → host: `{"exitcode": N}` or `{"signal": N}`, once, when the shell has ended |

Unknown frame types and control members are ignored. The shell is the
account's login shell on a new pseudo-terminal, started as a login shell in
the home directory with a fresh environment. It is not a PAM login: no
password, no logind session, no utmp entry. Closing the connection hangs the
shell up, like closing an SSH session. At most 8 sessions run at once, apart
from the 16 QGA connections, and every session is logged.

## Build

```sh
tools/build-iso.sh            # → dist/virtainer-guest-agent-<version>.iso (+ .sha256)
```

Prerequisites: [rustup](https://rustup.rs) (it installs the toolchain and the
musl target pinned in `rust-toolchain.toml`), `python3` and `xorriso`. The
script runs `cargo build --release --locked` for `x86_64-unknown-linux-musl`
(the default target, see `.cargo/config.toml`) and packs the binary with its
licence notices into a read-only ISO labelled `VIRTGA`, next to a `.sha256`
file. No system musl toolchain is needed: the Rust target links its bundled
musl.

## Install in a guest

The binary installs itself (`virtainer-guest-agent install`, as root, on
systemd and OpenRC guests). The install:

1. copies itself to `/usr/local/sbin/virtainer-guest-agent` atomically;
2. writes a systemd unit (or an OpenRC script on Alpine), then enables and
   starts it with `--no-block`;
3. runs `restorecon` when SELinux is enabled;
4. disables a qemu-ga unit that earlier Virtainer releases pointed at vsock
   port 100, keeping it as `.bak`.

Re-running it does not rewrite files or restart the service unless the binary
or the unit changed, so the same call both installs and upgrades.
`virtainer-guest-agent uninstall` removes the binary, the service unit and the
agent's runtime directory; it does not restore the old qemu-ga unit.

Recommended delivery: attach the ISO read-only to every VM and give the NoCloud
seed this vendor-data. It runs on every boot, so swapping the ISO upgrades the
agent:

```sh
#cloud-boothook
#!/bin/sh
d=$(mktemp -d) || exit 0
if mount -o ro LABEL=VIRTGA "$d" 2>/dev/null; then
  "$d/$(uname -m)/virtainer-guest-agent" install
  umount "$d"
fi
rmdir "$d"
```

Use a boothook, not a cloud-config `bootcmd`: a `bootcmd` in the user's own
user-data would replace the vendor one. Users can still opt out with
`vendor_data: {enabled: false}`. Without cloud-init, mount the ISO and run
the same `install` once by hand. To upgrade, swap the ISO (the boothook
installs the new binary at the next boot) or re-run `install` from the new
binary.

## Configuration

Optional `/etc/virtainer-guest-agent.conf` in the guest. A file that cannot be
parsed stops the agent instead of being half-applied.

```ini
# Same semantics as qemu-ga's --block-rpcs / --allow-rpcs.
block-rpcs = guest-exec, guest-file-open
# allow-rpcs = guest-ping, guest-info, guest-fsfreeze-freeze, ...
# Script run with "freeze"/"thaw". Default: qemu-ga's hook if one is
# installed (/etc/qemu-ga/fsfreeze-hook, /etc/qemu/fsfreeze-hook).
# Empty disables hooks.
# fsfreeze-hook = /usr/local/sbin/my-hook
# Seconds before auto-thaw; 0 disables auto-thaw.
freeze-timeout = 600
```

## Security

**Whoever can reach the host's vsock socket for this VM has root in the
guest.** The agent runs as root and its command set is root-equivalent. The
Shell adds no capability beyond `guest-exec`. Protect the socket the way you
would protect root SSH access to the guest.

- Root-equivalent commands: `guest-exec`, `__io.virtainer_shell`,
  `guest-file-open`, `guest-set-user-password`,
  `guest-ssh-add-authorized-keys`, `guest-ssh-remove-authorized-keys`,
  `guest-set-time` and `guest-shutdown`. A guest that must not give the host
  this reach can list them in `block-rpcs`, or use `allow-rpcs` with a short
  list, in the guest's config file. Blocking only some of them is not a
  boundary: for example `guest-file-open` can rewrite `/etc/passwd`, and
  `guest-set-time` can break certificate validation.
- On SELinux distros the agent runs as `unconfined_service_t`, so RHEL's qemu-ga
  restrictions (no exec, no file access, unlabeled mount points refused) do
  not apply.
- The ISO plus boothook runs whatever carries the `VIRTGA` label as root at
  every boot. Treat the ISO as trusted code: build it yourself or verify its
  `.sha256` against a checksum you obtained separately, and attach it
  read-only.
- Connections are accepted only from the host (CID 2). If `vsock_loopback` is
  loaded, any unprivileged guest process could otherwise reach the root agent;
  nested VMs could too. Port 100 is privileged, so no unprivileged process can
  bind it while the agent is down.
- `authorized_keys` is read and written with the target user's credentials, so
  a symlink there pointing at another user's file is refused. The credential
  switch uses raw per-thread syscalls on a dedicated thread, so it never
  affects other connections.
- `guest-file-open` opens paths as root. In the write modes it does not follow
  a symlink in the last path component.
- Files created through `guest-file-open` get mode 0644, not qemu-ga's 0666.
- Logging never blocks. Nothing is written while filesystems are frozen,
  because a journald stuck on a frozen disk must not stall the thaw.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Test

```sh
cargo test --locked             # unit tests, as an unprivileged user
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked  # the e2e suite boots this binary
e2e/run.py                      # real VMs under Cloud Hypervisor
```

The end-to-end suite needs `cloud-hypervisor` v53 and `ch-remote`, `CLOUDHV.fd`
and `hypervisor-fw` in `$VGA_E2E_BIN` (default `~/.cache/vga-e2e/bin`),
`qemu-img`, `xorriso`, `python3`, `/dev/kvm`, and a tap device that root
creates once; the script's docstring has the commands.

`e2e/run.py --list` shows the images it boots: Ubuntu 26.04 and 24.04,
Debian 13 and 12, Fedora 44, AlmaLinux 10, Rocky 9, CentOS Stream 10, RHEL 9.7
and 10.1, openSUSE Leap 16, Alpine 3.24, Arch and Amazon Linux 2023. The image
URLs are pinned, dated builds, so they need updating as upstreams rotate them;
RHEL images require a Red Hat login and must be supplied by hand. Downloads
are not checksum-verified. No per-distro results are published in this
repository.

Each guest gets the agent through the ISO and boothook above, and the host
talks to it over hybrid vsock. The suite checks:

- guest-info, OS info, host name, network interfaces, file systems and disks;
- freeze and thaw, including counts, and `guest-fstrim`;
- `guest-exec` and the guest-file commands;
- authorized-keys changes (including a symlink to `/etc/shadow`),
  `guest-set-user-password` and `guest-set-time`;
- live vCPU and memory hot-add;
- the Shell, including hang-up on disconnect;
- rejection of a connection from a local (loopback) vsock client;
- the SELinux context, where SELinux is enabled;
- `install` idempotence and the legacy qemu-ga unit cleanup;
- reboot and power-off;
- where the image ships qemu-ga, a diff of ten read-only commands against it
  on port 101 (`guest-get-osinfo`, `-host-name`, `-timezone`,
  `-network-get-interfaces`, `-get-fsinfo`, `-get-disks`, `-get-vcpus`,
  `-get-memory-block-info`, `-fsfreeze-status`, `-network-get-route`), with
  the known qemu-ga differences normalised.

## License

Copyright 2026 The Virtainer authors. Licensed under the
[Apache License, Version 2.0](LICENSE).

`src/autoonline.rs` is adapted from Kata Containers (also Apache-2.0); see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the notices that ship
with the binary. No QEMU (GPL) code is included, and none may be added.
