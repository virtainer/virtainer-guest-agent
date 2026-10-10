# Virtainer Guest Agent — a modern, vsock-native guest agent that speaks the QEMU Guest Agent protocol

The Virtainer Guest Agent is a QEMU Guest Agent (QGA, qemu-ga) compatible agent
for x86_64 Linux and Windows VMs on Cloud Hypervisor, from [Virtainer](https://virtainer.io).
The Linux build is one static binary (about 1 MB, no runtime dependencies),
reached by the host over vsock, that installs itself in systemd and OpenRC guests.
The Windows MVP runs as an auto-start LocalSystem service through virtio-win's
viosock Winsock provider and provisions Windows guests from a raw FAT12 seed.
It is the guest component of the Virtainer virtualization platform for classic VMs.

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
- **Linux commands:** every Linux command of QEMU 11.1's `qga/qapi-schema.json`,
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

## Windows MVP

The Windows build targets Windows Server 2019, 2022 and 2025 (Core and Desktop
Experience), and Windows 11 IoT Enterprise LTSC. It requires amd64 Windows,
virtio-win's `viosock` driver **and its Winsock provider**, and built-in Windows
PowerShell 5.1, CIM, LocalAccounts and NetTCPIP cmdlets. The command transport
uses Winsock AF_VSOCK (40), port 100, and rejects every peer except CID 2 before
starting a connection thread. The host uses the same Cloud Hypervisor hybrid
vsock handshake and QGA framing as on Linux.

These are implemented MVP paths. Cross-target check and Clippy do not establish
Windows runtime acceptance; SCM installation, the provider, specialize, PowerShell
provisioning and executable replacement must also be exercised in a real guest.

| Group | Supported Windows commands |
| --- | --- |
| Session | `guest-sync`, `guest-sync-delimited`, `guest-ping`, `guest-info` |
| Identity | `guest-get-osinfo`, `guest-get-host-name` |
| Time and power | `guest-get-time`, `guest-set-time`, `guest-shutdown` |
| Network | `guest-network-get-interfaces` (names, MACs, IPv4/IPv6 addresses and prefixes) |
| Exec | `guest-exec`, `guest-exec-status` (stdin, environment, separate or merged capture) |
| Files | `guest-file-open`, `guest-file-read`, `guest-file-write`, `guest-file-seek`, `guest-file-flush`, `guest-file-close` |
| Accounts | `guest-set-user-password` (base64 UTF-8 password, `crypted: false`) |
| Provisioning | `__io.virtainer_provision` |

`guest-set-time` requires an explicit Unix time in nanoseconds on Windows; this
build does not read an RTC. `guest-shutdown` accepts `powerdown`, `halt` and
`reboot`, uses the Windows shutdown API, and sends no reply on success. In this
MVP, `halt` also powers down. File and exec limits match the Linux limits above;
file write modes reject a reparse point in the last path component.

The known commands outside this table return the QAPI error
`{"error": {"class": "GenericError", "desc": "Command <name> is not supported"}}`.
This includes filesystem freeze/thaw and trim, filesystem/disk/device inventory,
vCPU and memory commands, statistics, routes, timezone/user inventory, authorized
key RPCs, suspend commands and `__io.virtainer_shell`. They are absent from
`guest-info`'s supported command list. Unknown command names return
`CommandNotFound`. VSS and ConPTY are outside this MVP; Windows snapshots are
crash-consistent.

### Windows installation and specialize

Run an elevated prompt once while preparing the image:

```powershell
.\virtainer-guest-agent.exe install
```

This copies the executable into
`%ProgramFiles%\Virtainer\GuestAgent\virtainer-guest-agent.exe`, registers
`virtainer-guest-agent` as an auto-start LocalSystem service, and starts it.
An unchanged executable is not rewritten or restarted. Installation also
sets private SYSTEM/Administrators directory ACLs. Windows RPC filters use
`%ProgramData%\Virtainer\GuestAgent\virtainer-guest-agent.conf`, with the same
`block-rpcs` and `allow-rpcs` syntax shown below; Linux freeze settings are not
accepted in this file. `uninstall` stops and deletes the service and removes its
executable. When invoked from the installed executable, Windows can keep that
file mapped; removal is then scheduled for the next reboot using
[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).
The command reports deferred removal; reboot before reinstalling. Provisioning
records are kept so a reinstall cannot replay the user's script.

The generalized image **must** include this entry in its unattend file's
`specialize` pass. Setup invokes it synchronously as SYSTEM before the normal
specialize reboot. It sets only the hostname, which takes effect with that
reboot. The network stack's RPC services are not running during specialize, so
network configuration waits for the service:

```xml
<settings pass="specialize">
  <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64"
             publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
    <RunSynchronous>
      <RunSynchronousCommand wcm:action="add"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
        <Order>1</Order>
        <Description>Apply Virtainer hostname and network</Description>
        <Path>&quot;C:\Program Files\Virtainer\GuestAgent\virtainer-guest-agent.exe&quot; specialize</Path>
      </RunSynchronousCommand>
    </RunSynchronous>
  </component>
</settings>
```

Adjust the path if Windows uses a different Program Files location. The agent
must already be installed, and the seed must already be attached when Setup
runs this entry. An ordinary service boot leaves a new instance `pending` until
its specialize checkpoint exists and the active Windows hostname matches the
requested name (case-insensitive). A service restart before the specialize reboot
keeps provisioning `pending` and defers networking, accounts and the user script. It does not
report `done` for a rename that still needs a reboot. The service is not running
during specialize, so the agent first answers on vsock after that reboot. Non-generalized images require the operator to arrange
this entry point and the appropriate reboot before using the service.

### Windows seed and provisioning status

Attach an unpartitioned FAT12 disk containing:

- `virtainer-guest-agent.exe`;
- `virtainer-provision.json`;
- optionally `user-script.ps1`.

Windows need not mount the volume. The agent scans `\\.\PhysicalDrive0` through
`\\.\PhysicalDrive255`, recognizes a seed by the contract filename on a valid
FAT12 volume, decodes its long filenames, and reads it twice to establish stable
content. Multiple matching seeds, corrupt files and inconsistent persisted state
are refused. The reader accepts images up to 256 MiB and files up to 64 MiB,
checks FAT geometry, FAT copies and cluster chains, and never writes the disk.

The schema and field names are:

```json
{
  "schema": 1,
  "instance_id": "00000000-0000-4000-8000-000000000001",
  "seed_version": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "hostname": "WEB-01",
  "admin": {"username": "Administrator", "password": "REPLACE-WITH-A-STRONG-PASSWORD"},
  "ssh_authorized_keys": ["ssh-ed25519 REPLACE-WITH-A-PUBLIC-KEY"],
  "timezone": "UTC",
  "network": [{"mac": "52:54:00:aa:bb:cc", "addresses": ["10.0.0.5/24"],
               "gateway": "10.0.0.1", "dns": ["1.1.1.1"]}],
  "user_script": "user-script.ps1"
}
```

`instance_id` is a canonical lowercase UUID; `seed_version` is the host-supplied
64-digit SHA-256 content identifier, returned unchanged. The agent checks stable
raw content; it does not independently recompute that identifier (the document
itself contains it). Hostnames use the NetBIOS form, at most 15 ASCII letters,
digits or hyphens, and cannot be all digits or start/end with a hyphen. Static
IPv4/IPv6 addresses are selected by MAC; an empty `network` selects DHCP on all
hardware adapters. A MAC-selected entry with empty `addresses` selects DHCP on
that adapter. Both DHCP paths remove manual IPv4/IPv6 addresses and static
default routes, enable DHCP for both families and IPv6 router discovery, and
reset DNS to automatic configuration.
Duplicate MACs, invalid CIDRs/IPs, unknown fields and other schema mistakes are
rejected before changes. `user_script`, when supplied, must be exactly
`user-script.ps1`.

Specialize applies the hostname. At service startup the agent updates
itself if the seed executable differs, then configures networking, creates or
enables the requested local administrator and sets its password, writes
`%ProgramData%\ssh\administrators_authorized_keys` with SYSTEM/Administrators-only
ACLs, sets the Windows timezone ID, and runs the optional PowerShell script as
SYSTEM (UTF-8 seed scripts receive a Unicode BOM for Windows PowerShell 5.1).
OpenSSH installation and enabling its service remain image preparation
steps. Credentials go to fixed PowerShell code on stdin, never on the command
line; records and helper error messages contain no credentials or script output.
When a PowerShell step fails, the recorded error holds that step's PowerShell
error category, error ID and message, with the administrator password removed
and the text limited to 300 characters; the same text goes to the agent log.

Records under `%ProgramData%\Virtainer\GuestAgent\instances` survive reboot.
Each instance's completed provisioning is retained, including when a different
instance later uses the image. A changed seed for an already completed instance
does not reapply its configuration or replay its script. Interrupted system
provisioning is `failed` with an unknown outcome and is not automatically retried.
The script is checkpointed before starting; failure or interruption is recorded
in `errors`, but does not block `done` and does not cause replay. Helpers have a
120-second limit; the user script has a 30-minute limit. An operator must resolve
failed/uncertain system steps before preparing a new instance.

Request provisioning status without arguments:

```json
{"execute": "__io.virtainer_provision"}
```

Its return object contains exactly `instance_id`, `seed_version`, `state`
(`pending`, `applying`, `done` or `failed`), `errors` and `agent_version`.
Before any instance is known, the first two fields are `null`. The last record
remains available after seed removal. Host readiness and seed removal must wait
for this instance's `done` and matching `seed_version`; ICMP is not the readiness
signal.

Boot-time updates copy the installed, working executable to `virtainer-guest-agent.updater.exe`
and stage the replacement separately as `virtainer-guest-agent.next.exe`. The
service stops after launching the updater. The updater runs the installed version's
code, waits for the service to stop, copies the installed binary to
`virtainer-guest-agent.previous.exe`, atomically replaces the installed
executable and restarts through SCM. The installed path remains present until
atomic replacement, including if the updater exits or Windows reboots after the
backup copy. A backup copy failure restarts the existing service. Startup is
confirmed within 60 seconds by observing two continuous seconds of SCM
`RUNNING`; the service publishes that state only after opening its vsock listener.
A replacement or startup failure attempts rollback. Before launching the helper,
the agent persists the instance ID, seed version and exact executable bytes in
`%ProgramData%\Virtainer\GuestAgent\failed-update`. This checkpoint also covers
helper crashes; it is retained on failure and written again before restarting
the fallback. The same input is suppressed across service restarts and reboots,
so the fallback can serve and provision without repeating the failed update.
Changed instance, seed version or executable bytes permit a new attempt.
Successful confirmed startup clears the checkpoint. To retry unchanged input
after correcting the failure, run these commands in an elevated PowerShell:

```powershell
Stop-Service virtainer-guest-agent
& "$env:ProgramFiles\Virtainer\GuestAgent\virtainer-guest-agent.exe" retry-update
Start-Service virtainer-guest-agent
```

`retry-update` requires the service to be stopped. This is trusted-seed, unsigned delivery;
attach the seed read-only and treat its executable, password and script as
privileged input. Authenticated live updates are outside the MVP.

The transport ABI follows [virtio-win's public viosock interface](https://github.com/virtio-win/kvm-guest-drivers-windows/blob/master/viosock/sys/public.h).
The Windows address layout follows its [socket ABI header](https://github.com/virtio-win/kvm-guest-drivers-windows/blob/master/viosock/inc/vio_sockets.h).
Command field semantics follow the [QGA protocol reference](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html).

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
- the Shell, including hang-up on disconnect and the limit of 8 sessions;
- `guest-file-open` refusing to follow a symlink in the write modes (reads
  still follow it);
- the message limits (a 1 MiB non-write message and a token flood get the
  size error and a close, a 2 MiB `guest-file-write` lands intact) and the
  limit of 16 connections;
- `guest-exec` returning while a background child still holds its pipe,
  keeping arguments out of the log, and log lines that cannot be forged with a
  newline in a path;
- the configuration file: `freeze-timeout` auto-thaw, `block-rpcs` (including
  the Shell), and refusal to start on a group-writable file;
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

## About Virtainer

[Virtainer](https://virtainer.io) is a self-hosted virtualization platform for
hardware you own: it runs full Linux VMs and Docker images as hardware-isolated
machines. Virtainer Free runs on a single host; [Virtainer Pro](https://virtainer.io/pro),
the multi-host edition for clusters, is in development. The Virtainer Guest Agent
is one of [Virtainer's open-source components](https://virtainer.io/open-source).
