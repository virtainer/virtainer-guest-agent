# Changelog

## 0.2.0

First public release.

- A QEMU Guest Agent compatible agent for x86_64 Linux guests on Cloud
  Hypervisor, serving the host over vsock port 100 (host connections only).
  Implements the Linux commands of QEMU 11.1's QGA schema except
  `guest-suspend-*`: session, file system freeze/thaw/trim, host name, OS info,
  time zone, users, network, disks and file systems, `guest-exec`, guest files,
  accounts and SSH keys, vCPU and memory-block hotplug, and load and
  disk statistics.
- Up to 16 concurrent QGA connections, instead of qemu-ga's one.
- `__io.virtainer_shell`: an interactive login shell on a pseudo-terminal over
  the same connection, with resize and exit status (up to 8 sessions).
- Hot-added vCPUs and memory blocks are onlined by the agent.
- Auto-thaw watchdog for frozen file systems (`freeze-timeout`).
- `guest-set-time` works without `hwclock`, and with an explicit time without
  an RTC.
- Optional `/etc/virtainer-guest-agent.conf` with `block-rpcs`, `allow-rpcs`,
  `fsfreeze-hook` and `freeze-timeout`.
- `install` / `uninstall` for systemd and OpenRC guests; the agent ISO
  (`tools/build-iso.sh`) plus a cloud-init boothook installs and upgrades it.
- `licenses` prints the third-party notices and licence texts bundled in the
  binary.
