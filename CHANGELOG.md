# Changelog

## Unreleased

- Windows: specialize sets only the hostname. Networking now runs in the
  service phase before accounts, because the network stack's RPC services are
  not available during specialize.
- Windows: accepted vsock connections are no longer switched with `FIONBIO`,
  which left viosock sockets non-blocking and made the agent drop connections
  that had no data pending. The listener stays blocking and is polled with a
  timeout so a service stop is still noticed.
- Windows: an existing read-only `administrators_authorized_keys` (or any other
  file the agent rewrites) no longer blocks provisioning.
- Windows: a failed PowerShell step records its error category, ID and message
  (administrator password removed, 300 characters at most) instead of only an
  exit status.

## 0.2.1

No change in what the agent does on a guest. This release carries the test
fixes made since 0.2.0, so that a host shipping it can be told apart from one
shipping 0.2.0.

- The file-system info test no longer assumes `/` is a local disk.
- The syslog reconnect test no longer depends on forks made by other tests
  running in parallel.
- The end-to-end suite covers more of the agent (file-open symlinks, limits,
  `guest-exec` supervision, logging and the configuration file), waits for
  cloud-init before it starts, and tells failures of the image or of the
  reference qemu-ga apart from failures of the agent.

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
