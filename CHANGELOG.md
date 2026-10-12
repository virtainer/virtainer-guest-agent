# Changelog

## 0.3.1

- Windows: when the requested host name is set but not yet active at the
  first service start after specialize (Windows Server 2019), the agent
  restarts Windows once per provisioning, after Windows setup has finished,
  and then completes provisioning. The restart is recorded before it happens
  in a file separate from the provisioning record (which keeps its 0.3.0
  format), logged, and carries a comment in the System log (event 1074).
  Before, such a VM stayed `pending` until someone restarted it.

## 0.3.0

First release with Windows guest support (Windows Server 2019, 2022 and
2025, and Windows 11 IoT Enterprise LTSC). On Windows the agent runs as a
LocalSystem service that speaks QGA to the host over vsock port 100 through
virtio-win's viosock provider, and provisions the guest from a FAT12 seed:
host name, network, accounts and SSH keys, optionally disabling the
built-in Administrator. The Linux agent behaves as in 0.2.1.

- Windows: a LocalSystem service serving the session, identity, time and
  power, network-interface and `guest-exec` commands listed in the README,
  with the same hybrid vsock handshake and framing as on Linux.
- Windows: provisioning from a FAT12 seed read without mounting it. The seed
  is checked against a strict schema, and per-instance checkpoints let a
  restart resume where it stopped. It sets the host name, network, time
  zone, accounts and SSH keys. The seed can also stage an agent update,
  kept with a backup to roll back to.
- Windows: `admin.disable_builtin` in the seed disables the built-in
  Administrator once the requested administrator exists. The account is
  found by SID, so a renamed or localized one is covered too.
- Windows: an interface that already has DHCP and a lease keeps it during
  network provisioning instead of falling back to APIPA.
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
