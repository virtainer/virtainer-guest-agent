# Security policy

The agent runs as root in every guest, so we treat security reports as our
highest priority. See [Security in the README](README.md#security) for the
threat model: whoever can reach the host's vsock socket for a VM has root in
that guest.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository.

Include what an attacker needs (for example, an unprivileged user in the
guest, or a process on the host), what they gain, and steps to reproduce.

We will acknowledge the report within 7 days and keep you updated while we
work on a fix. We follow coordinated disclosure: the fix and a security
advisory are published before details are made public, and we credit the
reporter in the advisory unless you prefer otherwise.

## Supported versions

Fixes go into the latest release only.

## Upgrading

Swap the agent ISO (the boothook installs the new binary at the next boot), or
re-run `virtainer-guest-agent install` from the new binary in each guest. See
[Install in a guest](README.md#install-in-a-guest).
