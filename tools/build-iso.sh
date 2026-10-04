#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors
# Build the release binary and pack the agent drive:
#   dist/virtainer-guest-agent-<version>.iso   (volume label VIRTGA)
#     x86_64/virtainer-guest-agent
#     VERSION
#     THIRD_PARTY_NOTICES.md, LICENSES/*.txt
# One read-only ISO serves every VM; the guest's boothook mounts it by label
# and runs `install` (see README.md).
# Prerequisites: the pinned Rust toolchain (rustup), python3, xorriso.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in xorriso python3 cargo; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

cargo build --release --locked
# Take the binary from where cargo says it built it: a CARGO_TARGET_DIR
# elsewhere would otherwise leave a stale copy here.
TARGET_DIR=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
BIN="$TARGET_DIR/x86_64-unknown-linux-musl/release/virtainer-guest-agent"
# `cargo pkgid` ends in <name>@<version> (or #<version> for older cargo).
PKGID=$(cargo pkgid)
VERSION=${PKGID##*[#@]}

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
install -D -m 0755 "$BIN" "$STAGE/x86_64/virtainer-guest-agent"
install -D -m 0644 THIRD_PARTY_NOTICES.md "$STAGE/THIRD_PARTY_NOTICES.md"
for f in LICENSES/*.txt; do
  install -D -m 0644 "$f" "$STAGE/$f"
done
printf 'version=%s\ngit=%s\n' "$VERSION" "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
  > "$STAGE/VERSION"

mkdir -p dist
OUT="dist/virtainer-guest-agent-$VERSION.iso"
# Write to a temp name first so a failed build never leaves a half ISO behind.
xorriso -as mkisofs -quiet -o "$OUT.tmp" -V VIRTGA -J -r "$STAGE"
mv "$OUT.tmp" "$OUT"
(cd dist && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
ls -l "$OUT"
cat "$OUT.sha256"
