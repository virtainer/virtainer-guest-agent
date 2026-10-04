#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Virtainer authors
# Regenerate LICENSES/THIRD-PARTY-RUST.txt: the licence texts and copyright
# lines of every crate in Cargo.lock for the musl target.
#   tools/third-party-licenses.sh           rewrite the file
#   tools/third-party-licenses.sh --check   fail if it is out of date
# Needs cargo-about 0.9.2:
#   cargo install --locked --features cli --version 0.9.2 cargo-about
set -euo pipefail
cd "$(dirname "$0")/.."

command -v cargo-about >/dev/null || {
  echo "cargo-about is required: cargo install --locked --features cli --version 0.9.2 cargo-about" >&2
  exit 1
}

OUT=LICENSES/THIRD-PARTY-RUST.txt
NEW=$(mktemp)
trap 'rm -f "$NEW"' EXIT
cargo about generate --locked -c tools/about/about.toml tools/about/about.hbs -o "$NEW"

if [ "${1:-}" = "--check" ]; then
  if ! diff -u "$OUT" "$NEW"; then
    echo "$OUT is out of date: run tools/third-party-licenses.sh" >&2
    exit 1
  fi
else
  mv "$NEW" "$OUT"
  trap - EXIT
fi
