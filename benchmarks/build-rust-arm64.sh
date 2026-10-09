#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
: "${MOSDNS_ZIG:?Set MOSDNS_ZIG to a Zig executable (0.14 or newer)}"
task_root="$(cd "$(dirname "$0")/.." && pwd)"
export CC_aarch64_unknown_linux_musl="$task_root/benchmarks/cc-musl.sh"
export AR_aarch64_unknown_linux_musl="$task_root/benchmarks/ar-musl.sh"
task_sysroot="$(rustc --print sysroot)"
task_host="$(rustc -vV | sed -n 's/^host: //p')"
task_linker="$task_sysroot/lib/rustlib/$task_host/bin/rust-lld"
cd "$task_root"
cargo rustc -p mosdns-rs --release --target aarch64-unknown-linux-musl --bin mosdns-rs -- -C "linker=$task_linker" -C linker-flavor=ld.lld
