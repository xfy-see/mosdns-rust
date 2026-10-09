#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
: "${MOSDNS_ZIG:?Set MOSDNS_ZIG}"
task_args=()
for arg in "$@"; do
    case "$arg" in
        --target=*) ;;
        *) task_args+=("$arg") ;;
    esac
done
exec "$MOSDNS_ZIG" cc -target x86_64-linux-musl "${task_args[@]}"
