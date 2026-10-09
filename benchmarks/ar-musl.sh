#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
: "${MOSDNS_ZIG:?Set MOSDNS_ZIG}"
exec "$MOSDNS_ZIG" ar "$@"
