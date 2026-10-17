#!/bin/sh
# Build the OpenSSL searcher and look for a vanity key.
# Usage: ./compile_and_run.sh CORES UID [DAYS] [LEADING]
# DAYS defaults to 250. LEADING defaults to 6.
set -eu
if [ "$#" -lt 2 ]; then
    echo "usage: $0 CORES UID [DAYS] [LEADING]" >&2
    exit 1
fi
cores=$1
uid=$2
days=${3:-250}
leading=${4:-6}
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$root"
# shellcheck disable=SC2046
gcc -O2 -Wall -Wextra -Werror $(pkg-config --cflags libcrypto) \
    -o accel/accel_openssl accel/accel_openssl.c $(pkg-config --libs libcrypto)
if [ -x "$root/.venv/bin/python" ]; then
    py=$root/.venv/bin/python
else
    py=python3
fi
exec "$py" -m pgpgen \
    -t "$cores" \
    -u "$uid" \
    -m "$days" \
    -l "$leading" \
    -o "$root/PGPKEYS" \
    -a "$root/accel/accel_openssl"
