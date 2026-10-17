#!/bin/sh
# Build the in-process search extension and look for a vanity key.
# Usage: ./compile_and_run.sh CORES UID [DAYS] [LEADING] [FILTER]
# DAYS defaults to 250. LEADING defaults to 6 and applies to the repeat
# filter. FILTER defaults to repeat. Other filters: run, word, speak,
# short, or a hex prefix such as C0DE or 0x00112233.
set -eu
if [ "$#" -lt 2 ]; then
    echo "usage: $0 CORES UID [DAYS] [LEADING]" >&2
    exit 1
fi
cores=$1
uid=$2
days=${3:-250}
leading=${4:-6}
filter=${5:-repeat}
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$root"
if [ -x "$root/.venv/bin/python" ]; then
    py=$root/.venv/bin/python
else
    py=python3
fi
"$py" -m pip install -e "$root"
exec "$py" -m pgpgen \
    -t "$cores" \
    -u "$uid" \
    -m "$days" \
    -l "$leading" \
    -f "$filter" \
    -o "$root/PGPKEYS"
