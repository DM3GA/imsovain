#!/bin/sh
# Configure the CMake build, compile the OpenSSL searcher, and look for a key.
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
if command -v cmake >/dev/null 2>&1; then
    cmake_bin=cmake
elif [ -x "$root/.venv/bin/cmake" ]; then
    cmake_bin=$root/.venv/bin/cmake
else
    echo "cmake is not installed. Use a system cmake, or: pip install -e '.[build]'" >&2
    exit 1
fi
"$cmake_bin" -S "$root" -B "$root/build"
"$cmake_bin" --build "$root/build"
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
    -a "$root/build/pgpgen-accel"
