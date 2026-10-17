#!/bin/sh
if [ $# -ne 1 ]; then
    echo "Need a parameter of number of CPU cores to use."
    exit 1
fi
gcc -v -march=native -mtune=native -O3 -Ofast -pipe -fno-plt -fexceptions -ftree-vectorize -ftree-vectorizer-verbose=2 -Wformat -Werror=format-security -lcrypto accel/accel_openssl.c -o accel/accel_openssl \
    && schedtool -D -n19 -e ./pgpgen.py -t$1 -o PGPKEYS -m 250 -a accel/accel_openssl

