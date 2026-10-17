# pgpgen

`pgpgen` generates an unencrypted OpenPGP v4 Ed25519 secret key whose fingerprint spells a repeated pattern in the key id.

A v4 fingerprint is SHA-1 of the public key packet body, with a two-octet length prefix. That hash includes the key's creation time. The program keeps the Ed25519 key fixed and walks the creation time backward from now, one second at a time, until the key id matches. SHA-1 is here because [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) defines the v4 fingerprint that way.

The key id is the last eight bytes of the fingerprint. A match means the key id opens with N copies of one doubled nibble: `00`, `11`, `22`, … or `FF`. The default is six bytes (`FFFFFFFFFFFF…`). Three bytes is enough to test the pipeline and looks like `AAAAAA…` or `EEEEEE…`.

Each output file is a transferable secret key: one certify-only primary, one user id, and a positive self-signature. There is no encryption subkey, and the secret material is not passphrase-protected. The files are mode `0600`.

## Requirements

- Python 3.9 or newer, with development headers
- A C compiler and OpenSSL (`libcrypto`)
- GnuPG, if you want to import the result

`pip install` builds a Python extension from `accel/search.c` with scikit-build-core and CMake. The build downloads CMake if the environment does not already have it. The scan then runs inside the `pgpgen` process.

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Run

```sh
./compile_and_run.sh CORES 'Name <name@example.com>' [DAYS] [LEADING]
```

`DAYS` is how far into the past the creation time may move. It defaults to 250. `LEADING` defaults to 6. The script installs the package, which compiles the extension, and starts the search.

The same options are on the `pgpgen` command. `--uid` is required.

```sh
pgpgen \
    -t 8 \
    -u 'Name <name@example.com>' \
    -m 250 \
    -l 6 \
    -o PGPKEYS
```

`-x` stops after the first written key. The program keeps going until you interrupt it. Threads share the process, and the scan releases the GIL while it hashes. `pgpgen` checks a returned timestamp with its own SHA-1 before it writes the key.

## Check

```sh
.venv/bin/python tests/check.py
```

That builds the extension, compares its SHA-1 with `hashlib`, asks it for the same hit hashlib found, imports a fixed test key into a temporary GnuPG home, and generates a key whose key id opens with three matching bytes.

## Layout

- `pgpgen/` builds the OpenPGP packets and drives the search
- `accel/search.c` is the SHA-1 scan
- `accel/module.c` exposes that scan as `pgpgen._accel`
- `CMakeLists.txt` and `pyproject.toml` build the extension
- `compile_and_run.sh` installs the package and starts a search

Generated keys under `PGPKEYS/`, `FOUND/`, and `FOUND_OLD/` stay out of git.
