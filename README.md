# pgpgen

`pgpgen` generates an unencrypted OpenPGP v4 Ed25519 secret key whose key id opens with a chosen pattern.

A v4 fingerprint is SHA-1 of the public key packet body, with a two-octet length prefix. That hash includes the key's creation time. The program keeps the Ed25519 key fixed and walks the creation time backward from now, one second at a time, until the key id matches. SHA-1 is here because [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) defines the v4 fingerprint that way.

The key id is the last eight bytes of the fingerprint. `--filter` chooses which prefix counts:

| filter | the key id opens with |
| --- | --- |
| `repeat` (default) | N copies of one doubled nibble: `00`, `11`, … or `FF`. `--leading` sets N and defaults to 6, so `FFFFFFFFFFFF…` |
| `run` | `00112233`, `01234567`, `89ABCDEF`, `FEDCBA98`, `33221100`, or `76543210` |
| `word` | a four-byte hex word: `DEADBEEF`, `CAFEBABE`, `C0DEC0DE`, `DEADC0DE`, `C0DECAFE`, `FEE1DEAD`, `8BADF00D`, `BAADF00D`, `B16B00B5`, `F00DF00D`, `13371337`, `CAFED00D`, `D15EA5ED`, `ABADCAFE`, `DECAFBAD`, `FACEFEED`, `BAAAAAAD`, `C0CAC01A`, `BEEFC0DE`, `FACEB00C` |
| `speak` | a three-byte word: `C0FFEE`, `DEC0DE`, `DEFACE`, `FACADE`, `DECADE`, `0FF1CE`, `BADA55`, `FA1AFE`, `10ADED`, `0B5E55`, `B00B1E`, `D00D1E`, `D00DAD`, `BEEFED`, `5EC0DE` |
| `short` | a two-byte word: `C0DE`, `CAFE`, `DEAD`, `BEEF`, `F00D`, `FACE`, `1337`, `BAAD`, `D00D`, `FADE`, `B00B`, `BABE`, `C0FF`, `10AD`, `0BAD`, `5EED` |
| hex, such as `C0DE` or `0x00112233` | exactly that prefix. `code`, `coffee`, and `deadbeef` are names for `C0DE`, `C0FFEE`, and `DEADBEEF` |

`--leading` applies only to `repeat`. Words in one filter are the same length, so a short prefix cannot hide a longer one. Three identical bytes (`AAAAAA…`) is enough to test `repeat`.

The scan compares those bytes. It does not turn the key id into hex and run a regular expression. A prefix filter is a 256-slot table on the first byte, then a compare of the rest, built once before the loop.

On this machine that table does not move the scan off the SHA-1 limit. `repeat`, `run`, `word`, and a single prefix such as `DEADBEEF` all hashed at about 6.8 million keys per second. A POSIX regex compiled once is about seven times slower than the byte table on its own, and running it inside the scan made the scan about 15% slower. Compiling that same regex on every hash fell to about 70 thousand matches per second, a few thousand times slower than the byte table, which is the hole a per-key regex falls into. `tests/check.py` prints the numbers from the machine it is run on.

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
./compile_and_run.sh CORES 'Name <name@example.com>' [DAYS] [LEADING] [FILTER]
```

`DAYS` is how far into the past the creation time may move. It defaults to 250. `LEADING` defaults to 6. `FILTER` defaults to `repeat`. The script installs the package, which compiles the extension, and starts the search.

The same options are on the `pgpgen` command. `--uid` is required.

```sh
pgpgen \
    -t 8 \
    -u 'Name <name@example.com>' \
    -m 250 \
    -l 6 \
    -f word \
    -o PGPKEYS
```

`-f run` looks for `00112233` and the other counts. `-f C0DE` looks for that prefix alone. `-f repeat` is the doubled-nibble search.

`-x` stops after the first written key. The program keeps going until you interrupt it. Threads share the process, and the scan releases the GIL while it hashes. `pgpgen` checks a returned timestamp with its own SHA-1 before it writes the key.

## Check

```sh
.venv/bin/python tests/check.py
```

That builds the extension, compares its SHA-1 with `hashlib`, asks it for the same hit hashlib found, imports a fixed test key into a temporary GnuPG home, generates a `repeat` key and a `C0DE` key, and prints how the byte filter compares with `regexec`.

## Layout

- `pgpgen/` builds the OpenPGP packets and drives the search
- `accel/search.c` is the SHA-1 scan
- `accel/filter.c` matches key-id prefixes without a regex
- `accel/module.c` exposes that scan as `pgpgen._accel`
- `CMakeLists.txt` and `pyproject.toml` build the extension
- `compile_and_run.sh` installs the package and starts a search

Generated keys under `PGPKEYS/`, `FOUND/`, and `FOUND_OLD/` stay out of git.
