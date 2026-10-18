# imsovain

`imsovain` generates an unencrypted OpenPGP v4 Ed25519 secret key whose key id opens with a pattern you can remember.

A v4 fingerprint is the SHA-1 of the public-key packet, prefixed with `0x99` and a two-octet length. [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) defines it that way, so the hash is SHA-1 even though SHA-1 collisions are public. The program keeps one Ed25519 key fixed and walks the creation time backward from now, one second at a time. The creation time is four bytes inside that hash. When the key id matches, it writes the secret key.

The key id is the last eight bytes of the fingerprint. A key id of `0000000000000000` is skipped and the search continues. OpenPGP uses that value as a wildcard, so it does not name one key.

A wider search window does not make a match more likely per hash. Each timestamp is one SHA-1. The window only decides how many timestamps are tried before the program draws a new key. The default window is 250 days. The largest window that fits in the four-byte timestamp is 49710 days, and a larger value is rejected.

## Filters

`--filter` chooses the pattern. The scan compares key-id bytes. It does not render the key id as hex and run a regular expression.

| filter | the key id opens with |
| --- | --- |
| `repeat` (default) | N copies of one doubled nibble: `00`, `11`, … or `FF`. `--leading` sets N and defaults to 6, so `FFFFFFFFFFFF…` |
| `run` | `00112233`, `01234567`, `89ABCDEF`, `FEDCBA98`, `33221100`, or `76543210` |
| `word` | a four-byte word: `DEADBEEF`, `CAFEBABE`, `C0DEC0DE`, `DEADC0DE`, `C0DECAFE`, `FEE1DEAD`, `8BADF00D`, `BAADF00D`, `B16B00B5`, `F00DF00D`, `13371337`, `CAFED00D`, `D15EA5ED`, `ABADCAFE`, `DECAFBAD`, `FACEFEED`, `BAAAAAAD`, `C0CAC01A`, `BEEFC0DE`, `FACEB00C` |
| `speak` | a three-byte word: `C0FFEE`, `DEC0DE`, `DEFACE`, `FACADE`, `DECADE`, `0FF1CE`, `BADA55`, `FA1AFE`, `10ADED`, `0B5E55`, `B00B1E`, `D00D1E`, `D00DAD`, `BEEFED`, `5EC0DE` |
| `short` | a two-byte word: `C0DE`, `CAFE`, `DEAD`, `BEEF`, `F00D`, `FACE`, `1337`, `BAAD`, `D00D`, `FADE`, `B00B`, `BABE`, `C0FF`, `10AD`, `0BAD`, `5EED` |
| hex, such as `C0DE` or `0x00112233` | exactly that prefix, 1 to 8 bytes |

`--leading` applies only to `repeat`. Words in one filter are the same length, so a short prefix cannot hide a longer one. These names are accepted too: `repeats`, `count` and `sequence` for `run`, `words`, `shorts`, `code` for `C0DE`, `coffee` for `C0FFEE`, and `deadbeef` for `DEADBEEF`.

There are 16 doubled nibbles, so a repeat of N bytes shows up once in `16 / 256^N` hashes. That is `2^(8N - 4)` hashes on average. The median wait is about 70% of the average. A miss is ordinary. After one average wait, about 37% of searches are still running.

## How long a repeat takes

These rates were measured on a Ryzen 9 7950X and a GeForce RTX 3060 Ti. One CPU thread hashes about 25 million keys per second. Thirty-two threads together hash about 460 million. The OpenCL kernel hashes about 10.6 billion, about 23 times the 32-thread CPU scan. Your machine will differ. `tests/check.py` prints the rate it just measured.

| leading bytes | average hashes | 1 CPU thread | 32 CPU threads | one GPU |
| --- | --- | --- | --- | --- |
| 4 | 268 million | 11 seconds | 0.6 seconds | 0.03 seconds |
| 5 | 69 billion | 46 minutes | 2.5 minutes | 6 seconds |
| 6 | 18 trillion | 8 days | 11 hours | 28 minutes |
| 7 | 4.5 × 10^15 | 6 years | 113 days | 5 days |
| 8 | 1.2 × 10^18 | 1500 years | 79 years | 3.4 years |

The prefix table does not move the CPU rate. The one-shot digest call this replaced stayed near 6 million per second on one thread and about 10 million with 32, because each call takes OpenSSL's provider lock. A POSIX regex compiled once is still several times slower than the byte table, and compiling that regex on every hash is a few thousand times slower.

`--opencl` runs the same scan on a GPU. The CPU scan stays the default. A missing GPU is an error, not a silent fallback. The GPU hashes the whole window it was given, and one GPU runs one scan at a time. Extra `-t` workers draw the next keys while a scan runs. They do not multiply the hash rate. The host expands the SHA-1 schedule once per key with the timestamp word set to zero. Only that word changes from one second to the next, and the GPU adds it back in.

A 250-day window is 21.6 million hashes. On this GPU that is a few milliseconds, so the time is the hash rate above, not the window. Use a window of a few thousand days on a faster GPU so launch overhead stays small next to the hashing. That still does not change how many hashes a match takes.

## Keys that get written

Each file under `PGPKEYS/` is a transferable secret key: one certify-only primary, one user id, and a positive self-signature. There is no encryption subkey. The secret material is not passphrase-protected. The file is created at mode `0600`. The file name is the fingerprint.

The packets are the old format from RFC 4880. The primary key is version 4, algorithm 22, with the Ed25519 curve OID `1.3.6.1.4.1.11591.15.1`. The public point is the byte `0x40` followed by 32 bytes. That is the form GnuPG imports.

Import one with GnuPG:

```sh
gpg --import PGPKEYS/<fingerprint>
```

`PGPKEYS/`, `PGPKEYS2/`, `FOUND/`, and `FOUND_OLD/` are gitignored. Do not commit secret keys.

## Requirements

- Python 3.9 or newer, with development headers, and the `venv` module
- A C compiler and OpenSSL (`libcrypto`)
- GnuPG, if you want to import the result
- An OpenCL GPU and `libOpenCL.so.1`, only for `--opencl`

The build does not need OpenCL headers. `libOpenCL.so.1` is loaded at run time. `pip install` builds `accel/` with scikit-build-core and CMake, and downloads CMake when the environment does not already have it.

## Build and run

From a fresh checkout:

```sh
python3 build_and_run.py 32 'Name <name@example.com>' 250 6 repeat opencl
```

That creates `.venv` if it is missing, installs this tree into it, compiles the C extension, and starts the search. Arguments:

```text
python3 build_and_run.py CORES UID [DAYS] [LEADING] [FILTER] [opencl]
```

`DAYS` defaults to 250, `LEADING` to 6, and `FILTER` to `repeat`. The sixth argument is the word `opencl` or it is omitted. Keys land in `PGPKEYS/` next to the script. The search runs until you interrupt it.

Examples, all of them average waits on the machine above:

```sh
# Three identical bytes on one CPU thread. Usually under a second.
python3 build_and_run.py 1 'Name <name@example.com>' 30 3 repeat

# DEADBEEF and the other four-byte words, eight CPU threads.
python3 build_and_run.py 8 'Name <name@example.com>' 250 6 word

# The prefix C0DE on the GPU. One hash in 65536 matches, so this is quick.
python3 build_and_run.py 4 'Name <name@example.com>' 7 2 C0DE opencl

# Six-byte repeat on the GPU. Average about half an hour.
python3 build_and_run.py 32 'Name <name@example.com>' 250 6 repeat opencl

# The count 00112233, among the other runs.
python3 build_and_run.py 8 'Name <name@example.com>' 60 4 run opencl
```

After the first install, the `imsovain` command in `.venv` is the same search with the flags spelled out. `--uid` is required.

```sh
.venv/bin/imsovain \
    -t 8 \
    -u 'Name <name@example.com>' \
    -m 250 \
    -l 6 \
    -f word \
    -o PGPKEYS
```

The same search on the GPU, stopping at the first key:

```sh
.venv/bin/imsovain \
    -t 4 \
    -u 'Name <name@example.com>' \
    -m 30 \
    -f C0DE \
    -o PGPKEYS \
    --opencl \
    -x
```

`-x` stops after one written key. Without it the program keeps going. `-f run` looks for `00112233` and the other counts. `-f coffee` looks for `C0FFEE`.

Each CPU scan keeps its own SHA-1 context and releases the GIL while it hashes. The GPU call releases the GIL too, then takes one process-wide lock so the OpenCL queue is used by one scan at a time. A returned timestamp is checked again in Python before the key is written.

## Check

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python tests/check.py
```

`build_and_run.py` already creates that environment, so this is enough on a second run:

```sh
.venv/bin/python tests/check.py
```

The check builds the extension, compares its SHA-1 with `hashlib`, asks the CPU and the GPU for the same hit hashlib found, imports a fixed test key into a temporary GnuPG home, generates a `repeat` key and a `C0DE` key on each path, and prints how the byte filter compares with `regexec`.

## Layout

- `build_and_run.py` creates `.venv`, installs the package, and starts a search
- `imsovain/` builds the OpenPGP packets and drives the search
- `accel/search.c` is the CPU SHA-1 scan
- `accel/opencl.c` is the same scan on an OpenCL GPU
- `accel/filter.c` matches key-id prefixes without a regex
- `accel/module.c` exposes both scans as `imsovain._accel`
- `CMakeLists.txt` and `pyproject.toml` build the extension
