#!/usr/bin/env python3
"""Create .venv, build the search extension, and start a vanity search.

Usage:
    python3 build_and_run.py CORES UID [DAYS] [LEADING] [FILTER] [opencl]

DAYS defaults to 250. LEADING defaults to 6 and applies only to the repeat
filter. FILTER defaults to repeat. Other filters: run, word, speak, short,
or a hex prefix such as C0DE or 0x00112233. Pass opencl as the sixth
argument to hash on the GPU.

A checkout needs Python 3.9 or newer. This script creates .venv when it is
missing, installs this tree into it, and then runs imsovain. Keys are
written under PGPKEYS/ in this directory.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
USAGE = (
    "usage: python3 build_and_run.py CORES UID [DAYS] [LEADING] [FILTER] [opencl]"
)


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def parse_args(argv: list[str]) -> list[str]:
    if len(argv) < 2 or len(argv) > 6:
        fail(USAGE)
    cores, uid = argv[0], argv[1]
    days = argv[2] if len(argv) > 2 else "250"
    leading = argv[3] if len(argv) > 3 else "6"
    filt = argv[4] if len(argv) > 4 else "repeat"
    gpu = argv[5] if len(argv) > 5 else ""
    if not cores.isdigit() or int(cores) < 1:
        fail("CORES must be a positive integer")
    if not uid or uid.isspace():
        fail("UID must be a user id, for example 'Name <name@example.com>'")
    if not days.isdigit() or int(days) < 1:
        fail("DAYS must be a positive integer")
    if not leading.isdigit() or not 1 <= int(leading) <= 8:
        fail("LEADING must be from 1 to 8")
    if not filt or filt.isspace():
        fail("FILTER must be a name or a hex prefix")
    if gpu not in ("", "opencl"):
        fail(USAGE)
    args = [
        "-t",
        cores,
        "-u",
        uid,
        "-m",
        days,
        "-l",
        leading,
        "-f",
        filt,
        "-o",
        str(ROOT / "PGPKEYS"),
    ]
    if gpu == "opencl":
        args.append("--opencl")
    return args


def ensure_venv() -> Path:
    if VENV_PYTHON.is_file() and os.access(VENV_PYTHON, os.X_OK):
        return VENV_PYTHON
    try:
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)
    except subprocess.CalledProcessError:
        fail(f"could not create {ROOT / '.venv'} with {sys.executable}")
    if not VENV_PYTHON.is_file():
        fail(f"{VENV_PYTHON} is missing after creating the virtualenv")
    return VENV_PYTHON


def install(python: Path) -> None:
    try:
        subprocess.run(
            [str(python), "-m", "pip", "install", "-e", str(ROOT)],
            check=True,
            cwd=ROOT,
        )
    except subprocess.CalledProcessError:
        fail(f"could not install {ROOT} into {python}")


def main() -> None:
    search_args = parse_args(sys.argv[1:])
    python = ensure_venv()
    install(python)
    os.execv(str(python), [str(python), "-m", "imsovain", *search_args])


if __name__ == "__main__":
    main()
