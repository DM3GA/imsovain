"""Talk to the OpenSSL search program.

The request is big-endian TLV on stdin:

    0x01  preimage, including the starting creation time
    0x02  uint16 offset of that creation time
    0x03  uint32 maximum attempts
    0x04  uint16 number of leading key-id bytes that must match

A reply is two lines: the unix time, or -1, then the number of SHA-1
attempts actually performed.
"""

from __future__ import annotations

import subprocess

# 0x99 || length || version || time...
TIME_OFFSET = 4


def search(binary: str, preimage: bytes, max_iter: int, leading: int) -> tuple[int | None, int]:
    if len(preimage) < TIME_OFFSET + 4:
        raise ValueError("fingerprint preimage is too short")
    if not 1 <= leading <= 8:
        raise ValueError("leading must be from 1 to 8")
    if not 1 <= max_iter <= 0xFFFFFFFF:
        raise ValueError("iteration count does not fit in four bytes")

    message = b"".join(
        (
            b"\x01" + len(preimage).to_bytes(2, "big") + preimage,
            b"\x02\x00\x02" + TIME_OFFSET.to_bytes(2, "big"),
            b"\x03\x00\x04" + max_iter.to_bytes(4, "big"),
            b"\x04\x00\x02" + leading.to_bytes(2, "big"),
        )
    )
    try:
        completed = subprocess.run(
            [binary],
            input=message,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"could not run {binary}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(detail or f"{binary} exited {completed.returncode}")

    lines = completed.stdout.splitlines()
    if len(lines) != 2:
        raise RuntimeError("accelerator reply was not two lines")
    try:
        found = int(lines[0])
        checked = int(lines[1])
    except ValueError as exc:
        raise RuntimeError("accelerator reply was not numeric") from exc
    if checked < 0:
        raise RuntimeError("accelerator reported a negative attempt count")
    if found < 0:
        return None, checked
    return found, checked


def sha1_hex(binary: str, payload: bytes) -> str:
    completed = subprocess.run(
        [binary, "--digest"],
        input=payload,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(detail or "digest helper failed")
    return completed.stdout.decode("ascii").strip()


def self_test_hex(binary: str) -> str:
    completed = subprocess.run(
        [binary, "--self-test"],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(detail or "SHA-1 self-test failed")
    return completed.stdout.decode("ascii").strip()
