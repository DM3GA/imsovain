#!/usr/bin/env python3
"""Prove the OpenSSL search agrees with hashlib and that GnuPG accepts a key."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

UID = "pgpgen test <pgpgen-test@example.com>"
LONG_UID = ("pgpgen " + ("A" * 300) + " <long-user@example.com>")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def build_extension() -> None:
    subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(ROOT)], check=True)


def gpg_import(home: Path, key_path: Path) -> str:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    home.mkdir(mode=0o700, exist_ok=True)
    os.chmod(home, 0o700)
    imported = subprocess.run(
        ["gpg", "--batch", "--status-fd", "1", "--import", str(key_path)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    require(imported.returncode == 0, imported.stderr or "gpg import failed")
    checked = subprocess.run(
        ["gpg", "--batch", "--check-signatures"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    combined = checked.stdout + checked.stderr
    require(checked.returncode == 0, combined or "gpg --check-signatures failed")
    require("good signature" in combined, combined)
    require("BAD signature" not in combined, combined)
    listed = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys"],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    fingerprints = [line.split(":")[9] for line in listed.stdout.splitlines() if line.startswith("fpr:")]
    require(len(fingerprints) == 1, listed.stdout)
    return fingerprints[0]


def test_sha1() -> None:
    from pgpgen.accel_proc import sha1_digest
    from pgpgen.packets import Ed25519Key, SecretKeyPacket

    expected = hashlib.sha1(b"pgpgen-sha1-selftest").digest()
    require(sha1_digest(b"pgpgen-sha1-selftest") == expected, "OpenSSL SHA-1 disagrees with hashlib")
    key = Ed25519Key(bytes(range(32)))
    for created in (1_700_000_000, 1_700_000_123, int(time.time())):
        preimage = SecretKeyPacket(key, created).fingerprint_preimage()
        require(sha1_digest(preimage) == hashlib.sha1(preimage).digest(), "preimage digest mismatch")
        require(preimage[4:8] == created.to_bytes(4, "big"), "creation time is not at offset 4")


def test_mpi_and_packet(work: Path) -> None:
    from pgpgen.packets import Ed25519Key, SecretKeyPacket, mpi_encode, transferable_secret_key

    point = b"\x40" + bytes(range(32))
    encoded = mpi_encode(point)
    bit_length = int.from_bytes(encoded[:2], "big")
    require(bit_length == 263, f"Ed25519 point MPI bit length is {bit_length}")
    require(encoded[2:] == point, "MPI dropped a non-zero leading byte")

    key = Ed25519Key(bytes(range(32)))
    packet = SecretKeyPacket(key, 1_700_000_000)
    blob = transferable_secret_key(packet, UID)
    path = work / "fixed.pgp"
    path.write_bytes(blob)
    os.chmod(path, 0o600)
    home = work / "gnupg-fixed"
    listed = gpg_import(home, path)
    require(listed == packet.fingerprint().hex().upper(), "GnuPG fingerprint differs from SHA-1")

    long_packet = transferable_secret_key(packet, LONG_UID)
    require(long_packet[0] == 0x94, "secret-key tag changed")
    # The user-id body is longer than 255 bytes, so the old-format header uses a two-byte length.
    uid_at = blob_index_of_uid(long_packet)
    require(long_packet[uid_at] == 0xB5, f"long user id used tag {long_packet[uid_at]:#x}")
    long_path = work / "long.pgp"
    long_path.write_bytes(long_packet)
    os.chmod(long_path, 0o600)
    long_home = work / "gnupg-long"
    long_fpr = gpg_import(long_home, long_path)
    require(long_fpr == packet.fingerprint().hex().upper(), "long user id changed the fingerprint")


def blob_index_of_uid(blob: bytes) -> int:
    """Return the offset of the user-id packet that follows a one-byte-length secret key."""
    require(blob[0] == 0x94, "expected a one-byte-length secret-key packet")
    return 2 + blob[1]


def test_search_agrees() -> None:
    from pgpgen.accel_proc import search
    from pgpgen.packets import Ed25519Key, SecretKeyPacket
    from pgpgen.pattern import key_id_matches
    leading = 3
    key = Ed25519Key(os.urandom(32))
    start = int(time.time())
    preimage = bytearray(SecretKeyPacket(key, start).fingerprint_preimage())
    found_at = None
    limit = 2_000_000
    for step in range(limit):
        stamp = start - step
        preimage[4:8] = stamp.to_bytes(4, "big")
        digest = hashlib.sha1(preimage).digest()
        if key_id_matches(digest, leading):
            found_at = step
            break
    require(found_at is not None, f"no 3-byte key id in {limit} hashlib attempts")
    original = SecretKeyPacket(key, start).fingerprint_preimage()
    found, checked = search(original, found_at + 1, leading)
    require(found == start - found_at, f"C search returned {found}, hashlib found offset {found_at}")
    require(checked == found_at + 1, f"C search counted {checked} attempts")
    if found_at > 0:
        missed, _checked = search(original, found_at, leading)
        require(missed is None, "C search matched earlier than hashlib")


def test_cli_key(work: Path) -> None:
    outdir = work / "keys"
    command = [
        sys.executable,
        "-m",
        "pgpgen",
        "-t",
        "4",
        "-m",
        "20",
        "-l",
        "3",
        "-u",
        UID,
        "-x",
        "-o",
        str(outdir),
    ]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    require(completed.returncode == 0, completed.stdout + completed.stderr)
    keys = sorted(outdir.iterdir())
    require(len(keys) >= 1, "generator wrote no key")
    for index, key_path in enumerate(keys):
        require(stat.S_IMODE(key_path.stat().st_mode) == 0o600, "secret key was not mode 0600")
        compact = key_path.name.replace("_", "")
        require(len(set(compact[-16:-10])) == 1, f"key id does not open with three matching bytes: {key_path.name}")
        home = work / f"gnupg-cli-{index}"
        listed = gpg_import(home, key_path)
        require(listed == compact, "saved filename does not match the GnuPG fingerprint")
        print(f"verified {key_path.name}")
    print(completed.stdout.strip())


def main() -> None:
    # pip's editable hook is loaded at interpreter startup. Build first, then
    # re-exec so this process can import pgpgen._accel.
    if os.environ.get("PGPGEN_CHECKS") != "1":
        build_extension()
        env = os.environ.copy()
        env["PGPGEN_CHECKS"] = "1"
        os.execve(sys.executable, [sys.executable, str(ROOT / "tests" / "check.py")], env)

    from pgpgen.engine import window_seconds

    work = ROOT / "testrun"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    test_sha1()
    test_mpi_and_packet(work)
    test_search_agrees()
    test_cli_key(work)
    require(window_seconds(250) == 250 * 24 * 60 * 60, "250-day window changed")
    shutil.rmtree(work)
    print("all checks passed")


if __name__ == "__main__":
    main()
