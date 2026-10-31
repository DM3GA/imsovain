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

UID = "imsovain test <imsovain-test@example.com>"
LONG_UID = ("imsovain " + ("A" * 300) + " <long-user@example.com>")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def build_extension() -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--config-settings=cmake.define.IMSOVAIN_WERROR=ON",
            "-e",
            str(ROOT),
        ],
        check=True,
    )


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
    from imsovain.accel_proc import sha1_digest
    from imsovain.packets import Ed25519Key, SecretKeyPacket

    expected = hashlib.sha1(b"imsovain-sha1-selftest").digest()
    require(sha1_digest(b"imsovain-sha1-selftest") == expected, "OpenSSL SHA-1 disagrees with hashlib")
    key = Ed25519Key(bytes(range(32)))
    for created in (1_700_000_000, 1_700_000_123, int(time.time())):
        preimage = SecretKeyPacket(key, created).fingerprint_preimage()
        require(sha1_digest(preimage) == hashlib.sha1(preimage).digest(), "preimage digest mismatch")
        require(preimage[4:8] == created.to_bytes(4, "big"), "creation time is not at offset 4")


def test_mpi_and_packet(work: Path) -> None:
    from imsovain.packets import Ed25519Key, SecretKeyPacket, mpi_encode, transferable_secret_key

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


def fingerprint_with_key_id(key_id: bytes) -> bytes:
    require(len(key_id) == 8, "a key id is 8 bytes")
    return b"\x11" * 12 + key_id


def test_filters() -> None:
    from imsovain.accel_proc import native_match
    from imsovain.pattern import parse_filter

    repeat6 = parse_filter("repeat", 6)
    repeat3 = parse_filter("repeat", 3)
    run = parse_filter("run")
    word = parse_filter("word")
    short = parse_filter("short")
    code = parse_filter("code")
    coffee = parse_filter("coffee")
    counted = parse_filter("0x0011_2233")
    require(parse_filter("C0 DE").prefixes == (bytes.fromhex("c0de"),), "hex spacing was not accepted")
    for bad in ("nope", "ABC", "0xGG", "", "123", "repeat", "repeats", "0xword", "0xrepeat"):
        try:
            parse_filter(bad)
        except ValueError:
            continue
        raise SystemExit(f"filter {bad!r} should have been rejected")

    vectors = (
        (repeat6, bytes.fromhex("FFFFFFFFFFFF0000"), True),
        (repeat6, bytes.fromhex("FFFFFFFFFF000000"), False),
        (repeat3, bytes.fromhex("AAAAAA0011223344"), True),
        (repeat3, bytes.fromhex("AAABAA0011223344"), False),
        (run, bytes.fromhex("00112233AABBCCDD"), True),
        (run, bytes.fromhex("01234567AABBCCDD"), True),
        (run, bytes.fromhex("00112234AABBCCDD"), False),
        (counted, bytes.fromhex("00112233AABBCCDD"), True),
        (counted, bytes.fromhex("01234567AABBCCDD"), False),
        (word, bytes.fromhex("DEADBEEF11223344"), True),
        (word, bytes.fromhex("DEADC0DE00000000"), True),
        (word, bytes.fromhex("DEADBE0011223344"), False),
        (word, bytes.fromhex("C0DE000000000000"), False),
        (short, bytes.fromhex("C0DE000000000000"), True),
        (code, bytes.fromhex("C0DEFFFFFFFFFFFF"), True),
        (code, bytes.fromhex("C0DF000000000000"), False),
        (coffee, bytes.fromhex("C0FFEE0011223344"), True),
        (coffee, bytes.fromhex("C0FFEF0011223344"), False),
        (parse_filter("DEADBEEFCAFEBABE"), bytes.fromhex("DEADBEEFCAFEBABE"), True),
        (parse_filter("DEADBEEFCAFEBABE"), bytes.fromhex("DEADBEEFCAFEBABF"), False),
        (parse_filter("repeat", 8), bytes(8), False),
        (parse_filter("repeat", 8), bytes.fromhex("1111111111111111"), True),
        (parse_filter("repeat", 6), bytes(8), False),
        (parse_filter("repeat", 1), bytes.fromhex("00FFFFFFFFFFFFFF"), True),
        (parse_filter("repeat", 1), bytes(8), False),
        (parse_filter("00000000"), bytes.fromhex("00000000FFFFFFFF"), True),
        (parse_filter("00000000"), bytes(8), False),
        (parse_filter("0000000000000000"), bytes(8), False),
        (parse_filter("00"), bytes.fromhex("0011223344556677"), True),
        (parse_filter("00"), bytes(8), False),
    )
    for filt, key_id, want in vectors:
        fingerprint = fingerprint_with_key_id(key_id)
        require(filt.matches(fingerprint) is want, f"python filter {filt.name} on {key_id.hex()}")
        require(native_match(fingerprint, filt) is want, f"C filter {filt.name} on {key_id.hex()}")
        shifted = fingerprint_with_key_id(b"\x00" + key_id[:7])
        if want and filt.kind == "prefix" and key_id[0] != 0:
            require(not filt.matches(shifted), f"filter {filt.name} matched past the first byte")

    for name in ("repeat", "run", "word", "speak", "short", "C0DE", "00112233"):
        filt = parse_filter(name, 4)
        for _ in range(200):
            fingerprint = os.urandom(20)
            require(
                native_match(fingerprint, filt) is filt.matches(fingerprint),
                f"C and python disagree on {name}",
            )


def find_with_hashlib(filt, limit: int):
    from imsovain.packets import Ed25519Key, SecretKeyPacket

    key = Ed25519Key(os.urandom(32))
    start = int(time.time())
    preimage = bytearray(SecretKeyPacket(key, start).fingerprint_preimage())
    found_at = None
    for step in range(limit):
        stamp = start - step
        preimage[4:8] = stamp.to_bytes(4, "big")
        if filt.matches(hashlib.sha1(preimage).digest()):
            found_at = step
            break
    require(found_at is not None, f"no {filt.name} hit in {limit} hashlib attempts")
    return key, start, found_at


def assert_search_agrees(filt, found_at: int, key, start: int) -> None:
    from imsovain.accel_proc import search
    from imsovain.packets import SecretKeyPacket

    original = SecretKeyPacket(key, start).fingerprint_preimage()
    found, checked = search(original, found_at + 1, filt)
    require(found == start - found_at, f"C search returned {found}, hashlib found offset {found_at}")
    require(checked == found_at + 1, f"C search counted {checked} attempts")
    if found_at > 0:
        missed, _checked = search(original, found_at, filt)
        require(missed is None, "C search matched earlier than hashlib")


def assert_opencl_agrees(filt, found_at: int, key, start: int) -> None:
    from imsovain.accel_proc import search
    from imsovain.packets import SecretKeyPacket

    original = SecretKeyPacket(key, start).fingerprint_preimage()
    found, checked = search(original, found_at + 1, filt, opencl=True)
    require(found == start - found_at, f"OpenCL returned {found}, hashlib found offset {found_at}")
    require(checked == found_at + 1, f"OpenCL counted {checked} for a window of {found_at + 1}")
    if found_at > 0:
        missed, missed_checked = search(original, found_at, filt, opencl=True)
        require(missed is None, "OpenCL matched earlier than hashlib")
        require(missed_checked == found_at, f"OpenCL miss counted {missed_checked}")


def opencl_device_or_none() -> str | None:
    from imsovain.accel_proc import opencl_device

    try:
        return opencl_device()
    except RuntimeError as exc:
        print(f"skipping the OpenCL checks: {exc}")
        return None


def test_opencl(device: str) -> None:
    from imsovain.accel_proc import search
    from imsovain.packets import Ed25519Key, SecretKeyPacket
    from imsovain.pattern import parse_filter

    print(f"opencl device {device}")
    for _ in range(8):
        filt = parse_filter("repeat", 2)
        key, start, found_at = find_with_hashlib(filt, 200_000)
        assert_opencl_agrees(filt, found_at, key, start)
    filt = parse_filter("short")
    key, start, found_at = find_with_hashlib(filt, 200_000)
    assert_opencl_agrees(filt, found_at, key, start)
    filt = parse_filter("C0DE")
    key, start, found_at = find_with_hashlib(filt, 2_000_000)
    assert_opencl_agrees(filt, found_at, key, start)
    filt = parse_filter("repeat", 3)
    key, start, found_at = find_with_hashlib(filt, 8_000_000)
    assert_opencl_agrees(filt, found_at, key, start)

    start = int(time.time())
    preimage = SecretKeyPacket(Ed25519Key(os.urandom(32)), start).fingerprint_preimage()
    iters = 1 << 30
    if iters > start:
        iters = start
    hard = parse_filter("repeat", 8)
    # The GPU clock is low until a couple of full windows have run.
    search(preimage, iters, hard, opencl=True)
    search(preimage, iters, hard, opencl=True)
    begin = time.perf_counter()
    found, checked = search(preimage, iters, hard, opencl=True)
    elapsed = time.perf_counter() - begin
    require(found is None, "benchmark window matched an 8-byte repeat")
    require(checked == iters, f"benchmark counted {checked}")
    require(elapsed > 0, "benchmark clock did not move")
    print(f"opencl scan {checked / elapsed:.0f}/s over {checked} hashes in {elapsed:.3f}s")


def run_cli_keys(work: Path, name: str, args: list[str]) -> tuple[str, list[str]]:
    """Run the generator with -x and check every key it wrote.

    Searches that are still running when the first key turns up may write
    more keys, so -x can leave several. Each one must have been reported.
    Returns stdout and the fingerprints without separators.
    """
    outdir = work / f"{name}-keys"
    command = [sys.executable, "-m", "imsovain", "-u", UID, "-x", "-o", str(outdir), *args]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    output = completed.stdout + completed.stderr
    require(completed.returncode == 0, output)
    require(stat.S_IMODE(outdir.stat().st_mode) == 0o700, "key directory was not mode 0700")
    keys = sorted(outdir.iterdir())
    require(len(keys) >= 1, f"{name}: generator wrote no key")
    reported = sorted(line.split()[1] for line in completed.stdout.splitlines() if line.startswith("found "))
    require(reported == [key.name for key in keys], f"{name}: a written key was not reported\n{output}")
    fingerprints = []
    for index, key_path in enumerate(keys):
        require(stat.S_IMODE(key_path.stat().st_mode) == 0o600, "secret key was not mode 0600")
        compact = key_path.name.replace("_", "")
        listed = gpg_import(work / f"gnupg-{name}-{index}", key_path)
        require(listed == compact, "saved filename does not match the GnuPG fingerprint")
        print(f"verified {key_path.name}")
        fingerprints.append(compact)
    return completed.stdout, fingerprints


def test_cli_opencl(work: Path) -> None:
    stdout, fingerprints = run_cli_keys(work, "opencl", ["-t", "4", "-m", "3", "-f", "C0DE", "--opencl"])
    require("opencl " in stdout, stdout)
    require("filter c0de: C0DE" in stdout, stdout)
    for compact in fingerprints:
        require(compact[-16:-12] == "C0DE", f"key id does not open with C0DE: {compact}")


def test_search_agrees() -> None:
    from imsovain.pattern import parse_filter

    repeat3 = parse_filter("repeat", 3)
    key, start, found_at = find_with_hashlib(repeat3, 2_000_000)
    assert_search_agrees(repeat3, found_at, key, start)
    code = parse_filter("C0DE")
    key, start, found_at = find_with_hashlib(code, 2_000_000)
    assert_search_agrees(code, found_at, key, start)


def test_cli_filter(work: Path) -> None:
    # --leading is ignored outside repeat, so this is a plain C0DE search.
    stdout, fingerprints = run_cli_keys(work, "code", ["-t", "4", "-m", "2", "-l", "6", "-f", "C0DE"])
    require("filter c0de: C0DE" in stdout, stdout)
    for compact in fingerprints:
        require(compact[-16:-12] == "C0DE", f"key id does not open with C0DE: {compact}")


def test_cli_rejects(work: Path) -> None:
    outdir = work / "rejected"
    empty = subprocess.run(
        [sys.executable, "-m", "imsovain", "-u", "", "-o", str(outdir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(empty.returncode != 0, "empty user id was accepted")
    require("Traceback" not in empty.stderr, empty.stderr)
    require("user id" in empty.stderr, empty.stderr)
    missing_leading = subprocess.run(
        [sys.executable, "-m", "imsovain", "-u", UID, "-o", str(outdir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(missing_leading.returncode != 0, "repeat without --leading was accepted")
    require("Traceback" not in missing_leading.stderr, missing_leading.stderr)
    require("leading" in missing_leading.stderr, missing_leading.stderr)
    huge = subprocess.run(
        [sys.executable, "-m", "imsovain", "-u", UID, "-l", "1", "-m", "49711", "-o", str(outdir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(huge.returncode != 0, "a window past four bytes was accepted")
    require("Traceback" not in huge.stderr, huge.stderr)
    require("four bytes" in huge.stderr, huge.stderr)
    require(not outdir.exists(), "a rejected search created the output directory")


def test_secret_mode(work: Path) -> None:
    from imsovain.engine import attempt_key
    from imsovain.pattern import parse_filter

    outdir = work / "umask-keys"
    outdir.mkdir()
    # 0277 would leave open() at 0400, so this checks the fchmod.
    previous = os.umask(0o277)
    try:
        result = attempt_key(str(outdir), UID, 86_400, parse_filter("repeat", 1))
    finally:
        os.umask(previous)
    require(result.path is not None, "no key written under umask 0277")
    mode = stat.S_IMODE(os.stat(result.path).st_mode)
    require(mode == 0o600, f"secret key mode was {mode:04o}")


def test_bootstrap_help() -> None:
    # The interpreter this virtualenv was made from has no editable install,
    # so `-m imsovain` goes through the bootstrap into .venv.
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates = [Path(sys.base_prefix) / "bin" / name for name in (version, "python3")]
    base = next((path for path in candidates if path.is_file()), None)
    if base is None or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve():
        print("skipping the bootstrap check: no base interpreter outside a virtualenv")
        return
    completed = subprocess.run(
        [str(base), "-m", "imsovain", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(completed.returncode == 0, completed.stderr)
    require("--uid" in completed.stdout and "--opencl" in completed.stdout, completed.stdout)
    require("Traceback" not in completed.stderr, completed.stderr)


def test_help() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "imsovain", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(completed.returncode == 0, completed.stderr)
    require("--filter" in completed.stdout and "00112233" in completed.stdout, completed.stdout)
    require("C0DE" in completed.stdout, completed.stdout)
    require("--opencl" in completed.stdout, completed.stdout)
    require("365" in completed.stdout, completed.stdout)
    require("default: 6" not in completed.stdout, completed.stdout)


def test_bench(work: Path) -> None:
    from imsovain.packets import Ed25519Key, SecretKeyPacket
    from imsovain.pattern import parse_filter

    preimage = SecretKeyPacket(Ed25519Key(os.urandom(32)), int(time.time())).fingerprint_preimage()
    blobs = {
        "preimage": preimage,
        "repeat": parse_filter("repeat", 6).pack(),
        "word": parse_filter("word").pack(),
        "run": parse_filter("run").pack(),
        "one": parse_filter("DEADBEEF").pack(),
    }
    paths = {}
    for name, blob in blobs.items():
        path = work / f"{name}.blob"
        path.write_bytes(blob)
        paths[name] = path
    binary = work / "bench_filter"
    build = subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-O3",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_GNU_SOURCE",
            "-I",
            str(ROOT / "accel"),
            str(ROOT / "tests" / "bench_filter.c"),
            str(ROOT / "accel" / "filter.c"),
            str(ROOT / "accel" / "search.c"),
            "-lcrypto",
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    require(build.returncode == 0, build.stderr or "filter benchmark failed to compile")
    iters = "1000000"
    completed = subprocess.run(
        [
            str(binary),
            str(paths["preimage"]),
            str(paths["repeat"]),
            str(paths["word"]),
            str(paths["run"]),
            str(paths["one"]),
            iters,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    require(completed.returncode == 0, completed.stderr or completed.stdout or "filter benchmark failed")
    rows = {}
    for line in completed.stdout.splitlines():
        kind, name, count, seconds, rate, hits = line.split()
        rows[(kind, name)] = (int(count), float(seconds), float(rate), int(hits))
        print(f"{kind:12} {name:8} {float(rate):12.0f}/s  hits {hits}  in {float(seconds):.3f}s")
    repeat_rate = rows[("byte_scan", "repeat")][2]
    for name in ("word", "run", "one"):
        rate = rows[("byte_scan", name)][2]
        require(
            rate >= repeat_rate * 0.75,
            f"{name} scan ran at {rate:.0f}/s, repeat at {repeat_rate:.0f}/s",
        )
    byte_word = rows[("byte_match", "word")][2]
    regex_word = rows[("regex_match", "word")][2]
    byte_one = rows[("byte_match", "one")][2]
    regex_one = rows[("regex_match", "one")][2]
    require(
        byte_word >= regex_word * 4,
        f"word byte match {byte_word:.0f}/s is not 4x the regex {regex_word:.0f}/s",
    )
    require(
        byte_one >= regex_one * 4,
        f"single-prefix byte match {byte_one:.0f}/s is not 4x the regex {regex_one:.0f}/s",
    )
    recompile = rows[("regex_recompile", "word")][2]
    require(
        byte_word >= recompile * 20,
        f"recompiling the regex each hash ran at {recompile:.0f}/s, byte match at {byte_word:.0f}/s",
    )
    require(
        rows[("byte_scan", "word")][3] == rows[("regex_scan", "word")][3],
        "word byte scan and regex scan counted different hits",
    )
    require(
        rows[("byte_scan", "one")][3] == rows[("regex_scan", "one")][3],
        "DEADBEEF byte scan and regex scan counted different hits",
    )
    word_scan = rows[("byte_scan", "word")][2]
    regex_scan = rows[("regex_scan", "word")][2]
    print(
        f"word prefixes are {word_scan / repeat_rate:.3f}x the repeat scan; "
        f"regex scan is {regex_scan / word_scan:.3f}x the byte scan; "
        f"compiled-once regex matcher is {regex_word / byte_word:.4f}x the byte matcher; "
        f"recompiled regex matcher is {recompile / byte_word:.4f}x the byte matcher"
    )


def test_cli_key(work: Path) -> None:
    stdout, fingerprints = run_cli_keys(work, "repeat", ["-t", "4", "-m", "20", "-l", "3"])
    for compact in fingerprints:
        require(len(set(compact[-16:-10])) == 1, f"key id does not open with three matching bytes: {compact}")
    print(stdout.strip())


def main() -> None:
    # pip's editable hook is loaded at interpreter startup. Build first, then
    # re-exec so this process can import imsovain._accel.
    if os.environ.get("IMSOVAIN_CHECKS") != "1":
        build_extension()
        env = os.environ.copy()
        env["IMSOVAIN_CHECKS"] = "1"
        os.execve(sys.executable, [sys.executable, str(ROOT / "tests" / "check.py")], env)

    from imsovain.engine import window_seconds

    work = ROOT / "testrun"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    test_sha1()
    test_mpi_and_packet(work)
    test_filters()
    test_cli_rejects(work)
    test_secret_mode(work)
    test_search_agrees()
    device = opencl_device_or_none()
    if device is not None:
        test_opencl(device)
    test_bootstrap_help()
    test_help()
    test_cli_key(work)
    test_cli_filter(work)
    if device is not None:
        test_cli_opencl(work)
    test_bench(work)
    require(window_seconds(250) == 250 * 24 * 60 * 60, "250-day window changed")
    require(window_seconds(49710) == 49710 * 24 * 60 * 60, "largest four-byte window changed")
    try:
        window_seconds(49711)
    except ValueError:
        pass
    else:
        raise SystemExit("a window past four bytes was accepted")
    shutil.rmtree(work)
    print("all checks passed" if device is not None else "all checks passed, without OpenCL")


if __name__ == "__main__":
    main()
