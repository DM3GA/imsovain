"""Generate one key and move its creation time until the key id matches."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from imsovain.accel_proc import TIME_OFFSET, search
from imsovain.packets import (
    Ed25519Key,
    SecretKeyPacket,
    format_fingerprint,
    transferable_secret_key,
)
from imsovain.pattern import Filter

SECONDS_PER_DAY = 24 * 60 * 60


@dataclass(frozen=True)
class Attempt:
    checked: int
    seconds: float
    fingerprint: str | None = None
    path: str | None = None
    created: int | None = None


def window_seconds(days: int) -> int:
    if days < 1:
        raise ValueError("the search window must cover at least one day")
    seconds = days * SECONDS_PER_DAY
    if seconds > 0xFFFFFFFF:
        raise ValueError("the search window does not fit in four bytes")
    return seconds


def _write_secret(path: str, blob: bytes) -> None:
    """Create an unencrypted secret key at mode 0600.

    O_EXCL refuses an existing file or symlink. open() applies the umask, so
    the fchmod is what keeps 0600 when the umask is stricter. The key is
    synced before this returns, and a failed write removes the partial file.
    """
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        os.unlink(path)
        raise


def attempt_key(outdir: str, user_id: str, max_iter: int, filt: Filter, opencl: bool = False) -> Attempt:
    started = time.perf_counter()
    key = Ed25519Key(os.urandom(32))
    created = int(time.time())
    packet = SecretKeyPacket(key, created)
    preimage = packet.fingerprint_preimage()
    if preimage[TIME_OFFSET : TIME_OFFSET + 4] != created.to_bytes(4, "big"):
        raise RuntimeError("creation time is not at the expected fingerprint offset")

    found, checked = search(preimage, max_iter, filt, opencl=opencl)
    elapsed = time.perf_counter() - started
    if found is None:
        return Attempt(checked=checked, seconds=elapsed)

    placed = SecretKeyPacket(key, found)
    fingerprint = placed.fingerprint()
    if not filt.matches(fingerprint):
        raise RuntimeError("search timestamp does not produce the requested key id")

    text = format_fingerprint(fingerprint)
    path = os.path.join(outdir, text)
    blob = transferable_secret_key(placed, user_id)
    _write_secret(path, blob)
    return Attempt(
        checked=checked,
        seconds=elapsed,
        fingerprint=text,
        path=path,
        created=found,
    )
