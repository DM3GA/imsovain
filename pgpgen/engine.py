"""Generate one key and move its creation time until the key id matches."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from pgpgen.accel_proc import TIME_OFFSET, search
from pgpgen.packets import (
    Ed25519Key,
    SecretKeyPacket,
    format_fingerprint,
    transferable_secret_key,
)
from pgpgen.pattern import Filter, key_id_matches

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
    if not key_id_matches(fingerprint, filt):
        raise RuntimeError("search timestamp does not produce the requested key id")

    text = format_fingerprint(fingerprint)
    path = os.path.join(outdir, text)
    blob = transferable_secret_key(placed, user_id)
    with open(path, "xb") as handle:
        handle.write(blob)
    os.chmod(path, 0o600)
    return Attempt(
        checked=checked,
        seconds=elapsed,
        fingerprint=text,
        path=path,
        created=found,
    )
