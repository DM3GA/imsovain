"""In-process SHA-1 search.

`pgpgen._accel` is the extension built by CMake. The search releases the
GIL, so several Python threads can hash at the same time.
"""

from __future__ import annotations

# 0x99 || length || version || time...
TIME_OFFSET = 4


def _accel():
    try:
        from pgpgen import _accel as native
    except ImportError as exc:
        raise RuntimeError(
            "pgpgen._accel is not built. From the repository root, run: pip install -e ."
        ) from exc
    return native


def sha1_digest(payload: bytes) -> bytes:
    digest = _accel().sha1(payload)
    if not isinstance(digest, bytes) or len(digest) != 20:
        raise RuntimeError("extension returned a digest that is not 20 bytes")
    return digest


def search(preimage: bytes, max_iter: int, leading: int) -> tuple[int | None, int]:
    if len(preimage) < TIME_OFFSET + 4:
        raise ValueError("fingerprint preimage is too short")
    if not 1 <= leading <= 8:
        raise ValueError("leading must be from 1 to 8")
    if not 1 <= max_iter <= 0xFFFFFFFF:
        raise ValueError("iteration count does not fit in four bytes")
    found, checked = _accel().search(preimage, TIME_OFFSET, max_iter, leading)
    checked = int(checked)
    if checked < 0:
        raise RuntimeError("extension reported a negative attempt count")
    if found is None:
        return None, checked
    return int(found), checked
