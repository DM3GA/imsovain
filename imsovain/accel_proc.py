"""In-process SHA-1 search.

`imsovain._accel` is the extension built by CMake. The CPU search releases
the GIL, so several Python threads can hash at the same time. The OpenCL
search also releases the GIL. One GPU runs one scan at a time, and that
scan hashes the whole window instead of stopping at the first hit.
"""

from __future__ import annotations

# 0x99 || length || version || time...
TIME_OFFSET = 4


def _accel():
    try:
        from imsovain import _accel as native
    except ImportError as exc:
        raise RuntimeError(
            "imsovain._accel is not built. From the repository root, run: pip install -e ."
        ) from exc
    return native


def sha1_digest(payload: bytes) -> bytes:
    digest = _accel().sha1(payload)
    if not isinstance(digest, bytes) or len(digest) != 20:
        raise RuntimeError("extension returned a digest that is not 20 bytes")
    return digest


def search(preimage: bytes, max_iter: int, filt, opencl: bool = False) -> tuple[int | None, int]:
    if len(preimage) < TIME_OFFSET + 4:
        raise ValueError("fingerprint preimage is too short")
    if not 1 <= max_iter <= 0xFFFFFFFF:
        raise ValueError("iteration count does not fit in four bytes")
    native = _accel()
    if opencl:
        found, checked = native.search_opencl(preimage, TIME_OFFSET, max_iter, filt.pack())
    else:
        found, checked = native.search(preimage, TIME_OFFSET, max_iter, filt.pack())
    checked = int(checked)
    if checked < 0:
        raise RuntimeError("extension reported a negative attempt count")
    if found is None:
        return None, checked
    return int(found), checked


def opencl_device() -> str:
    name = _accel().opencl_device()
    if not isinstance(name, str) or name == "":
        raise RuntimeError("OpenCL device name was empty")
    return name


def native_match(fingerprint: bytes, filt) -> bool:
    if len(fingerprint) != 20:
        raise ValueError("a v4 fingerprint is 20 bytes")
    return bool(_accel().match(fingerprint, filt.pack()))
