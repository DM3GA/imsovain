"""Key-id vanity rule.

The OpenPGP v4 key id is the last eight bytes of the SHA-1 fingerprint.
A match requires those bytes to open with `leading` copies of one doubled
nibble: 0x00, 0x11, 0x22, ... or 0xFF.
"""


def is_doubled_nibble(byte: int) -> bool:
    return (byte >> 4) == (byte & 0x0F)


def key_id_matches(fingerprint: bytes, leading: int) -> bool:
    if not 1 <= leading <= 8:
        raise ValueError("leading must be from 1 to 8")
    if len(fingerprint) != 20:
        raise ValueError("a v4 fingerprint is 20 bytes")
    key_id = fingerprint[-8:]
    first = key_id[0]
    if not is_doubled_nibble(first):
        return False
    return key_id[:leading] == bytes([first]) * leading
