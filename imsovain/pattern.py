"""Key-id filters.

The OpenPGP v4 key id is the last eight bytes of the SHA-1 fingerprint.
Every filter looks at a prefix of those bytes.

`repeat` wants N copies of one doubled nibble: 0x00, 0x11, ... or 0xFF.
The other filters want one of a fixed list of prefixes, such as 00112233
or C0DE. The scanner compares those bytes. It does not run a regex.
"""

from __future__ import annotations

from dataclasses import dataclass

REPEAT_KIND = 0
PREFIX_KIND = 1
MAX_PREFIXES = 32

# Four-byte counts. Same length, so none of them hides another.
RUNS = (
    bytes.fromhex("00112233"),
    bytes.fromhex("01234567"),
    bytes.fromhex("89ABCDEF"),
    bytes.fromhex("FEDCBA98"),
    bytes.fromhex("33221100"),
    bytes.fromhex("76543210"),
)

# Four-byte words. Same length on purpose: a short word in this set would
# match long before DEADBEEF ever showed up.
WORDS = (
    bytes.fromhex("DEADBEEF"),
    bytes.fromhex("CAFEBABE"),
    bytes.fromhex("C0DEC0DE"),
    bytes.fromhex("DEADC0DE"),
    bytes.fromhex("C0DECAFE"),
    bytes.fromhex("FEE1DEAD"),
    bytes.fromhex("8BADF00D"),
    bytes.fromhex("BAADF00D"),
    bytes.fromhex("B16B00B5"),
    bytes.fromhex("F00DF00D"),
    bytes.fromhex("13371337"),
    bytes.fromhex("CAFED00D"),
    bytes.fromhex("D15EA5ED"),
    bytes.fromhex("ABADCAFE"),
    bytes.fromhex("DECAFBAD"),
    bytes.fromhex("FACEFEED"),
    bytes.fromhex("BAAAAAAD"),
    bytes.fromhex("C0CAC01A"),
    bytes.fromhex("BEEFC0DE"),
    bytes.fromhex("FACEB00C"),
)

# Three-byte words. Common enough to find in about a million hashes.
SPEAK = (
    bytes.fromhex("C0FFEE"),
    bytes.fromhex("DEC0DE"),
    bytes.fromhex("DEFACE"),
    bytes.fromhex("FACADE"),
    bytes.fromhex("DECADE"),
    bytes.fromhex("0FF1CE"),
    bytes.fromhex("BADA55"),
    bytes.fromhex("FA1AFE"),
    bytes.fromhex("10ADED"),
    bytes.fromhex("0B5E55"),
    bytes.fromhex("B00B1E"),
    bytes.fromhex("D00D1E"),
    bytes.fromhex("D00DAD"),
    bytes.fromhex("BEEFED"),
    bytes.fromhex("5EC0DE"),
)

# Two-byte words. C0DE is in here; -f C0DE still asks for that one prefix.
SHORT = (
    bytes.fromhex("C0DE"),
    bytes.fromhex("CAFE"),
    bytes.fromhex("DEAD"),
    bytes.fromhex("BEEF"),
    bytes.fromhex("F00D"),
    bytes.fromhex("FACE"),
    bytes.fromhex("1337"),
    bytes.fromhex("BAAD"),
    bytes.fromhex("D00D"),
    bytes.fromhex("FADE"),
    bytes.fromhex("B00B"),
    bytes.fromhex("BABE"),
    bytes.fromhex("C0FF"),
    bytes.fromhex("10AD"),
    bytes.fromhex("0BAD"),
    bytes.fromhex("5EED"),
)

PRESETS = {
    "run": RUNS,
    "word": WORDS,
    "speak": SPEAK,
    "short": SHORT,
}

# Names that are not themselves hex. A hex string is accepted as a prefix.
ALIASES = {
    "repeats": "repeat",
    "count": "run",
    "sequence": "run",
    "words": "word",
    "shorts": "short",
    "code": "C0DE",
    "coffee": "C0FFEE",
    "deadbeef": "DEADBEEF",
}


@dataclass(frozen=True)
class Filter:
    name: str
    kind: str
    leading: int = 0
    prefixes: tuple[bytes, ...] = ()

    def pack(self) -> bytes:
        if self.kind == "repeat":
            if not 1 <= self.leading <= 8:
                raise ValueError("leading must be from 1 to 8")
            return bytes((REPEAT_KIND, self.leading, 0, 0))
        if not self.prefixes or len(self.prefixes) > MAX_PREFIXES:
            raise ValueError("a prefix filter needs 1 to 32 prefixes")
        out = bytearray((PREFIX_KIND, 0, len(self.prefixes), 0))
        for prefix in self.prefixes:
            if not 1 <= len(prefix) <= 8:
                raise ValueError("a key-id prefix must be 1 to 8 bytes")
            out.append(len(prefix))
            out += prefix
            out += bytes(8 - len(prefix))
        return bytes(out)

    def matches(self, fingerprint: bytes) -> bool:
        if len(fingerprint) != 20:
            raise ValueError("a v4 fingerprint is 20 bytes")
        key_id = fingerprint[-8:]
        if self.kind == "repeat":
            if not 1 <= self.leading <= 8:
                raise ValueError("leading must be from 1 to 8")
            first = key_id[0]
            if (first >> 4) != (first & 0x0F):
                return False
            return key_id[: self.leading] == bytes([first]) * self.leading
        return any(key_id.startswith(prefix) for prefix in self.prefixes)


def repeat(leading: int) -> Filter:
    if not 1 <= leading <= 8:
        raise ValueError("leading must be from 1 to 8")
    return Filter(name="repeat", kind="repeat", leading=leading)


def describe(filt: Filter) -> str:
    if filt.kind == "repeat":
        return f"repeat: {filt.leading} doubled-nibble bytes"
    shown = ", ".join(prefix.hex().upper() for prefix in filt.prefixes)
    return f"{filt.name}: {shown}"


def _compact(text: str) -> str:
    return "".join(ch for ch in text.strip() if ch not in " \t_")


def _hex_prefix(text: str) -> bytes | None:
    if not text or len(text) > 16 or len(text) % 2 != 0:
        return None
    if any(ch not in "0123456789abcdef" for ch in text):
        return None
    return bytes.fromhex(text)


def parse_filter(text: str, leading: int = 6) -> Filter:
    raw = _compact(text)
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    key = ALIASES.get(raw.lower(), raw.lower()).lower()
    if key == "repeat":
        return repeat(leading)
    preset = PRESETS.get(key)
    if preset is not None:
        return Filter(name=key, kind="prefix", prefixes=preset)
    prefix = _hex_prefix(key)
    if prefix is None:
        raise ValueError(
            "unknown filter. Use repeat, run, word, speak, short, "
            "or a hex prefix such as C0DE or 0x00112233"
        )
    return Filter(name=prefix.hex(), kind="prefix", prefixes=(prefix,))


def key_id_matches(fingerprint: bytes, filt: Filter) -> bool:
    return filt.matches(fingerprint)
