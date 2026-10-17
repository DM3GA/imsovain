"""OpenPGP v4 Ed25519 transferable secret keys.

Packet bytes follow RFC 4880. The v4 fingerprint is SHA-1 over
`0x99 || two-octet length || public key body`. The self-signature hashes
that same public key body, the user id, and the hashed signature subpackets
with SHA-256, then signs the digest with Ed25519.
"""

from __future__ import annotations

import hashlib
import struct

import nacl.bindings as sodium

ED25519_OID = bytes.fromhex("092b06010401da470f01")
# Certify-only key flags, algorithm preferences, MDC, and no-modify.
# Length octets follow RFC 4880 section 5.2.3.1.
_STATIC_HASHED_SUBPACKETS = bytes.fromhex(
    "021b01"  # key flags: certify
    "040b090a0d"  # symmetric: AES-256, Twofish, Camellia-256
    "0515090a080b"  # hash: SHA-384, SHA-512, SHA-256, SHA-224
    "051600020301"  # compression: uncompressed, zlib, bzip2, zip
    "021e01"  # features: modification detection
    "021780"  # key server preferences: no-modify
)


def mpi_encode(value: bytes) -> bytes:
    """Encode an unsigned integer as an OpenPGP multiprecision integer."""
    stripped = value.lstrip(b"\x00")
    if not stripped:
        raise ValueError("MPI value is zero")
    first = stripped[0]
    leading_zero_bits = 0
    while (first & (0x80 >> leading_zero_bits)) == 0:
        leading_zero_bits += 1
    bit_length = len(stripped) * 8 - leading_zero_bits
    return struct.pack(">H", bit_length) + stripped


def old_packet(tag: int, body: bytes) -> bytes:
    """Old-format packet. The length field grows with the body."""
    if not 0 <= tag <= 15:
        raise ValueError("old-format packet tag must fit in four bits")
    length = len(body)
    if length < 256:
        header = bytes((0x80 | (tag << 2), length))
    elif length < 65536:
        header = bytes((0x80 | (tag << 2) | 0x01,)) + struct.pack(">H", length)
    else:
        header = bytes((0x80 | (tag << 2) | 0x02,)) + struct.pack(">I", length)
    return header + body


class Ed25519Key:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        public, secret = sodium.crypto_sign_seed_keypair(seed)
        if len(public) != 32 or secret[:32] != seed:
            raise RuntimeError("libsodium returned an unexpected Ed25519 key")
        self.seed = seed
        self.public = public
        self.sodium_secret = secret


class SecretKeyPacket:
    def __init__(self, key: Ed25519Key, created: int) -> None:
        if not 0 <= created <= 0xFFFFFFFF:
            raise ValueError("creation time does not fit in four bytes")
        self.key = key
        self.created = created

    def public_body(self) -> bytes:
        public_mpi = mpi_encode(b"\x40" + self.key.public)
        return b"\x04" + struct.pack(">I", self.created) + b"\x16" + ED25519_OID + public_mpi

    def fingerprint_preimage(self) -> bytes:
        body = self.public_body()
        return b"\x99" + len(body).to_bytes(2, "big") + body

    def fingerprint(self) -> bytes:
        return hashlib.sha1(self.fingerprint_preimage()).digest()

    def secret_body(self) -> bytes:
        secret_mpi = mpi_encode(self.key.seed)
        checksum = (sum(secret_mpi) % 65536).to_bytes(2, "big")
        # S2K usage 0: unencrypted secret MPI followed by a simple checksum.
        return self.public_body() + b"\x00" + secret_mpi + checksum

    def packet(self) -> bytes:
        return old_packet(5, self.secret_body())


def user_id_bytes(user_id: str) -> bytes:
    raw = user_id.encode("utf-8")
    if not 1 <= len(raw) <= 65535:
        raise ValueError("user id must be 1 to 65535 bytes of UTF-8")
    return raw


def user_id_packet(user_id: str) -> bytes:
    return old_packet(13, user_id_bytes(user_id))


def _signature_trailer(secret: SecretKeyPacket, user_id: str) -> tuple[bytes, bytes, bytes]:
    fingerprint = secret.fingerprint()
    hashed = (
        bytes((0x16, 0x21, 0x04))
        + fingerprint
        + bytes((0x05, 0x02))
        + struct.pack(">I", secret.created)
        + _STATIC_HASHED_SUBPACKETS
    )
    unhashed = bytes((0x09, 0x10)) + fingerprint[-8:]
    public = secret.public_body()
    key_and_uid = (
        b"\x99"
        + len(public).to_bytes(2, "big")
        + public
        + b"\xb4"
        + len(user_id_bytes(user_id)).to_bytes(4, "big")
        + user_id_bytes(user_id)
    )
    hashed_prefix = bytes((0x04, 0x13, 0x16, 0x08)) + len(hashed).to_bytes(2, "big") + hashed
    trailer = key_and_uid + hashed_prefix + b"\x04\xff" + len(hashed_prefix).to_bytes(4, "big")
    return trailer, hashed_prefix, unhashed


def signature_packet(secret: SecretKeyPacket, user_id: str) -> bytes:
    trailer, hashed_prefix, unhashed = _signature_trailer(secret, user_id)
    digest = hashlib.sha256(trailer).digest()
    signature = sodium.crypto_sign(digest, secret.key.sodium_secret)[:64]
    body = (
        hashed_prefix
        + len(unhashed).to_bytes(2, "big")
        + unhashed
        + digest[:2]
        + mpi_encode(signature[:32])
        + mpi_encode(signature[32:])
    )
    return old_packet(2, body)


def transferable_secret_key(secret: SecretKeyPacket, user_id: str) -> bytes:
    return secret.packet() + user_id_packet(user_id) + signature_packet(secret, user_id)


def format_fingerprint(fingerprint: bytes) -> str:
    text = fingerprint.hex().upper()
    head, tail = text[:-16], text[-16:]
    groups = "_".join(tail[i : i + 4] for i in range(0, 16, 4))
    return f"{head}_{groups}"
