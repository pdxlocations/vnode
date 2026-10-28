from __future__ import annotations

import base64
import secrets
import struct
import zlib
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional, Tuple

import xeddsa

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def generate_keypair() -> Tuple[bytes, bytes]:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return public_key, private_bytes


def derive_public_key(private_key: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def node_id_from_public_key(public_key: bytes) -> int:
    """Meshtastic 2.8 identity binding (IEEE CRC-32 of the X25519 key)."""
    if len(public_key) != 32:
        raise ValueError("Public key must be 32 bytes")
    return zlib.crc32(public_key) & 0xFFFFFFFF


def signing_buffer(from_node: int, packet_id: int, to_node: int, data) -> bytes:
    """Firmware v1 signing layout; relay-mutated fields are deliberately excluded."""
    has_bitfield = data.HasField("bitfield")
    flags = int(data.want_response) | (int(has_bitfield) << 1)
    return struct.pack(
        "<B8IB",
        1,
        from_node,
        packet_id,
        to_node,
        int(data.portnum),
        data.request_id,
        data.reply_id,
        data.emoji,
        data.bitfield if has_bitfield else 0,
        flags,
    ) + bytes(data.payload)


def sign_data(
    private_key: bytes, from_node: int, packet_id: int, to_node: int, data
) -> bytes:
    """Sign with the existing X25519 scalar, normalizing the Edwards sign bit to zero."""
    scalar = bytearray(private_key)
    if len(scalar) != 32:
        raise ValueError("Private key must be 32 bytes")
    scalar[0] &= 248
    scalar[31] = (scalar[31] & 127) | 64
    normalized = xeddsa.priv_force_sign(bytes(scalar), False)
    return xeddsa.ed25519_priv_sign(
        normalized, signing_buffer(from_node, packet_id, to_node, data)
    )


def attach_signature(data, signature: bytes) -> None:
    """Field 10 is preserved as an unknown field by pre-2.8 protobuf packages."""
    if len(signature) != 64:
        raise ValueError("XEdDSA signature must be 64 bytes")
    if "xeddsa_signature" in data.DESCRIPTOR.fields_by_name:
        data.xeddsa_signature = signature
    else:
        data.MergeFromString(b"\x52\x40" + signature)


def build_nonce(packet_id: int, from_node: int, extra_nonce: int) -> bytes:
    nonce = bytearray(16)
    nonce[0:8] = int(packet_id).to_bytes(8, "little", signed=False)
    nonce[8:12] = int(from_node).to_bytes(4, "little", signed=False)
    if extra_nonce:
        nonce[4:8] = int(extra_nonce).to_bytes(4, "little", signed=False)
    return bytes(nonce[:13])


def build_shared_key(private_key: bytes, public_key: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(private_key).exchange(
        X25519PublicKey.from_public_bytes(public_key)
    )
    return sha256(shared).digest()


@dataclass(frozen=True)
class PkiEnvelope:
    ciphertext: bytes
    tag: bytes
    extra_nonce: int

    def pack(self) -> bytes:
        return (
            self.ciphertext
            + self.tag
            + self.extra_nonce.to_bytes(4, "little", signed=False)
        )


def encrypt_dm(
    *,
    sender_private_key: bytes,
    receiver_public_key: bytes,
    packet_id: int,
    from_node: int,
    plaintext: bytes,
    extra_nonce: Optional[int] = None,
) -> bytes:
    nonce_value = (
        secrets.randbits(32) if extra_nonce is None else int(extra_nonce) & 0xFFFFFFFF
    )
    key = build_shared_key(sender_private_key, receiver_public_key)
    nonce = build_nonce(packet_id, from_node, nonce_value)
    encrypted = AESCCM(key, tag_length=8).encrypt(nonce, plaintext, None)
    return PkiEnvelope(encrypted[:-8], encrypted[-8:], nonce_value).pack()


def decrypt_dm(
    *,
    receiver_private_key: bytes,
    sender_public_key: bytes,
    packet_id: int,
    from_node: int,
    payload: bytes,
) -> bytes:
    if len(payload) < 12:
        raise ValueError("PKI payload too short")
    ciphertext = payload[:-12]
    tag = payload[-12:-4]
    extra_nonce = int.from_bytes(payload[-4:], "little", signed=False)
    key = build_shared_key(receiver_private_key, sender_public_key)
    nonce = build_nonce(packet_id, from_node, extra_nonce)
    return AESCCM(key, tag_length=8).decrypt(nonce, ciphertext + tag, None)
