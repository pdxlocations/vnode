from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from hashlib import sha256

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


def generate_keypair() -> tuple[bytes, bytes]:
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
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


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
        return self.ciphertext + self.tag + self.extra_nonce.to_bytes(4, "little", signed=False)


def encrypt_dm(
    *,
    sender_private_key: bytes,
    receiver_public_key: bytes,
    packet_id: int,
    from_node: int,
    plaintext: bytes,
    extra_nonce: int | None = None,
) -> bytes:
    nonce_value = secrets.randbits(32) if extra_nonce is None else int(extra_nonce) & 0xFFFFFFFF
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
