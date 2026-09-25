"""AES-256-GCM primitives for the calibration archive.

Record payloads are encrypted with a per-record 256-bit data encryption key
(DEK).  The DEK itself is wrapped (encrypted) with the current 256-bit master
key.  Both layers use AES-GCM with a random 96-bit nonce and record-bound
associated data, so a wrapped DEK or ciphertext can never be transplanted
onto a different record.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32  # AES-256
NONCE_LEN = 12  # 96-bit GCM nonce

AAD_RECORD_PREFIX = "lx-archive:v1:record:"
AAD_WRAP_PREFIX = "lx-archive:v1:dek-wrap:"


def generate_key() -> bytes:
    """Generate a fresh 256-bit key (master key or DEK)."""
    return os.urandom(KEY_LEN)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt and return nonce || ciphertext || tag."""
    if len(key) != KEY_LEN:
        raise ValueError("AES-256 key must be 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Decrypt a blob produced by :func:`aes_gcm_encrypt`."""
    if len(key) != KEY_LEN:
        raise ValueError("AES-256 key must be 32 bytes")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_aad(record_id: str) -> str:
    """Canonical associated data bound into a record ciphertext."""
    return f"{AAD_RECORD_PREFIX}{record_id}"


def wrap_aad(record_id: str) -> bytes:
    """Canonical associated data bound into a wrapped DEK."""
    return f"{AAD_WRAP_PREFIX}{record_id}".encode("utf-8")


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))
