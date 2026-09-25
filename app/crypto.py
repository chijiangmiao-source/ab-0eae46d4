"""Cryptographic primitives: AES-256-GCM record encryption and key wrapping.

Every calibration record is encrypted under a freshly generated 256-bit data
key (DEK). The DEK is then wrapped (encrypted) under a master key using
AES-256-GCM with authenticated additional data binding the wrap to the record
and the wrapping master-key version, so a wrap cannot be moved between records
or master keys.

All binary blobs use a self-describing framing::

    v1 | 12-byte nonce | ciphertext (plaintext + 16-byte GCM tag at tail)

so the format is self contained and future versions can be negotiated.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"v1"
KEY_LEN = 32  # AES-256
NONCE_LEN = 12
_ENCODING = "utf-8"


def new_key() -> bytes:
    """Generate a fresh AES-256 key."""
    return AESGCM.generate_key(bit_length=256)


def _b64e(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    import base64

    return base64.b64decode(text.encode("ascii"), validate=True)


def _aad(parts: list[bytes]) -> bytes:
    """Length-prefixed concatenation so fields cannot be confused."""
    out = bytearray()
    for part in parts:
        out.extend(len(part).to_bytes(4, "big"))
        out.extend(part)
    return bytes(out)


def encrypt_record(plaintext: str, dek: bytes, record_id: str) -> tuple[str, str]:
    """Return ``(ciphertext_b64, digest_hex)`` for the given plaintext.

    The ciphertext is AES-256-GCM under ``dek`` with AAD binding the record id.
    The digest is computed over the plaintext and is rotation invariant.
    """
    import hashlib

    data = plaintext.encode(_ENCODING)
    digest = hashlib.sha256(data).hexdigest()
    nonce = os.urandom(NONCE_LEN)
    aad = _aad([b"record", record_id.encode(_ENCODING), digest.encode("ascii")])
    ct = AESGCM(dek).encrypt(nonce, data, aad)
    blob = VERSION + nonce + ct
    return _b64e(blob), digest


def decrypt_record(ciphertext_b64: str, dek: bytes, record_id: str, digest: str) -> str:
    """Authenticate and decrypt a record ciphertext."""
    blob = _b64d(ciphertext_b64)
    version, nonce, ct = blob[:2], blob[2 : 2 + NONCE_LEN], blob[2 + NONCE_LEN :]
    if version != VERSION:
        raise ValueError(f"unsupported ciphertext version: {version!r}")
    aad = _aad([b"record", record_id.encode(_ENCODING), digest.encode("ascii")])
    data = AESGCM(dek).decrypt(nonce, ct, aad)
    return data.decode(_ENCODING)


def wrap_dek(dek: bytes, master_key: bytes, record_id: str, kid: str) -> str:
    """Wrap a DEK under a master key, binding record id and kid in the AAD."""
    nonce = os.urandom(NONCE_LEN)
    aad = _aad(
        [
            b"wrap",
            record_id.encode(_ENCODING),
            str(kid).encode(_ENCODING),
        ]
    )
    ct = AESGCM(master_key).encrypt(nonce, dek, aad)
    return _b64e(VERSION + nonce + ct)


def unwrap_dek(wrapped_b64: str, master_key: bytes, record_id: str, kid: str) -> bytes:
    """Authenticate and unwrap a DEK wrapped under ``master_key``."""
    blob = _b64d(wrapped_b64)
    version, nonce, ct = blob[:2], blob[2 : 2 + NONCE_LEN], blob[2 + NONCE_LEN :]
    if version != VERSION:
        raise ValueError(f"unsupported wrap version: {version!r}")
    aad = _aad(
        [
            b"wrap",
            record_id.encode(_ENCODING),
            str(kid).encode(_ENCODING),
        ]
    )
    return AESGCM(master_key).decrypt(nonce, ct, aad)


def content_digest(plaintext: str) -> str:
    import hashlib

    return hashlib.sha256(plaintext.encode(_ENCODING)).hexdigest()
