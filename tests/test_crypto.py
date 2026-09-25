"""Unit tests for the AES-256-GCM crypto layer."""
import os

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto import (
    KEY_LEN,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_key,
    record_aad,
    sha256_hex,
    wrap_aad,
)


def test_roundtrip():
    key = generate_key()
    blob = aes_gcm_encrypt(key, b"LXe calibration 41.5 keV", b"aad")
    assert aes_gcm_decrypt(key, blob, b"aad") == b"LXe calibration 41.5 keV"


def test_key_is_256_bit():
    assert len(generate_key()) == KEY_LEN == 32


def test_wrong_key_rejected():
    blob = aes_gcm_encrypt(generate_key(), b"data", b"aad")
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(generate_key(), blob, b"aad")


def test_wrong_aad_rejected():
    key = generate_key()
    blob = aes_gcm_encrypt(key, b"data", record_aad("rec-1").encode())
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, blob, record_aad("rec-2").encode())


def test_tampered_ciphertext_rejected():
    key = generate_key()
    blob = bytearray(aes_gcm_encrypt(key, b"data", b"aad"))
    blob[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, bytes(blob), b"aad")


def test_nonce_randomised():
    key = generate_key()
    a = aes_gcm_encrypt(key, b"same plaintext", b"aad")
    b = aes_gcm_encrypt(key, b"same plaintext", b"aad")
    assert a != b  # fresh random nonce per encryption


def test_non_256bit_key_rejected():
    with pytest.raises(ValueError):
        aes_gcm_encrypt(os.urandom(16), b"x", b"aad")


def test_digest_and_aad_canonical():
    assert sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert record_aad("r1") == "lx-archive:v1:record:r1"
    assert wrap_aad("r1") == b"lx-archive:v1:dek-wrap:r1"
