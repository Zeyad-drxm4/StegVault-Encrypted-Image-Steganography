"""Cryptographic helpers: key derivation, authenticated encryption, keyed permutation."""

from __future__ import annotations

import os

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

# scrypt cost parameters (interactive-login strength; ~50-100 ms on a laptop)
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


class DecryptionError(Exception):
    """Raised when authenticated decryption fails (wrong password or tampered data)."""


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derive two independent 256-bit keys from a password.

    Returns (encryption_key, permutation_key).
    """
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = Scrypt(salt=salt, length=64, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    material = kdf.derive(password.encode("utf-8"))
    return material[:32], material[32:]


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """AES-256-GCM encrypt. Output layout: nonce || ciphertext || tag."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, blob: bytes, associated_data: bytes) -> bytes:
    nonce, body = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, body, associated_data)
    except InvalidTag as exc:
        raise DecryptionError("Authentication failed.") from exc


def keyed_permutation(key: bytes, n: int) -> np.ndarray:
    """Deterministic pseudo-random permutation of range(n) derived from `key`.

    Uses an AES-CTR keystream as sort keys, so the result is identical on every
    platform and NumPy version (unlike NumPy's own RNG streams).
    """
    if n == 0:
        return np.empty(0, dtype=np.int64)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16)).encryptor()
    stream = encryptor.update(b"\x00" * (n * 8)) + encryptor.finalize()
    sort_keys = np.frombuffer(stream, dtype="<u8")
    return np.argsort(sort_keys, kind="stable")
