"""Key derivation and encryption. Argon2id into AES-256-GCM."""
from __future__ import annotations

import base64
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_T = 3          # time cost (OWASP recommended >=3 for interactive)
DEFAULT_M = 64 * 1024  # 64 MiB
DEFAULT_P = 4
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def generate_salt(n: int = SALT_LEN) -> bytes:
    return os.urandom(n)


def derive_key(master: str, salt: bytes, t: int = DEFAULT_T, m: int = DEFAULT_M, p: int = DEFAULT_P) -> bytes:
    if not master:
        raise ValueError("master password must not be empty")
    return hash_secret_raw(master.encode("utf-8"), salt, time_cost=t,
                           memory_cost=m, parallelism=p, hash_len=KEY_LEN, type=Type.ID)


def encrypt_blob(key: bytes, plaintext: bytes, aad: bytes = b"blackhole-sec/vault-v1") -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt_blob(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"blackhole-sec/vault-v1") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())
