"""Key derivation and encryption. Argon2id into AES-256-GCM."""
from __future__ import annotations

import base64
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Vault opens on every command, so the default stays below the bundle
# default. Params live in the file; old vaults keep their own numbers.
KDF_PRESETS = {
    "light": {"t": 3, "m": 64 * 1024, "p": 4},      # the old default
    "hard": {"t": 8, "m": 512 * 1024, "p": 4},      # default now
    "paranoid": {"t": 12, "m": 2048 * 1024, "p": 4},  # ~128x light
}
DEFAULT_PRESET = "hard"
DEFAULT_T = KDF_PRESETS[DEFAULT_PRESET]["t"]
DEFAULT_M = KDF_PRESETS[DEFAULT_PRESET]["m"]
DEFAULT_P = KDF_PRESETS[DEFAULT_PRESET]["p"]
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def preset_params(preset: str) -> dict:
    if preset not in KDF_PRESETS:
        raise ValueError(f"unknown kdf preset {preset!r}; pick one of: {', '.join(KDF_PRESETS)}")
    return dict(KDF_PRESETS[preset])


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


def file_key(vault_key: bytes | bytearray, file_id: str) -> bytes:
    """One key per stored file, derived from the vault key."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None,
                info=b"blackhole-sec vault file " + file_id.encode()).derive(bytes(vault_key))


def encrypt_file_blob(vault_key: bytes | bytearray, file_id: str, data: bytes) -> bytes:
    """nonce || ciphertext. The file id goes in as AAD, so blobs cannot be swapped around."""
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(file_key(vault_key, file_id)).encrypt(nonce, data, file_id.encode())
    return nonce + ct


def decrypt_file_blob(vault_key: bytes | bytearray, file_id: str, blob: bytes) -> bytes:
    if len(blob) <= NONCE_LEN:
        raise ValueError("file blob is truncated")
    return AESGCM(file_key(vault_key, file_id)).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], file_id.encode())


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())
