"""One encrypted file on disk. Wrong password just doesn't open."""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .crypto import (
    DEFAULT_M,
    DEFAULT_P,
    DEFAULT_T,
    b64d,
    b64e,
    decrypt_blob,
    derive_key,
    encrypt_blob,
    generate_salt,
)

VAULT_VERSION = 1
VERIFIER = "blackhole-sec-verifier"


@dataclass
class VaultEntry:
    service: str
    username: str = ""
    password: str = ""
    notes: str = ""
    created: int = 0
    updated: int = 0


class VaultLocked(Exception):
    pass


class Vault:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._key: bytes | None = None
        self._entries: dict[str, VaultEntry] = {}
        self._salt: bytes | None = None
        self._params: dict = {}

    # ---- lifecycle ----
    @classmethod
    def create(cls, path: str | Path, master: str) -> Vault:
        v = cls(path)
        salt = generate_salt()
        key = derive_key(master, salt)
        v._key, v._salt = key, salt
        v._params = {"t": DEFAULT_T, "m": DEFAULT_M, "p": DEFAULT_P}
        v._entries = {}
        v._save()
        _wipe(key)
        v._key = derive_key(master, salt, DEFAULT_T, DEFAULT_M, DEFAULT_P)
        return v

    def unlock(self, master: str) -> None:
        raw = json.loads(self.path.read_text())
        salt = b64d(raw["salt"])
        p = raw.get("kdf_params", {})
        key = derive_key(master, salt, p.get("t", DEFAULT_T), p.get("m", DEFAULT_M), p.get("p", DEFAULT_P))
        try:
            pt = decrypt_blob(key, b64d(raw["nonce"]), b64d(raw["ct"]))
            payload = json.loads(pt.decode())
        except Exception:
            _wipe(key)
            raise VaultLocked("wrong master password or corrupted vault")
        if payload.get("verifier") != VERIFIER:
            _wipe(key)
            raise VaultLocked("wrong master password or corrupted vault")
        self._key, self._salt, self._params = key, salt, p
        self._entries = {k: VaultEntry(**e) for k, e in payload.get("entries", {}).items()}

    def lock(self) -> None:
        if self._key:
            _wipe(self._key)
        self._key = None
        self._entries = {}

    @property
    def is_locked(self) -> bool:
        return self._key is None

    def _require_open(self):
        if self.is_locked:
            raise VaultLocked("vault is locked")

    def _save(self) -> None:
        self._require_open()
        assert self._key and self._salt
        payload = {"verifier": VERIFIER,
                   "entries": {k: asdict(e) for k, e in self._entries.items()}}
        nonce, ct = encrypt_blob(self._key, json.dumps(payload).encode())
        raw = {"version": VAULT_VERSION, "kdf": "argon2id",
               "kdf_params": self._params, "salt": b64e(self._salt),
               "nonce": b64e(nonce), "ct": b64e(ct)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(raw))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    # ---- CRUD ----
    def set(self, service: str, username: str = "", password: str = "", notes: str = "") -> VaultEntry:
        self._require_open()
        now = int(time.time())
        e = self._entries.get(service) or VaultEntry(service=service, created=now)
        e.username, e.password, e.notes, e.updated = username, password, notes, now
        self._entries[service] = e
        self._save()
        return e

    def get(self, service: str) -> VaultEntry | None:
        self._require_open()
        return self._entries.get(service)

    def remove(self, service: str) -> bool:
        self._require_open()
        if service in self._entries:
            del self._entries[service]
            self._save()
            return True
        return False

    def list_services(self) -> list[str]:
        self._require_open()
        return sorted(self._entries)

    def change_master(self, new_master: str) -> None:
        self._require_open()
        salt = generate_salt()
        self._salt = salt
        if self._key:
            _wipe(self._key)
        self._key = derive_key(new_master, salt,
                               self._params.get("t", DEFAULT_T),
                               self._params.get("m", DEFAULT_M),
                               self._params.get("p", DEFAULT_P))
        self._save()

    def audit(self) -> dict:
        """Password health: what is reused, weak, or untouched for over a year."""
        self._require_open()
        pw_map: dict[str, list[str]] = {}
        weak, old = [], []
        now = int(time.time())
        for s, e in self._entries.items():
            pw_map.setdefault(e.password, []).append(s)
            if len(e.password) < 12:
                weak.append(s)
            if e.updated and now - e.updated > 365 * 86400:
                old.append(s)
        reused = {pw: svcs for pw, svcs in pw_map.items() if pw and len(svcs) > 1}
        score = 100 - 15 * len(reused) - 5 * len(weak) - 2 * len(old)
        return {"score": max(0, score), "reused": reused, "weak": sorted(weak),
                "stale": sorted(old), "total": len(self._entries)}


def _wipe(b: bytearray | bytes) -> None:
    try:
        for i in range(len(b)):
            b[i] = 0  # type: ignore
    except Exception:
        pass
