"""One encrypted file on disk. Wrong password just doesn't open."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .crypto import (
    DEFAULT_M,
    DEFAULT_P,
    DEFAULT_PRESET,
    DEFAULT_T,
    b64d,
    b64e,
    decrypt_blob,
    decrypt_file_blob,
    derive_key,
    encrypt_blob,
    encrypt_file_blob,
    generate_salt,
    preset_params,
)

VAULT_VERSION = 1
VERIFIER = "blackhole-sec-verifier"
FILE_MAX_BYTES = 64 * 1024 * 1024


@dataclass
class VaultEntry:
    service: str
    username: str = ""
    password: str = ""
    notes: str = ""
    created: int = 0
    updated: int = 0
    kind: str = "secret"  # "secret" or "file"
    file_id: str = ""
    filename: str = ""
    size: int = 0
    sha256: str = ""


class VaultLocked(Exception):
    pass


class Vault:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self._key: bytearray | None = None
        self._entries: dict[str, VaultEntry] = {}
        self._salt: bytes | None = None
        self._params: dict = {}

    @classmethod
    def create(cls, path: str | Path, master: str, preset: str = DEFAULT_PRESET,
               t: int | None = None, m: int | None = None, p: int | None = None) -> Vault:
        v = cls(path)
        params = preset_params(preset)
        if t is not None:
            params["t"] = t
        if m is not None:
            params["m"] = m
        if p is not None:
            params["p"] = p
        salt = generate_salt()
        v._key = bytearray(derive_key(master, salt, params["t"], params["m"], params["p"]))
        v._salt, v._params = salt, params
        v._entries = {}
        v._save()
        return v

    def unlock(self, master: str) -> None:
        raw = json.loads(self.path.read_text())
        salt = b64d(raw["salt"])
        p = raw.get("kdf_params", {})
        key = bytearray(derive_key(master, salt, p.get("t", DEFAULT_T), p.get("m", DEFAULT_M), p.get("p", DEFAULT_P)))
        try:
            pt = decrypt_blob(bytes(key), b64d(raw["nonce"]), b64d(raw["ct"]))
            payload = json.loads(pt.decode())
        except Exception:
            _wipe(key)
            raise VaultLocked("wrong master password or corrupted vault") from None
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

    @property
    def files_dir(self) -> Path:
        """File blobs live in a sibling directory so the vault itself stays small."""
        return self.path.with_name(self.path.name + ".files")

    def _blob_path(self, file_id: str) -> Path:
        return self.files_dir / f"{file_id}.bin"

    def _save(self) -> None:
        self._require_open()
        assert self._key and self._salt
        payload = {"verifier": VERIFIER,
                   "entries": {k: asdict(e) for k, e in self._entries.items()}}
        nonce, ct = encrypt_blob(bytes(self._key), json.dumps(payload).encode())
        raw = {"version": VAULT_VERSION, "kdf": "argon2id",
               "kdf_params": self._params, "salt": b64e(self._salt),
               "nonce": b64e(nonce), "ct": b64e(ct)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(raw))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def set(self, service: str, username: str = "", password: str = "", notes: str = "") -> VaultEntry:
        self._require_open()
        now = int(time.time())
        e = self._entries.get(service) or VaultEntry(service=service, created=now)
        stale = e.file_id if e.kind == "file" else ""
        e.kind, e.file_id, e.filename, e.size, e.sha256 = "secret", "", "", 0, ""
        e.username, e.password, e.notes, e.updated = username, password, notes, now
        self._entries[service] = e
        self._save()
        if stale:
            self._blob_path(stale).unlink(missing_ok=True)
        return e

    def get(self, service: str) -> VaultEntry | None:
        self._require_open()
        return self._entries.get(service)

    def remove(self, service: str) -> bool:
        self._require_open()
        e = self._entries.get(service)
        if e is None:
            return False
        del self._entries[service]
        self._save()
        if e.kind == "file" and e.file_id:
            self._blob_path(e.file_id).unlink(missing_ok=True)
        return True

    def list_services(self) -> list[str]:
        self._require_open()
        return sorted(self._entries)

    def add_file(self, source: str | Path, label: str = "", notes: str = "",
                 max_bytes: int = FILE_MAX_BYTES) -> VaultEntry:
        """Store a copy of a file under LABEL. The bytes get their own key and go
        to the sibling .files directory; only metadata goes into the payload."""
        self._require_open()
        src = Path(source).expanduser()
        if not src.is_file():
            raise FileNotFoundError(f"no file at {src}")
        size = src.stat().st_size
        if size > max_bytes:
            raise ValueError(f"{src.name} is {_mib(size)}, the vault cap is {_mib(max_bytes)}")
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        label = label or src.name
        old = self._entries.get(label)
        stale = old.file_id if old and old.kind == "file" else ""
        file_id = secrets.token_hex(8)
        assert self._key is not None
        blob = encrypt_file_blob(self._key, file_id, data)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.files_dir, 0o700)
        tmp = self.files_dir / f"{file_id}.tmp"
        tmp.write_bytes(blob)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._blob_path(file_id))
        now = int(time.time())
        e = old or VaultEntry(service=label, created=now)
        e.kind, e.file_id, e.filename = "file", file_id, src.name
        e.size, e.sha256, e.notes, e.updated = size, digest, notes, now
        e.username = e.password = ""
        self._entries[label] = e
        try:
            self._save()
        except Exception:
            self._blob_path(file_id).unlink(missing_ok=True)
            raise
        if stale and stale != file_id:
            self._blob_path(stale).unlink(missing_ok=True)
        return e

    def export_file(self, label: str, dest: str | Path = ".", force: bool = False) -> Path:
        """Write a stored file back out. DEST is a directory when it names one
        (or ends in a slash), a file path otherwise."""
        self._require_open()
        e = self._entries.get(label)
        if e is None or e.kind != "file":
            raise KeyError(label)
        blob_path = self._blob_path(e.file_id)
        if not blob_path.is_file():
            raise FileNotFoundError(f"stored bytes for '{label}' are gone ({blob_path.name} missing)")
        assert self._key is not None
        try:
            data = decrypt_file_blob(self._key, e.file_id, blob_path.read_bytes())
        except InvalidTag:
            raise ValueError(f"the stored copy of '{label}' is damaged (failed its integrity check)") from None
        if hashlib.sha256(data).hexdigest() != e.sha256:
            raise ValueError(f"the stored copy of '{label}' does not match its checksum")
        raw = str(dest)
        dest = Path(dest).expanduser()
        out = dest / (e.filename or label) if dest.is_dir() or raw.endswith(("/", os.sep)) else dest
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists() and not force:
            raise FileExistsError(out)
        tmp = out.with_name(out.name + ".part")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, out)
        return out

    def change_master(self, new_master: str, preset: str = DEFAULT_PRESET) -> None:
        """Re-key with a fresh salt. Also upgrades the KDF to the current default
        unless a preset is given, so 'vault passwd' is the migration path for old vaults.
        Stored files are re-wrapped under the new key: the payload is saved first and
        only then do the new blobs take over, so a failed save changes nothing."""
        self._require_open()
        assert self._key is not None
        old_key = self._key
        salt = generate_salt()
        params = preset_params(preset)
        new_key = bytearray(derive_key(new_master, salt, params["t"], params["m"], params["p"]))
        staged: list[tuple[Path, Path]] = []
        try:
            for e in self._entries.values():
                if e.kind != "file" or not e.file_id:
                    continue
                blob = self._blob_path(e.file_id)
                data = decrypt_file_blob(old_key, e.file_id, blob.read_bytes())
                if hashlib.sha256(data).hexdigest() != e.sha256:
                    raise ValueError(f"stored copy of '{e.service}' does not match its checksum")
                new_blob = blob.with_name(blob.name + ".new")
                new_blob.write_bytes(encrypt_file_blob(new_key, e.file_id, data))
                os.chmod(new_blob, 0o600)
                staged.append((new_blob, blob))
        except Exception:
            for new_blob, _ in staged:
                new_blob.unlink(missing_ok=True)
            _wipe(new_key)
            raise
        self._salt, self._params = salt, params
        _wipe(old_key)
        self._key = new_key
        try:
            self._save()
        except Exception:
            for new_blob, _ in staged:
                new_blob.unlink(missing_ok=True)
            raise
        for new_blob, blob in staged:
            os.replace(new_blob, blob)

    def audit(self) -> dict:
        """Password health: what is reused, weak, or untouched for over a year."""
        self._require_open()
        pw_map: dict[str, list[str]] = {}
        weak, old = [], []
        now = int(time.time())
        for s, e in self._entries.items():
            if e.kind == "file":
                continue  # stored files carry no site password
            pw_map.setdefault(e.password, []).append(s)
            if len(e.password) < 12:
                weak.append(s)
            if e.updated and now - e.updated > 365 * 86400:
                old.append(s)
        reused = {pw: svcs for pw, svcs in pw_map.items() if pw and len(svcs) > 1}
        score = 100 - 15 * len(reused) - 5 * len(weak) - 2 * len(old)
        return {"score": max(0, score), "reused": reused, "weak": sorted(weak),
                "stale": sorted(old), "total": len(self._entries)}


def _mib(n: int) -> str:
    return f"{n / (1024 * 1024):.0f} MiB"


def _wipe(b: bytearray | bytes) -> None:
    """Best effort: zero a bytearray in place. Bytes cannot be wiped in Python."""
    if isinstance(b, bytearray):
        b[:] = b"\x00" * len(b)
