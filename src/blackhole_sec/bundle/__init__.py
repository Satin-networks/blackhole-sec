"""Secure directory archives (.bhb).

Plain zip has two problems I kept running into: weak passwords crack fast,
and filenames sit in the clear even with AES. .bhb packs a directory to
tar.gz, then encrypts the whole thing with Argon2id -> AES-256-GCM.
Only blackhole can open it, which is the point.

Layout v1, big-endian:
  BHB1 | kdf_id | t,m,p | salt | nonce | ct_len | ct
  ct holds the tar.gz. The header is used as AAD.

Two modes: password, or no password (writes a .key file you need to keep).
"""
from __future__ import annotations

import io
import os
import shutil
import struct
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vault.crypto import DEFAULT_M, DEFAULT_P, DEFAULT_T, b64d, b64e, derive_key, generate_salt

MAGIC = b"BHB1"
VERSION_KDF_ARGON = 1
VERSION_KDF_NONE = 0
HEADER_FMT = ">4sBIIIH"  # magic, kdf_id, t, m, p, salt_len
NONCE_LEN = 12
# tar bigger than this spills to disk instead of RAM
SPOOL_LIMIT = 256 * 1024 * 1024


def _arcname(path: Path, root: Path) -> str:
    arc = path.relative_to(root).as_posix()
    if arc.startswith(("/", "~")) or ".." in Path(arc).parts:
        raise ValueError(f"unsafe path: {arc}")
    return arc


def _build_tar(src_dir: Path) -> bytes:
    with tempfile.SpooledTemporaryFile(max_size=SPOOL_LIMIT) as tmp:
        with tarfile.open(fileobj=tmp, mode="w:gz") as tf:
            for root, dirs, files in os.walk(src_dir):
                for d in sorted(dirs):
                    full = Path(root) / d
                    ti = tarfile.TarInfo(_arcname(full, src_dir))
                    ti.type = tarfile.DIRTYPE
                    ti.mode = 0o755
                    ti.mtime = int(full.stat().st_mtime)
                    tf.addfile(ti)
                for fn in sorted(files):
                    full = Path(root) / fn
                    arc = _arcname(full, src_dir)
                    ti = tf.gettarinfo(str(full), arcname=arc)
                    ti.uid = ti.gid = 0
                    ti.uname = ti.gname = ""
                    ti.mtime = int(ti.mtime)
                    with open(full, "rb") as f:
                        tf.addfile(ti, f)
        tmp.seek(0)
        return tmp.read()


def _safe_extract(tar_bytes: bytes, dest: Path) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    out: list[str] = []
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for m in tf.getmembers():
            # only regular files and dirs, never symlinks, fifos, devices
            if not (m.isfile() or m.isdir()):
                continue
            p = Path(m.name)
            if m.name.startswith("/") or ".." in p.parts or m.name.startswith("~"):
                continue
            target = dest / p
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(m)
                if f is None:
                    continue
                with open(target, "wb") as out_f:
                    shutil.copyfileobj(f, out_f, length=1024 * 1024)
                try:
                    os.chmod(target, m.mode & 0o777)
                except OSError:
                    pass
                out.append(m.name)
    return out


def _parse_header(data: bytes) -> tuple[int, int, int, int, bytes, bytes, bytes, bytes]:
    """Split a bundle into params and ciphertext. Raises ValueError, never struct.error."""
    hlen = struct.calcsize(HEADER_FMT)
    if len(data) < hlen + NONCE_LEN + 8:
        raise ValueError("not a .bhb bundle (too short)")
    try:
        magic, kdf_id, t, m, p, slen = struct.unpack(HEADER_FMT, data[:hlen])
    except struct.error as e:
        raise ValueError("not a .bhb bundle (bad header)") from e
    if magic != MAGIC:
        raise ValueError("not a .bhb bundle (bad magic)")
    off = hlen
    salt = data[off:off + slen]
    off += slen
    nonce = data[off:off + NONCE_LEN]
    off += NONCE_LEN
    if len(data) < off + 8:
        raise ValueError("truncated bundle")
    (ct_len,) = struct.unpack(">Q", data[off:off + 8])
    off += 8
    ct = data[off:off + ct_len]
    if len(ct) != ct_len:
        raise ValueError("truncated bundle")
    header = data[:off - 8]  # everything before ct_len is authenticated
    return kdf_id, t, m, p, salt, nonce, ct, header


def _unlock(kdf_id: int, t: int, m: int, p: int, salt: bytes,
            password: str | None, bundle: str | Path, keyfile: str | Path | None) -> bytes:
    if kdf_id == VERSION_KDF_ARGON:
        if not password:
            raise ValueError("bundle needs a password (--password)")
        return derive_key(password, salt, t, m, p)
    if kdf_id == VERSION_KDF_NONE:
        kf = keyfile or (str(bundle) + ".key")
        return b64d(Path(kf).read_text().strip())
    raise ValueError(f"unsupported kdf_id {kdf_id}")


def _wipe(key: bytes) -> None:
    try:
        for i in range(len(key)):
            key[i] = 0  # type: ignore
    except (TypeError, IndexError):
        pass


def create_bundle(src_dir: str | Path, out: str | Path, password: str | None,
                  t: int = DEFAULT_T, m: int = DEFAULT_M, p: int = DEFAULT_P) -> dict:
    src = Path(src_dir)
    dst = Path(out)
    if not src.is_dir():
        raise ValueError("src must be a directory")
    tar_bytes = _build_tar(src)
    if password:
        salt = generate_salt()
        key = derive_key(password, salt, t, m, p)
        kdf_id = VERSION_KDF_ARGON
        keyfile = None
    else:
        salt = generate_salt(8)  # header salt marker only
        key = os.urandom(32)
        kdf_id = VERSION_KDF_NONE
        keyfile = str(dst) + ".key"
        Path(keyfile).write_text(b64e(key))
        os.chmod(keyfile, 0o600)
    nonce = os.urandom(NONCE_LEN)
    header = struct.pack(HEADER_FMT, MAGIC, kdf_id, t, m, p, len(salt)) + salt + nonce
    ct = AESGCM(key).encrypt(nonce, tar_bytes, header)
    _wipe(key)
    with open(dst, "wb") as f:
        f.write(header + struct.pack(">Q", len(ct)) + ct)
    os.chmod(dst, 0o600)
    return {"bundle": str(dst), "keyfile": keyfile, "bytes_in": len(tar_bytes),
            "bytes_out": dst.stat().st_size, "kdf": "argon2id" if password else "keyfile"}


def read_bundle(bundle: str | Path, password: str | None = None,
                keyfile: str | Path | None = None) -> bytes:
    """Decrypt and return the raw tar.gz bytes. Raises ValueError on any failure."""
    data = Path(bundle).read_bytes()
    kdf_id, t, m, p, salt, nonce, ct, header = _parse_header(data)
    key = _unlock(kdf_id, t, m, p, salt, password, bundle, keyfile)
    try:
        return AESGCM(key).decrypt(nonce, ct, header)
    except Exception as e:
        raise ValueError("decryption failed: wrong password/keyfile or tampered bundle") from e
    finally:
        _wipe(key)


def list_bundle(bundle: str | Path, password: str | None = None,
                keyfile: str | Path | None = None) -> list[tuple[str, int]]:
    """List (name, size) of files inside, without extracting anything."""
    buf = io.BytesIO(read_bundle(bundle, password, keyfile))
    out: list[tuple[str, int]] = []
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for m in tf.getmembers():
            if m.isfile():
                out.append((m.name, m.size))
    return out


def extract_bundle(bundle: str | Path, dest: str | Path, password: str | None = None,
                   keyfile: str | Path | None = None) -> list[str]:
    return _safe_extract(read_bundle(bundle, password, keyfile), Path(dest))
