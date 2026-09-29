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
import struct
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vault.crypto import DEFAULT_M, DEFAULT_P, DEFAULT_T, b64d, b64e, derive_key, generate_salt

MAGIC = b"BHB1"
VERSION_KDF_ARGON = 1
VERSION_KDF_NONE = 0
HEADER_FMT = ">4sBIIIH"  # magic, kdf_id, t, m, p, salt_len
NONCE_LEN = 12


def _build_tar(src_dir: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for root, _, files in os.walk(src_dir):
            for fn in sorted(files):
                full = Path(root) / fn
                arc = full.relative_to(src_dir).as_posix()
                # ZipSlip-class defense at build time
                if arc.startswith("/") or ".." in Path(arc).parts:
                    raise ValueError(f"unsafe path: {arc}")
                ti = tf.gettarinfo(str(full), arcname=arc)
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mtime = int(ti.mtime)
                with open(full, "rb") as f:
                    tf.addfile(ti, f)
    return buf.getvalue()


def _safe_extract(tar_bytes: bytes, dest: Path) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    out: list[str] = []
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for m in tf.getmembers():
            # Reject everything but regular files/dirs (no symlinks, fifos, devices)
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
                target.write_bytes(f.read())
                try:
                    os.chmod(target, m.mode & 0o777)
                except Exception:
                    pass
                out.append(m.name)
    return out


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
    aad = header  # authenticate everything before ct
    ct = AESGCM(key).encrypt(nonce, tar_bytes, aad)
    # wipe key material best-effort
    try:
        for i in range(len(key)):
            key[i] = 0  # type: ignore
    except Exception:
        pass
    with open(dst, "wb") as f:
        f.write(header + struct.pack(">Q", len(ct)) + ct)
    os.chmod(dst, 0o600)
    return {"bundle": str(dst), "keyfile": keyfile, "bytes_in": len(tar_bytes),
            "bytes_out": dst.stat().st_size, "kdf": "argon2id" if password else "keyfile"}


def extract_bundle(bundle: str | Path, dest: str | Path, password: str | None = None,
                   keyfile: str | Path | None = None) -> list[str]:
    data = Path(bundle).read_bytes()
    hlen = struct.calcsize(HEADER_FMT)
    magic, kdf_id, t, m, p, slen = struct.unpack(HEADER_FMT, data[:hlen])
    if magic != MAGIC:
        raise ValueError("not a .bhb bundle (bad magic)")
    off = hlen
    salt = data[off:off + slen]
    off += slen
    nonce = data[off:off + NONCE_LEN]
    off += NONCE_LEN
    (ct_len,) = struct.unpack(">Q", data[off:off + 8])
    off += 8
    ct = data[off:off + ct_len]
    if len(ct) != ct_len:
        raise ValueError("truncated bundle")
    header = data[:off - 8]  # up to nonce inclusive == AAD
    if kdf_id == VERSION_KDF_ARGON:
        if not password:
            raise ValueError("bundle needs a password (--password)")
        key = derive_key(password, salt, t, m, p)
    elif kdf_id == VERSION_KDF_NONE:
        kf = keyfile or (str(bundle) + ".key")
        key = b64d(Path(kf).read_text().strip())
    else:
        raise ValueError(f"unsupported kdf_id {kdf_id}")
    try:
        tar_bytes = AESGCM(key).decrypt(nonce, ct, header)
    except Exception as e:
        raise ValueError("decryption failed: wrong password/keyfile or tampered bundle") from e
    finally:
        try:
            for i in range(len(key)):
                key[i] = 0  # type: ignore
        except Exception:
            pass
    return _safe_extract(tar_bytes, Path(dest))
