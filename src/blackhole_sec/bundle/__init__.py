"""Secure directory archives (.bhb).

Three ways to pack a directory:

- With a password: tar.gz encrypted whole with Argon2id -> AES-256-GCM.
  Names, contents, everything hidden. Only blackhole opens it.
- With a password and --keyfile: the same, plus a second factor. The
  key is Argon2id(password) mixed (HKDF) with SHA-256(keyfile bytes),
  so opening needs both. A leaked bundle alone cannot even be attacked
  offline without the keyfile.
- With --no-password: plain packed tar.gz, not encrypted at all. Anyone
  with the file can open it, same as zip without a password. Only for
  stuff you don't mind sharing.

Password mode is built so that guessing the password is the only way in,
and a guess is never cheap. The Argon2id work factor lives in the header
as t/m/p, so every bundle carries its own cost:

  light     64 MiB, 3 passes    (the old default; weak devices, tests)
  hard      1 GiB, 8 passes     (default since 0.3.0; ~42x light)
  paranoid  2 GiB, 12 passes    (~128x light; wants RAM to spare)

read_bundle derives with whatever the file says, so bundles written by
older versions keep opening with their original numbers. Creating one
also refuses sloppy passwords up front (see password_problems).

Old keyfile-mode bundles (a random key in a sidecar .key file, from
0.2.x and earlier) still open, but nothing creates them anymore.

Layout v1, big-endian:
  BHB1 | kdf_id | t,m,p | salt | [nonce] | ct_len | ct
  kdf_id 1 (password), 3 (password + keyfile), and 0 (legacy keyfile)
  carry a 12-byte nonce and ct is AES-GCM with the header as AAD.
  kdf_id 2 (plain) has no nonce and ct is the tar.gz as-is.
"""
from __future__ import annotations

import hashlib
import io
import os
import shutil
import struct
import tarfile
import tempfile
from pathlib import Path

from argon2.exceptions import HashingError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..policy import password_problems as password_problems  # re-export, older importers
from ..vault.crypto import b64d, derive_key, generate_salt, mix_keyfile_digest

MAGIC = b"BHB1"
VERSION_KDF_ARGON = 1
VERSION_KDF_NONE = 0  # legacy keyfile mode: still readable, no longer written
VERSION_KDF_PLAIN = 2
VERSION_KDF_ARGON_KEYFILE = 3  # password + keyfile (two factors)
HEADER_FMT = ">4sBIIIH"  # magic, kdf_id, t, m, p, salt_len
NONCE_LEN = 12
# tar bigger than this spills to disk instead of RAM
SPOOL_LIMIT = 256 * 1024 * 1024

# Password-mode work factors: what one guess costs an offline attacker.
# Scale memory first, that is what hurts GPUs.
KDF_PRESETS = {
    "light": {"t": 3, "m": 64 * 1024, "p": 4},
    "hard": {"t": 8, "m": 1024 * 1024, "p": 4},
    "paranoid": {"t": 12, "m": 2048 * 1024, "p": 4},
}
DEFAULT_KDF_PRESET = "hard"

# accepted header ranges, so a crafted file cannot ask this machine
# for more RAM than it has
MIN_T, MAX_T = 1, 64
MIN_M, MAX_M = 8, 4 * 1024 * 1024  # KiB
MIN_P, MAX_P = 1, 16
MIN_SALT, MAX_SALT = 8, 64


class BundleError(ValueError):
    """Anything wrong with a .bhb file: shape, parameters, or contents."""


class NeedsPassword(BundleError):
    """The bundle is password-protected and no password was given."""


class WrongPassword(BundleError):
    """Authentication failed: wrong secret, or the file was tampered with."""


class NeedsKeyfile(BundleError):
    """The bundle is two-factor and the keyfile was not given (or is missing)."""


class WeakPassword(BundleError):
    """The password would not survive a serious offline guess."""


def _kdf_params(preset: str, t: int | None, m: int | None, p: int | None) -> tuple[int, int, int]:
    if preset not in KDF_PRESETS:
        raise BundleError(
            f"unknown kdf preset {preset!r}; pick one of: {', '.join(KDF_PRESETS)}"
        )
    base = KDF_PRESETS[preset]
    return (
        base["t"] if t is None else t,
        base["m"] if m is None else m,
        base["p"] if p is None else p,
    )


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
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            for m in tf:
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
    except OSError:
        raise
    except (tarfile.TarError, EOFError) as e:
        raise BundleError("bundle contents are damaged") from e
    return out


def _parse_header(data: bytes) -> tuple[int, int, int, int, bytes, bytes, bytes, bytes]:
    """Split a bundle into params and payload. Raises BundleError, never struct.error."""
    hlen = struct.calcsize(HEADER_FMT)
    if len(data) < hlen + 8:
        raise BundleError("not a .bhb bundle (too short)")
    try:
        magic, kdf_id, t, m, p, slen = struct.unpack(HEADER_FMT, data[:hlen])
    except struct.error as e:
        raise BundleError("not a .bhb bundle (bad header)") from e
    if magic != MAGIC:
        raise BundleError("not a .bhb bundle (bad magic)")
    if kdf_id not in (VERSION_KDF_ARGON, VERSION_KDF_NONE, VERSION_KDF_PLAIN, VERSION_KDF_ARGON_KEYFILE):
        raise BundleError(f"unsupported kdf_id {kdf_id}")
    if kdf_id != VERSION_KDF_PLAIN:
        if not (MIN_T <= t <= MAX_T) or not (MIN_M <= m <= MAX_M) or not (MIN_P <= p <= MAX_P):
            raise BundleError(
                f"unsupported KDF parameters in header (t={t}, m={m}, p={p})"
            )
        if not (MIN_SALT <= slen <= MAX_SALT):
            raise BundleError(f"unsupported salt length {slen}")
    off = hlen
    salt = data[off:off + slen]
    if len(salt) != slen:
        raise BundleError("truncated bundle")
    off += slen
    nonce = b""
    if kdf_id in (VERSION_KDF_ARGON, VERSION_KDF_NONE, VERSION_KDF_ARGON_KEYFILE):
        nonce = data[off:off + NONCE_LEN]
        if len(nonce) != NONCE_LEN:
            raise BundleError("truncated bundle")
        off += NONCE_LEN
    if len(data) < off + 8:
        raise BundleError("truncated bundle")
    (ct_len,) = struct.unpack(">Q", data[off:off + 8])
    off += 8
    ct = data[off:off + ct_len]
    if len(ct) != ct_len:
        raise BundleError("truncated bundle")
    header = data[:off - 8]  # everything before ct_len is authenticated (modes 0 and 1)
    return kdf_id, t, m, p, salt, nonce, ct, header


def _unlock(kdf_id: int, t: int, m: int, p: int, salt: bytes,
            password: str | None, bundle: str | Path, keyfile: str | Path | None) -> bytes:
    if kdf_id == VERSION_KDF_ARGON:
        if not password:
            raise NeedsPassword("bundle needs a password (--password)")
        return derive_key(password, salt, t, m, p)
    if kdf_id == VERSION_KDF_ARGON_KEYFILE:
        if not password:
            raise NeedsPassword("bundle needs a password (--password)")
        if not keyfile:
            raise NeedsKeyfile("this bundle also needs its keyfile (--keyfile PATH)")
        base = bytearray(derive_key(password, salt, t, m, p))
        try:
            return mix_keyfile_digest(bytes(base), _keyfile_digest(keyfile))
        finally:
            _wipe(base)
    if kdf_id == VERSION_KDF_NONE:
        kf = keyfile or (str(bundle) + ".key")
        raw = Path(kf).read_text().strip()
        try:
            return b64d(raw)
        except Exception as e:
            raise BundleError(f"keyfile {kf} is not a valid key") from e
    raise BundleError(f"unsupported kdf_id {kdf_id}")


def _wipe(key: bytes | bytearray) -> None:
    """Best effort: zero a bytearray in place. Bytes cannot be wiped in Python."""
    if isinstance(key, bytearray):
        key[:] = b"\x00" * len(key)


def _keyfile_digest(keyfile: str | Path) -> bytes:
    """Stream a keyfile through SHA-256; only the digest ever mixes into the key."""
    p = Path(keyfile).expanduser()
    if not p.is_file():
        raise NeedsKeyfile(f"no keyfile at {p}")
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as e:
        raise BundleError(f"cannot read keyfile {p}: {e.strerror or e}") from e
    return h.digest()


def create_bundle(src_dir: str | Path, out: str | Path, password: str | None,
                  t: int | None = None, m: int | None = None, p: int | None = None,
                  preset: str = DEFAULT_KDF_PRESET, keyfile: str | Path | None = None) -> dict:
    src = Path(src_dir)
    dst = Path(out)
    if not src.is_dir():
        raise BundleError("src must be a directory")
    kf = Path(keyfile).expanduser() if keyfile else None
    tar_bytes = _build_tar(src)
    if password:
        problems = password_problems(password)
        if problems:
            raise WeakPassword("password rejected: " + "; ".join(problems))
        t, m, p = _kdf_params(preset, t, m, p)
        salt = generate_salt()
        kdf_id = VERSION_KDF_ARGON_KEYFILE if kf is not None else VERSION_KDF_ARGON
        nonce = os.urandom(NONCE_LEN)
        header = struct.pack(HEADER_FMT, MAGIC, kdf_id, t, m, p, len(salt)) + salt + nonce
        key = bytearray(derive_key(password, salt, t, m, p))
        if kf is not None:
            mixed = bytearray(mix_keyfile_digest(bytes(key), _keyfile_digest(kf)))
            _wipe(key)
            key = mixed
        try:
            ct = AESGCM(bytes(key)).encrypt(nonce, tar_bytes, header)
        finally:
            _wipe(key)
        label = f"argon2id {m // 1024} MiB x {t} passes"
        if kf is not None:
            label += " + keyfile"
    else:
        if kf is not None:
            raise BundleError("a keyfile is a second factor; it needs a password too")
        t = m = p = 0
        header = struct.pack(HEADER_FMT, MAGIC, VERSION_KDF_PLAIN, 0, 0, 0, 0)
        ct = tar_bytes
        label = "plain (not encrypted)"
    with open(dst, "wb") as f:
        f.write(header + struct.pack(">Q", len(ct)) + ct)
    os.chmod(dst, 0o600)
    params = None if t == 0 else {"t": t, "m": m, "p": p}
    return {"bundle": str(dst), "keyfile": str(kf) if kf else None, "bytes_in": len(tar_bytes),
            "bytes_out": dst.stat().st_size, "kdf": label, "params": params}


def read_bundle(bundle: str | Path, password: str | None = None,
                keyfile: str | Path | None = None) -> bytes:
    """Decrypt and return the raw tar.gz bytes. Raises BundleError on any failure."""
    data = Path(bundle).read_bytes()
    kdf_id, t, m, p, salt, nonce, ct, header = _parse_header(data)
    if kdf_id == VERSION_KDF_PLAIN:
        return ct
    try:
        key = _unlock(kdf_id, t, m, p, salt, password, bundle, keyfile)
    except (MemoryError, HashingError) as e:
        raise BundleError(
            f"key derivation failed: this bundle wants {m // 1024} MiB of RAM free"
        ) from e
    key = bytearray(key)
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, header)
    except Exception as e:
        raise WrongPassword("decryption failed: wrong password/keyfile or tampered bundle") from e
    finally:
        _wipe(key)


_KIND = {
    VERSION_KDF_ARGON: "argon2id",
    VERSION_KDF_ARGON_KEYFILE: "argon2id+keyfile",
    VERSION_KDF_NONE: "keyfile",
    VERSION_KDF_PLAIN: "plain",
}


def bundle_info(bundle: str | Path) -> dict:
    """Header facts: kind, payload size, and for password bundles t/m/p."""
    data = Path(bundle).read_bytes()
    kdf_id, t, m, p, _salt, _nonce, ct, _header = _parse_header(data)
    info = {"kind": _KIND[kdf_id], "path": str(bundle), "bytes": len(data),
            "payload_bytes": len(ct)}
    if kdf_id in (VERSION_KDF_ARGON, VERSION_KDF_ARGON_KEYFILE):
        info.update(t=t, m=m, p=p)
    return info


def bundle_kind(bundle: str | Path) -> str:
    """One of 'argon2id', 'argon2id+keyfile', 'keyfile', 'plain'. Raises BundleError on garbage."""
    return bundle_info(bundle)["kind"]


def list_bundle(bundle: str | Path, password: str | None = None,
                keyfile: str | Path | None = None) -> list[tuple[str, int]]:
    """List (name, size) of files inside, without extracting anything."""
    buf = io.BytesIO(read_bundle(bundle, password, keyfile))
    out: list[tuple[str, int]] = []
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            members = tf.getmembers()
    except (tarfile.TarError, EOFError, OSError) as e:
        raise BundleError("bundle contents are damaged") from e
    for m in members:
        if m.isfile():
            out.append((m.name, m.size))
    return out


def extract_bundle(bundle: str | Path, dest: str | Path, password: str | None = None,
                   keyfile: str | Path | None = None) -> list[str]:
    return _safe_extract(read_bundle(bundle, password, keyfile), Path(dest))
