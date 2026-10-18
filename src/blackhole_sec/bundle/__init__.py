"""Secure directory archives (.bhb).

Two ways to pack a directory:

- With a password: tar.gz encrypted whole with Argon2id -> AES-256-GCM.
  Names, contents, everything hidden. Only blackhole opens it.
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
  kdf_id 1 (password) and 0 (legacy keyfile) carry a 12-byte nonce and
  ct is AES-GCM with the header as AAD. kdf_id 2 (plain) has no nonce
  and ct is the tar.gz as-is.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import struct
import tarfile
import tempfile
from pathlib import Path

from argon2.exceptions import HashingError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vault.crypto import b64d, derive_key, generate_salt

MAGIC = b"BHB1"
VERSION_KDF_ARGON = 1
VERSION_KDF_NONE = 0  # legacy keyfile mode: still readable, no longer written
VERSION_KDF_PLAIN = 2
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

MIN_PASSWORD_LEN = 12


class BundleError(ValueError):
    """Anything wrong with a .bhb file: shape, parameters, or contents."""


class NeedsPassword(BundleError):
    """The bundle is password-protected and no password was given."""


class WrongPassword(BundleError):
    """Authentication failed: wrong secret, or the file was tampered with."""


class WeakPassword(BundleError):
    """The password would not survive a serious offline guess."""


# exact matches only; the pattern rules below catch most of the rest
COMMON_PASSWORDS = frozenset({
    "123456", "123456789", "12345678", "1234567", "1234567890", "12345",
    "111111", "000000", "666666", "654321", "123123", "121212", "112233",
    "123321", "qwerty", "qwerty123", "qwertyuiop", "azerty", "asdfghjkl",
    "zxcvbnm", "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "letmein", "welcome", "welcome1", "iloveyou", "iloveu", "monkey",
    "monkey1", "dragon", "master", "shadow", "sunshine", "princess",
    "football", "baseball", "soccer", "hockey", "pokemon", "minecraft",
    "batman", "superman", "starwars", "trustno1", "whatever", "hello123",
    "admin", "admin123", "root", "toor", "guest", "secret", "changeme",
    "computer", "internet", "michael", "jennifer", "jordan23", "hunter2",
    "killer", "buster", "harley", "ranger", "tigger", "charlie", "daniel",
    "thomas", "robert", "andrew", "joshua", "pepper", "cookie", "maggie",
    "summer", "winter", "spring", "autumn", "october", "november", "december",
    "january", "february", "march1", "april", "august", "september",
    "kali", "kalilinux", "debian", "ubuntu", "linux123", "windows",
    "blackhole", "opsec", "opencode", "hacker", "h4cker", "gamer", "gamer1",
    "minecraft1", "fortnite", "roblox", "cod123", "sniper", "matrix",
    "terminal", "scriptkiddie", "freedom", "america", "canada", "london",
    "paris1", "berlin", "tokyo1", "naruto", "goku", "sasuke", "vegeta",
    "onepiece", "deathnote", "satan", "god", "jesus", "jesus1", "love123",
    "baby123", "angel", "angel1", "devil666", "soccer1", "basketball",
})

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "0123456789")


def _repetitive(low: str) -> bool:
    """True for passwords built from runs, counts, or keyboard walks."""
    if len(low) < 4:
        return False
    if re.fullmatch(r"(.+)\1+", low):  # "abcabc", "x1x1x1"
        return True
    if re.search(r"(.)\1{3,}", low):  # "aaaa", "!!!!"
        return True
    if re.search(r"(.{1,3})\1{2,}", low):  # "ababab", "123123123"
        return True
    runs = ["abcdefghijklmnopqrstuvwxyz", "0123456789", *_KEYBOARD_ROWS]
    for seq in runs:
        for i in range(len(seq) - 3):
            chunk = seq[i:i + 4]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def password_problems(password: str) -> list[str]:
    """Reasons PW is too weak to protect an archive. Empty means accepted."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"shorter than {MIN_PASSWORD_LEN} characters")
    classes = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ))
    if len(password) < 16 and classes < 3:
        problems.append(
            "under 16 characters and not mixing three of: lower, upper, digits, symbols"
        )
    low = password.lower()
    if low in COMMON_PASSWORDS:
        problems.append("it is one of the most guessed passwords")
    if _repetitive(low):
        problems.append("it repeats simple runs (like aaaa, abcd, qwerty)")
    return problems


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
    if kdf_id not in (VERSION_KDF_ARGON, VERSION_KDF_NONE, VERSION_KDF_PLAIN):
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
    if kdf_id in (VERSION_KDF_ARGON, VERSION_KDF_NONE):
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


def create_bundle(src_dir: str | Path, out: str | Path, password: str | None,
                  t: int | None = None, m: int | None = None, p: int | None = None,
                  preset: str = DEFAULT_KDF_PRESET) -> dict:
    src = Path(src_dir)
    dst = Path(out)
    if not src.is_dir():
        raise BundleError("src must be a directory")
    tar_bytes = _build_tar(src)
    if password:
        problems = password_problems(password)
        if problems:
            raise WeakPassword("password rejected: " + "; ".join(problems))
        t, m, p = _kdf_params(preset, t, m, p)
        salt = generate_salt()
        kdf_id = VERSION_KDF_ARGON
        nonce = os.urandom(NONCE_LEN)
        header = struct.pack(HEADER_FMT, MAGIC, kdf_id, t, m, p, len(salt)) + salt + nonce
        key = bytearray(derive_key(password, salt, t, m, p))
        try:
            ct = AESGCM(bytes(key)).encrypt(nonce, tar_bytes, header)
        finally:
            _wipe(key)
        label = f"argon2id {m // 1024} MiB x {t} passes"
    else:
        t = m = p = 0
        header = struct.pack(HEADER_FMT, MAGIC, VERSION_KDF_PLAIN, 0, 0, 0, 0)
        ct = tar_bytes
        label = "plain (not encrypted)"
    with open(dst, "wb") as f:
        f.write(header + struct.pack(">Q", len(ct)) + ct)
    os.chmod(dst, 0o600)
    params = None if t == 0 else {"t": t, "m": m, "p": p}
    return {"bundle": str(dst), "keyfile": None, "bytes_in": len(tar_bytes),
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
    VERSION_KDF_NONE: "keyfile",
    VERSION_KDF_PLAIN: "plain",
}


def bundle_info(bundle: str | Path) -> dict:
    """Header facts: kind, payload size, and for password bundles t/m/p."""
    data = Path(bundle).read_bytes()
    kdf_id, t, m, p, _salt, _nonce, ct, _header = _parse_header(data)
    info = {"kind": _KIND[kdf_id], "path": str(bundle), "bytes": len(data),
            "payload_bytes": len(ct)}
    if kdf_id == VERSION_KDF_ARGON:
        info.update(t=t, m=m, p=p)
    return info


def bundle_kind(bundle: str | Path) -> str:
    """One of 'argon2id', 'keyfile', 'plain'. Raises BundleError on garbage."""
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
