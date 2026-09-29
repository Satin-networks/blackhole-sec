from pathlib import Path

import pytest

from blackhole_sec.vault.generator import generate_passphrase, generate_password
from blackhole_sec.vault.store import Vault, VaultLocked


def test_create_set_get_audit(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "correct-horse-battery-staple-1!")
    v.set("github", "alice", "supersecretpassword123", "notes")
    e = v.get("github")
    assert e and e.password == "supersecretpassword123"
    a = v.audit()
    assert a["total"] == 1
    assert p.stat().st_mode & 0o777 == 0o600
    v.lock()
    assert v.is_locked


def test_wrong_master_rejected(tmp_path: Path):
    p = tmp_path / "v.db"
    Vault.create(p, "right-password-12345")
    v = Vault(p)
    with pytest.raises(VaultLocked):
        v.unlock("wrong-password-12345")


def test_reuse_detected(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "another-good-master-1!")
    v.set("a", "u", "samepassword12345")
    v.set("b", "u", "samepassword12345")
    a = v.audit()
    assert a["reused"]


def test_generators():
    assert len(generate_password(20)) == 20
    assert len(generate_passphrase(5).split("-")) == 5
    with pytest.raises(ValueError):
        generate_password(4)
