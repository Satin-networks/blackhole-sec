from pathlib import Path

import pytest

from blackhole_sec.vault.generator import generate_passphrase, generate_password
from blackhole_sec.vault.store import Vault, VaultLocked


def test_create_set_get_audit(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "correct-horse-battery-staple-1!", preset="light")
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
    Vault.create(p, "right-password-12345", preset="light")
    v = Vault(p)
    with pytest.raises(VaultLocked):
        v.unlock("wrong-password-12345")


def test_reuse_detected(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "another-good-master-1!", preset="light")
    v.set("a", "u", "samepassword12345")
    v.set("b", "u", "samepassword12345")
    a = v.audit()
    assert a["reused"]


def test_vault_defaults_are_heavier(tmp_path: Path):
    import json

    from blackhole_sec.vault.crypto import DEFAULT_PRESET, KDF_PRESETS

    assert DEFAULT_PRESET == "hard"
    hard = KDF_PRESETS["hard"]
    # at least 16x the old 64 MiB x 3 per guess
    assert hard["m"] * hard["t"] >= 16 * (64 * 1024 * 3)
    p = tmp_path / "v.db"
    Vault.create(p, "defaults-check-master-1!")
    params = json.loads(p.read_text())["kdf_params"]
    assert params == hard


def test_change_master_upgrades_kdf(tmp_path: Path):
    import json

    p = tmp_path / "v.db"
    v = Vault.create(p, "old-master-password-1", preset="light")
    v.change_master("new-master-password-1")
    params = json.loads(p.read_text())["kdf_params"]
    from blackhole_sec.vault.crypto import KDF_PRESETS

    assert params == KDF_PRESETS["hard"]
    v2 = Vault(p)
    with pytest.raises(VaultLocked):
        v2.unlock("old-master-password-1")
    v2.unlock("new-master-password-1")
    assert v2.get("github") is None  # empty vault, but it opens


def test_generators():
    assert len(generate_password(20)) == 20
    assert len(generate_passphrase(5).split("-")) == 5
    with pytest.raises(ValueError):
        generate_password(4)


def test_passphrase_wordlist_is_the_full_eff_list():
    from blackhole_sec.vault.generator import eff_words

    words = eff_words()
    # the full 7776 minus the few hyphenated entries the loader drops
    assert 7700 < len(words) <= 7776
    assert len(set(words)) == len(words)
    assert all(w.isascii() and w.islower() for w in words)
