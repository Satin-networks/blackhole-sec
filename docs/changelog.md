# Changelog

## 0.2.2

- `--no-password` now packs plain and unencrypted: no keyfile, opens
  with no flags. Password mode is unchanged and still fully encrypted.
- Old keyfile bundles from 0.2.x still open.
- Damaged bundles report cleanly instead of tracebacking.

## 0.2.1

- Permission errors on root-owned files now say so and suggest sudo.
- `bundle create` prints that the source was left untouched.
- Installer scripts go system-wide under sudo (`/usr/local`).

## 0.2.0

- Color throughout: severity-colored signals, score bars, graded audit
  scores. `--json`/`--csv` stay plain. `--no-color` (or NO_COLOR, or a
  pipe) turns it off.
- New: `vault rm`, `vault passwd`, `bundle list`, `bundle verify`,
  `intake --json`.
- Fixed: bundles keep empty directories; huge directories spill to disk
  instead of RAM; corrupt bundles say so instead of tracebacking;
  malformed URLs can't crash `check`; clipboard copies use persistent
  tools first and no longer promise an auto-clear that never happened.
- Leaner install: dropped two unused dependencies.

## 0.1.1

- Every command documents its arguments with examples (`COMMAND -h`,
  plus `-h` short flag everywhere).
- New `blackhole upgrade` (and `--check`) for self-updates from PyPI.
- Curl installer trio: `scripts/install.sh`, `update.sh`, `uninstall.sh`.
- CLI version now reads installed package metadata, no more drift.
- Filesystem failures (permission denied, missing vault, bad password)
  print one-line errors instead of tracebacks.

## 0.1.0 - first public cut

- `check`: offline link scoring, 25+ signals, JSON/CSV/batch, exit codes.
- `vault`: Argon2id plus AES-256-GCM store, generator, audit.
- `shred`: analyze, clean, verify, shred with 1/3/7 passes.
- `bundle`: `.bhb` encrypted archives, password and keyfile modes.
- `intake`: link plus file triage in one command.
- Docs site (this), CI, pip packaging as `blackhole-sec`.
