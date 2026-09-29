# Changelog

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
