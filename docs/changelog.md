# Changelog

## 0.4.0

- `bundle create --keyfile PATH` adds a second factor: the bundle key
  becomes Argon2id(password) mixed with the keyfile's hash, so opening
  needs both and a leaked bundle cannot even be tested offline. A
  missing keyfile path is minted on the spot (32 random bytes, 0600).
- The docs have a head-to-head with age and 7-Zip now.
- The vault stores files now: `vault add-file PATH` (64 MiB cap) keeps
  a copy inside, `vault export LABEL [--out DEST]` writes it back with
  a checksum check. The bytes sit encrypted in a `<vault>.files`
  directory beside the vault, so ordinary password lookups stay quick.
- Vault prompts are friendlier: type a master of your own, press Enter
  at any password prompt to get one generated, and a weak master warns
  instead of refusing. `vault init --kdf light|hard|paranoid` picks the
  work factor for the machine it will live on.
- `vault list` shows each entry's kind and a real date. `vault get` on
  a stored file points you at `vault export`.
- `blackhole upgrade` no longer dies on externally managed pythons
  (PEP 668) - it falls back to a user-site install - and it refuses to
  walk you backwards when the install is ahead of PyPI.
- The readme and docs carry a logo now.

## 0.3.0

- `.bhb` bundles are much harder to crack. Password mode now runs
  Argon2id at 1 GiB and 8 passes by default - ~42x the work of 0.2.x
  per guess - and `bundle create --kdf paranoid` roughly triples that
  again (~128x). Unlock takes a few seconds now; that is the point.
- Old bundles keep opening unchanged: the work factor lives in the
  header as t/m/p, and the reader derives with whatever it finds.
  Absurd header values are rejected before any memory is spent.
- Weak bundle passwords are refused at creation (12+ chars, three
  classes under 16, no top-list classics, no keyboard walks) and
  `bundle create --generate` prints a fresh 24-char password for you.
- `bundle extract`/`list`/`verify` detect encrypted bundles and prompt
  for the password themselves; a wrong password re-prompts up to three
  tries. `--password` still works, it just stopped being required.
- Passphrase generation now draws from the EFF large wordlist (7776
  words, ~64 bits for five) instead of a 26-word rump.
- Derived bundle keys are zeroed after use (best effort in Python).

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
