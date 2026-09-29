# Command reference

Every command documents itself. Whatever is here, `blackhole COMMAND -h`
says it better, since it is generated from the same code.

## Conventions

- `-h` works everywhere as a short `--help`.
- `--no-color` on any command (or the NO_COLOR env var) disables colors.
  `--json` and `--csv` are always plain.
- Secrets are typed into hidden prompts, never passed as flags (so they
  stay out of shell history).
- Commands that inspect only (`check`, `shred analyze`, `shred verify`,
  `vault list`, `vault audit`) never change anything.
- Filesystem failures print one line naming the file, never a traceback.

## blackhole check [URL]...

Score links without fetching them. Defanged output, JSON/CSV modes,
exit code 2 when anything hits `--threshold` (default 50).

```bash
blackhole check "http://secure-paypal-login.tk/free-nitro"
blackhole check -f urls.txt --json > report.json
blackhole check suspect.tk/x --explain
```

## blackhole vault ...

`init` creates the vault, `set`/`get` store and fetch by SERVICE name,
`list` shows names, `audit` scores password health, `gen` prints a fresh
secret without storing it.

```bash
blackhole vault init --vault ~/.blackhole/vault.db
blackhole vault set github --username alice --generate 24
blackhole vault get github --show
blackhole vault rm old-forum --yes
blackhole vault passwd
```

`--vault PATH` on any subcommand points at a different vault file.

## blackhole shred ...

`analyze` scores metadata, `clean` writes `*.cleaned` copies, `verify`
exits 0/1 for scripts, `shred` deletes for real.

```bash
blackhole shred analyze photo.jpg
blackhole shred clean *.jpg --out-dir ./clean --yes
blackhole shred verify photo.cleaned.jpg; echo $?
blackhole shred shred secret.txt --passes 7 --yes
```

## blackhole bundle ...

`create` packs SRC_DIR into OUT_FILE (`.bhb`), `extract` unpacks it,
`list` shows contents without extracting, `verify` checks the
password/key with exit 0/1. Password mode prompts; `--no-password`
writes an OUT_FILE.key instead.

```bash
blackhole bundle create ./photos ./photos.bhb
blackhole bundle extract ./photos.bhb ./restored --password
blackhole bundle list ./photos.bhb --password
blackhole bundle verify ./photos.bhb --password; echo $?
```

## blackhole intake URL FILE [--json]

One-shot triage for a DM with a link and an attachment: prints the link
verdict plus the file metadata verdict. `--json` merges both into one
machine-readable object.

## blackhole upgrade [--check]

Fetches the latest release from PyPI and installs it with pip. The one
command here that needs network. `--check` only compares versions.

```bash
blackhole upgrade --check
blackhole upgrade
```
