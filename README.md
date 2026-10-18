<p align="center">
  <img src="https://raw.githubusercontent.com/satin-networks/blackhole-sec/main/docs/assets/logo.svg" width="140" alt="blackhole-sec">
</p>

# blackhole-sec

A small offline toolkit I actually use: check sketchy links, keep passwords
and files in an encrypted vault, strip photo metadata before posting, and
pack directories into encrypted `.bhb` files instead of zip.

No accounts. No network calls. Nothing leaves your machine.

Full write-ups for each tool live here:
**https://satin-networks.github.io/blackhole-sec/**

```bash
pip install blackhole-sec
```

```bash
blackhole check "http://secure-paypal-login.tk/free-nitro"
blackhole vault init
blackhole shred analyze photo.jpg
blackhole bundle create ./mydir ./backup.bhb
```

## The four tools

### 1. check - is this link a trap?

Paste a Discord / email lure and get a straight answer. Everything runs
locally, the URL is never fetched.

```bash
blackhole check "http://secure.paypal.com.evil.tk/login?redirect=http://evil.com"
# MALICIOUS 68/100 (HIGH) hxxp[:]//secure[.]paypal[.]com[.]evil[.]tk/login...
#   +18 brand_impersonation: brand=paypal host=secure.paypal.com.evil.tk
#   +10 suspicious_tld: .tk
#   ...

blackhole check -f urls.txt --json > report.json
echo "http://paypal-secure.tk/login" | blackhole check --file -
```

Scoring is plain and explainable: each signal adds points, 0-20 is BENIGN,
21-49 SUSPICIOUS, 50+ MALICIOUS. Output is defanged (`hxxp[://]`) so you
can't click it by accident. Batch mode and `--threshold` fit nicely in scripts.

### 2. vault - passwords and files on your own disk

One encrypted file, one master password. Argon2id turns your master into a
key, AES-256-GCM does the rest. I never store the master anywhere.

```bash
blackhole vault init --vault ~/.blackhole/vault.db
blackhole vault set github --username alice --generate 24
blackhole vault get github --show
blackhole vault list
blackhole vault audit
blackhole vault gen --length 24
blackhole vault add-file ~/tax-2025.pdf   # keep a file in the vault
blackhole vault export tax-2025.pdf       # write it back out
blackhole vault rm old-forum --yes
blackhole vault passwd
```

The file is chmod 0600. Every command locks when it finishes. `audit`
calls out reused, short, and stale passwords with a 0-100 score. Stored
files keep their own encryption keys in a `.files` directory next to the
vault; back up both.

Lose the master and the vault is gone - there is no reset, by design.

### 3. shred - clean it before you post it

Photos carry GPS, camera model, and timestamps. `analyze` shows what's in
there, `clean` writes a `*.cleaned` copy with it stripped (your original
stays untouched), `verify` passes or fails for scripts, and `shred`
overwrites and deletes for real.

```bash
blackhole shred analyze photo.jpg
blackhole shred clean photo.jpg
blackhole shred verify photo.cleaned.jpg; echo $?
blackhole shred shred secret.txt --passes 7 --yes
```

### 4. bundle - encrypted archives that aren't zip

With a password, `.bhb` packs a directory to tar.gz and encrypts the
whole blob. Filenames, sizes, everything is hidden. Only blackhole
opens it. With `--no-password` it packs plain: no encryption, opens
with nothing extra, same deal as a zip with no password.

Password mode is heavy on purpose: Argon2id at 1 GiB and 8 passes by
default (~42x the work of the old default), `--kdf paranoid` for
~128x. Weak passwords are refused at creation; `--generate` makes a
strong one and prints it once. Add `--keyfile` for a second factor:
the bundle then needs the password and the file both, and a stolen
copy cannot be tested offline without it.

```bash
blackhole bundle create ./photos ./photos.bhb
blackhole bundle create ./photos ./photos.bhb --generate  # strong password, printed once
blackhole bundle create ./photos ./photos.bhb --keyfile ~/bh-photos.key  # two factors
blackhole bundle create ./photos ./photos.bhb --kdf paranoid
blackhole bundle create ./photos ./photos.bhb --no-password  # plain: anyone can open it
blackhole bundle extract ./photos.bhb ./restored  # prompts on its own
blackhole bundle list ./photos.bhb
blackhole bundle verify ./photos.bhb; echo $?
```

Wrong password or a tampered file just refuses to open; a wrong entry
re-prompts up to three times, then gives up. Extraction rejects
absolute paths, `..`, and symlinks. There is a
[head-to-head with age and 7-Zip](https://satin-networks.github.io/blackhole-sec/comparison/)
if you are picking a tool.

### Triage: a link and a file at once

When a DM has both, `intake` scores the link and checks the file's
metadata in one pass:

```bash
blackhole intake "http://evil.tk/login" ./photo.jpg  # link + file in one go
blackhole intake "http://evil.tk/login" ./photo.jpg --json
```

Colors are on when your terminal supports them and off when piped.
Force it either way with `--no-color` or the NO_COLOR env var.

## Install

Python 3.11 or newer. Pick one:

```bash
# with pip
pip install blackhole-sec

# without touching pip yourself (venv + links handled for you)
curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/install.sh | bash

# system-wide, so `sudo blackhole ...` works too
curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/install.sh | sudo bash
```

From source:

```bash
pip install -e ".[dev]"
```

Depends on click, rich, cryptography, argon2-cffi and Pillow. That's it.

Upgrade later with `blackhole upgrade` (or the scripts/update.sh
one-liner). Remove with the scripts/uninstall.sh one-liner; your vault
file is left alone.

## Layout

```
src/blackhole_sec/
  check/    link scoring, no network
  vault/    encrypted store + generator
  shred/    metadata + secure delete
  bundle/   .bhb create / extract
  cli.py    everything wired together
tests/      offline fixtures, no network
docs/       longer write-ups for each tool
```

## Security notes

Short version is in `SECURITY.md`. The honest version:

- Standard primitives only (Argon2id, AES-GCM, `secrets`). Nothing home-rolled.
- `check` never touches the network. Input capped at 2048 chars.
- Secrets live in 0600 files. Keys are wiped best-effort after use.
- Not audited. Don't bet your life on any single tool, including this one.

Found something? Open a private advisory with version, OS, and steps.
Please don't post vault files or bundles anywhere public.

## License

MIT - see LICENSE. Built by Satin Networks alongside
[wisp](https://github.com/satin-networks/wisp), our local WireGuard manager.
