# Vault

One encrypted file. One master password. No sync, no cloud, no recovery -
which is exactly why there's nothing to breach.

## Setup

```bash
blackhole vault init --vault ~/.blackhole/vault.db
```

The file is created chmod 0600. Pick a long master and write it down
somewhere safe. If you lose it, the vault is gone.

## Daily use

```bash
# save something (prompts for the rest)
blackhole vault set github --username alice --generate 24

# passphrases are nicer to type
blackhole vault set wifi --passphrase 5

# read it back
blackhole vault get github --show

# delete one you don't need (asks first unless --yes)
blackhole vault rm old-forum

# change the master (re-encrypts everything)
blackhole vault passwd

# copy without printing (best-effort clipboard, clears after ~30s)
blackhole vault get github

# what's in there
blackhole vault list

# fresh password without storing anything
blackhole vault gen --length 24
```

## Storing files

```bash
# keep a copy of a file in the vault (64 MiB cap)
blackhole vault add-file ~/tax-2025.pdf

# give it a shorter name if you like
blackhole vault add-file ~/keys/api.pem --name stripe-key

# write it back out (checksum checked, chmod 0600)
blackhole vault export stripe-key --out ~/keys/

# overwrite a copy you already exported
blackhole vault export tax-2025.pdf --force
```

`vault list` shows stored files with their size and original name,
`vault rm` deletes the copy inside the vault (the file you added stays
untouched), and `vault passwd` re-wraps everything under the new master.

## Health check

```bash
blackhole vault audit
```

```
Score: 85/100  entries=12
reused passwords: {'hunter2...': ['old-forum', 'test-box']}
weak (<12 chars): ['router']
stale (>1y): ['bank-backup-code']
```

Change the reused and short ones first. That's the whole game.

## How it works

- Master + random 16-byte salt go through Argon2id (512 MiB, 8 passes
  by default; older vaults keep their own numbers until `vault passwd`)
  into a 32-byte key.
- Everything is one JSON blob encrypted with AES-256-GCM. The header
  (magic, params, salt, nonce) is authenticated as AAD.
- Unlock tries to decrypt a known verifier. Wrong password just fails.
- The master is never written anywhere. Each command locks when it ends.
- Stored files live in a `<vault>.files` directory beside the vault,
  each encrypted under its own HKDF subkey of the vault key. The vault
  file itself stays small, so ordinary lookups stay quick.
- Generated passphrases draw from the EFF large wordlist (7776 words:
  five words is ~64 bits). Generated passwords default to 20 chars
  mixing letters, digits and symbols (~120 bits).

## Moving machines

Copy the `.db` file - and the matching `.files` directory if you stored
any files in it. That's it. Back both up like you'd back up anything
precious - the backup is still encrypted, safe to keep on a USB stick.
