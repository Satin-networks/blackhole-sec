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

- Master + random 16-byte salt go through Argon2id (t=3, m=64MiB, p=4)
  into a 32-byte key.
- Everything is one JSON blob encrypted with AES-256-GCM. The header
  (magic, params, salt, nonce) is authenticated as AAD.
- Unlock tries to decrypt a known verifier. Wrong password just fails.
- The master is never written anywhere. Each command locks when it ends.

## Moving machines

Copy the `.db` file. That's it. Back it up like you'd back up anything
precious - the backup is still encrypted, safe to keep on a USB stick.
