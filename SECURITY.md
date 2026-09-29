# Security notes

How I think about this, plainly: what it covers and what it doesn't.

## Covered

- `check` never fetches URLs. Input capped at 2048 chars, output defanged.
  Safe to paste that "free nitro" link.
- Stolen vault file: Argon2id (t=3, m=64MiB, p=4) + AES-256-GCM. The master
  is never stored. Files are 0600. Unlock is pass/fail against a verifier.
- Posting photos: `clean` writes a new file, the original stays put.
  `verify` exits non-zero while sensitive tags remain.
- `.bhb` archives encrypt names and contents as one blob. Extraction skips
  absolute paths, `..`, symlinks and device nodes.

## Not covered

- An unlocked machine. Plaintext lives in memory while the vault is open.
  I lock after every command and clear the clipboard best-effort, but no
  local vault survives someone reading live RAM.
- Weak passwords. Argon2id slows guessing, it doesn't rescue `123456`.
  Use `vault gen`.
- Malware. `clean` strips metadata, it doesn't sandbox anything.
- Print-shop redaction. Image EXIF is fully stripped; PDFs are copied with
  a report of what's left. For legal-grade work use a dedicated tool.
- Audits. Standard pieces, small readable code, but no third-party audit yet.

## Reporting

Write privately with version, OS and steps. Keep vault files and bundles
to yourself.
