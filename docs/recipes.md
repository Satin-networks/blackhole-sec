# Everyday recipes

Copy-paste flows for the stuff I actually do week to week.

## Someone DMs you a "free nitro" link

```bash
blackhole check "http://discord-nitro-free.tk/claim?user=you"
# SUSPICIOUS or MALICIOUS -> don't log in, block and report
```

If they also sent a file, triage both at once:

```bash
blackhole intake "http://discord-nitro-free.tk/claim" ./qr-code.png
```

## Posting photos in a public server

```bash
blackhole shred analyze trip.jpg
blackhole shred clean trip.jpg
blackhole shred verify trip.cleaned.jpg && echo OK
# post trip.cleaned.jpg, keep or shred the original
```

## Storing a new account

```bash
blackhole vault set github --username alice --generate 24
blackhole vault audit   # run monthly, fix reused and short ones first
```

## Sending a folder to a friend

```bash
blackhole bundle create ./project ./project.bhb
# send project.bhb over any channel, share the password over a
# different one (call them, don't put both in the same chat)
```

## Cleaning a whole folder before upload

```bash
for f in *.jpg; do blackhole shred clean "$f" --yes; done
blackhole shred verify *.cleaned.jpg
blackhole bundle create . ./upload.bhb --no-password
# upload upload.bhb - plain mode, so only for stuff that's fine public
```

## Checking a list from a mod queue

```bash
blackhole check -f reported-links.txt --csv > verdicts.csv
# sort by score, review the top of the list first
```
