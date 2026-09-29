# Checking links

`blackhole check` reads the URL as text and scores it. It never opens
the page, never does DNS, never calls an API. Safe to run on the nastiest
"free nitro" lure.

## Quick start

```bash
blackhole check "http://secure.paypal.com.evil.tk/login"
```

```
MALICIOUS 68/100 (HIGH) hxxp[:]//secure[.]paypal[.]com[.]evil[.]tk/login
  +18 brand_impersonation: brand=paypal host=secure.paypal.com.evil.tk
  +10 suspicious_tld: .tk
  + 8 suspicious_keywords: login,secure
```

Notice the output is defanged (`hxxp[://]`, `[.]`) so it can't be
clicked by accident.

## Scores

| Range | Verdict | What I do |
|-------|---------|-----------|
| 0-20 | BENIGN | Carry on |
| 21-49 | SUSPICIOUS | Hover, verify sender, don't log in |
| 50-100 | MALICIOUS | Don't touch it |

Confidence (VERY_LOW → HIGH) is based on how many signals fired.
Every signal prints its weight, the evidence, and a MITRE tag like
`T1566.002` so you can look it up.

## Batch and scripts

```bash
# a list of links
blackhole check -f urls.txt --json > report.json

# from a pipe
echo "http://paypal-secure.tk/login" | blackhole check --file -

# CSV for a spreadsheet
blackhole check -f urls.txt --csv > report.csv

# fail the build on anything scary
blackhole check "http://evil.tk/x" --threshold 50; echo $?
# exit 2 means something scored at or above the threshold
```

## What it looks at

Short version: IP hosts, punycode and homoglyphs, shorteners, odd TLDs,
long URLs, deep paths, tons of subdomains or hyphens, `@` tricks, missing
https, weird ports, heavy percent-encoding, high entropy, lure words
(`login`, `nitro`, `wallet`…), `.exe`-style paths, open-redirect params,
brand names in the wrong domain, near-miss typos (`paypa1`), free-hosting
domains, digit-heavy names, and embedded credentials.

Long version lives in `src/blackhole_sec/check/features.py` - it's one
readable file, tweak the lists to taste.

## Limits

Lexical only. It can't catch a hacked WordPress page on a legit domain,
and brand-new lure words need adding by hand. That's the trade for never
touching the network.
