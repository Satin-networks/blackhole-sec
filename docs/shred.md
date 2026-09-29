# Shredding files

Photos quietly carry GPS, camera model, and timestamps. Handy for your own
archive, bad for a public Discord post. Shred lets you look, strip, and,
when you mean it, delete.

## The flow I use

```bash
blackhole shred analyze photo.jpg
# 40/100 photo.jpg tags=['GPSInfo', 'Model', 'DateTimeOriginal']

blackhole shred clean photo.jpg
# cleaned -> photo.cleaned.jpg, verify=PASS

blackhole shred verify photo.cleaned.jpg; echo $?
# PASS ... sensitive=[]

blackhole shred shred secret.txt --passes 3 --yes
```

Rules I stuck to:

- `clean` never edits in place. It writes `*.cleaned.*` next to the
  original so you can't nuke the only copy by typo.
- `verify` is script-friendly: exit 0 clean, 1 dirty.
- `shred` overwrites (1, 3 or 7 passes), renames a few times to hide the
  name, then unlinks. SSDs can't promise much here - encryption plus shred
  is the honest combo - but spinning disks are properly gone.

## Formats

JPEG, PNG, WebP, TIFF EXIF is fully stripped via Pillow. DOCX core props
and PDF author fields are reported; PDFs are copied with a note of what's
left rather than a false promise. Use a dedicated redaction tool for
legal-grade PDFs.

## Watch out

`clean` strips metadata, not malware. Don't open files you don't trust
just because they're clean.
