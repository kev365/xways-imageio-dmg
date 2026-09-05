# Generating the real-world DMG test corpus on a Mac

The synthetic images from `make_test_dmg.py` prove the decoders and the block
map, but only `hdiutil` produces *authentic* UDIF layouts (out-of-order chunk
payloads, comment entries, real partition schemes, the exact LZFSE / LZMA
framing Apple uses). This is the recipe for building that corpus on a Mac in
one sitting. Everything lands in one folder you then copy to Windows.

## Before you start

| Check | Why |
| --- | --- |
| `sw_vers` shows **macOS 10.15 Catalina or newer** (a 2013 MacBook tops out at **Big Sur 11**, which is fine) | ULMO (LZMA) needs 10.15+, ULFO (LZFSE) 10.11+, APFS images 10.13+. Older macOS silently fails those conversions. |
| Roughly **2 GB free** on the destination | The corpus is ~600 MB including the raw `.cdr` oracles, plus ~2.2 GB for the large sparse image (section 4b). |
| A way to move ~3 GB to Windows | USB stick (exFAT or FAT32; the largest file is ~2.2 GB, under FAT32's 4 GB limit), shared folder, or `scp`. |

No Xcode, Homebrew, or admin rights are needed. `hdiutil`, `shasum`, `ditto`
and `awk` ship with macOS.

## Run it

1. Copy `make_test_dmgs_macos.sh` (next to this file) onto the Mac.
2. In Terminal:

   ```bash
   cd /Volumes/<STICK>                # if running from a USB stick
   bash make_test_dmgs_macos.sh         # writes to ~/dmg-samples
   # or: bash make_test_dmgs_macos.sh /Volumes/<STICK>/dmg-samples
   ```

3. It takes 5–15 minutes and is resumable (re-run after a failure and it skips
   what already exists). Watch for lines starting with `!!` — a failed
   conversion means that format is unsupported on that macOS (its `.err` file
   says why). Everything else keeps going.
4. When it prints `Done.`, copy the **whole folder** to the Windows workspace
   test-data store under a `dmg\` subfolder (the store is outside every git
   tree; never commit any of it).

The script never prompts. If a password prompt does appear, something in that
step regressed on that macOS version: press Ctrl+C, and send the terminal
output back rather than typing the password (which is `xways-test`, also in `PASSWORD.txt`).

## What you get

| File(s) | What it exercises |
| --- | --- |
| `src_<seed>.dmg` (UDRW) | The four seed volumes: `hfsgpt` (HFS+ in a GPT scheme), `apfsgpt` (APFS in GPT), `hfsapm` (HFS+ in an Apple Partition Map), `hfsnone` (single volume, no scheme). Each holds a README, a 3 MiB random file, a 2 MiB repetitive text, a 1 MiB zero file, a number sequence, the words list, and `CONTENTS.sha256` listing every file's hash. |
| `raw_<seed>.cdr` | The **expanded raw bytes** of that seed (`hdiutil convert -format UDTO`). This is the oracle: `dmgtest extract` of every conversion of the same seed must hash identically. |
| `<seed>_UDRO.dmg` … `<seed>_ULMO.dmg` | Read-only raw, **ADC** (UDCO), **zlib** (UDZO), **bzip2** (UDBZ), **LZFSE** (ULFO), **LZMA** (ULMO) — 24 images, one per chunk type per partition scheme. |
| `*.imageinfo.txt` | `hdiutil imageinfo` for each: format, partition scheme, checksum type, segment info. Compare against `dmgtest map` output. |
| `enc_aes128_udzo.dmg`, `enc_aes256_udzo.dmg`, `enc_aes256_ulfo.dmg` | **Encrypted UDIF** (`encrcdsa` v2) — phase 1b targets. Plaintext = the seed, so `raw_hfsgpt.cdr` / `raw_apfsgpt.cdr` remain the oracles. |
| `enc_aes256_udrw.dmg` + `raw_enc_aes256_udrw.cdr` | Encrypted **read-write** image: the plaintext is a raw volume with no koly trailer inside — the "passthrough after decryption" path. |
| `seg1m_hfsgpt_UDZO.dmg` + `.dmgpart` files | **Segmented** image (1 MB segments, five parts). `raw_hfsgpt.cdr` is its oracle. |
| `sparse_hfs.sparseimage` + `raw_sparse_hfs.cdr` | **Sparse image** (`sprs` band table). |
| `bundle_hfs.sparsebundle.zip` + `raw_bundle_hfs.cdr` | **Sparse bundle** (a directory of band files, zipped for transport; unzip it on Windows and add its `Info.plist` as the image). |
| `big_sparse_hfs.sparseimage` + `big_sparse_hfs.sha256` | **Large sparse image** (2.4 GB, > 2016 bands) — verifies the chained band-index blocks beyond the 4096-byte header. The oracle is the SHA-256 of the expanded bytes (no raw copy, to save space). |
| `enc_sparse_hfs.sparseimage` + `enc_sparse_hfs.sha256` | **Encrypted sparse image** (AES-256 over band storage). Hash oracle. |
| `enc_bundle_hfs.sparsebundle.zip` + `enc_bundle_hfs.sha256` | **Encrypted sparse bundle**. Hash oracle; unzip on Windows. |
| `enc_seg1m_hfsgpt_UDZO.dmg` + `.dmgpart` files, and/or `seg1m_enc_aes256_udzo.dmg` + `.dmgpart` files | **Encrypted + segmented** (added 2026-09-04). Route (a) = `convert -encryption AES-256 -segmentSize 1m` of the seed; route (b) = `hdiutil segment` of the already-encrypted `enc_aes256_udzo.dmg`. hdiutil may refuse one or both — a `.err` file records why. `raw_hfsgpt.cdr` is the oracle for whichever exists. The script also prints the first 8 bytes of every segment file (`encrcdsa` = encryption wraps each file). |
| `enc_pw_unicode.dmg`, `enc_pw_long.dmg` + `PASSWORDS-EXTRA.txt` | **Passphrase edge cases**: a non-ASCII (UTF-8, incl. CJK and a symbol) passphrase and a 200-character one, over the `hfsnone` seed; `raw_hfsnone.cdr` is the oracle, the passphrases are in the tab-separated `PASSWORDS-EXTRA.txt`. |
| `SHA256SUMS.txt`, `MANIFEST.txt`, `PASSWORD.txt` | Hashes of every artefact, the macOS version, the listing, and the encryption password. |

## Back on Windows: what to run

From the plugin folder (build the harness first with
`harness\build_harness.bat` if `harness\dmgtest.exe` is missing); replace
`<test-data>` with wherever you keep test images outside the repo:

```bat
REM one format
harness\dmgtest.exe map     <test-data>\dmg-samples\hfsgpt_ULFO.dmg
harness\dmgtest.exe verify  <test-data>\dmg-samples\hfsgpt_ULFO.dmg
harness\dmgtest.exe extract <test-data>\dmg-samples\hfsgpt_ULFO.dmg %TEMP%\hfsgpt_ULFO.raw
certutil -hashfile %TEMP%\hfsgpt_ULFO.raw SHA256
certutil -hashfile <test-data>\dmg-samples\raw_hfsgpt.cdr SHA256     REM must match
```

Or all of them at once in PowerShell:

```powershell
$d = '<test-data>\dmg-samples'
Get-ChildItem "$d\*_U*.dmg" | ForEach-Object {
    $seed = $_.BaseName.Split('_')[0]
    $raw  = "$env:TEMP\$($_.BaseName).raw"
    & harness\dmgtest.exe extract $_.FullName $raw | Out-Null
    $got = (Get-FileHash $raw -Algorithm SHA256).Hash
    $exp = (Get-FileHash "$d\raw_$seed.cdr" -Algorithm SHA256).Hash
    '{0,-22} {1}' -f $_.Name, $(if ($got -eq $exp) { 'MATCH' } else { "MISMATCH $got" })
}
```

For the hash-oracle samples (section 4b), compare the extract's hash with the
`.sha256` file instead of a `.cdr`; encrypted ones need `--password xways-test`:

```powershell
foreach ($n in 'big_sparse_hfs.sparseimage','enc_sparse_hfs.sparseimage','enc_bundle_hfs.sparsebundle\Info.plist') {
    $stem = ($n -split '[\\.]')[0]
    & harness\dmgtest.exe extract "$d\$n" "$env:TEMP\$stem.raw" --password xways-test | Out-Null
    $got = (Get-FileHash "$env:TEMP\$stem.raw" -Algorithm SHA256).Hash.ToLower()
    $exp = (Get-Content "$d\$stem.sha256").Trim()
    '{0,-28} {1}' -f $n, $(if ($got -eq $exp) { 'MATCH' } else { "MISMATCH $got" })
}
```

Then the in-X-Ways pass: add `apfsgpt_ULFO.dmg`, `hfsapm_UDBZ.dmg` and
`hfsnone_UDCO.dmg` to a throwaway case, confirm the volumes list their files,
and check a few file hashes against `CONTENTS.sha256` from inside the volume.
Record the results (macOS version, which formats converted, any failures) in
the plugin's gitignored `xways-imageio-dmg-testdata.md` and in
your project's testing notes.

## If a step fails on the Mac

- **`hdiutil: convert failed - Operation not supported`** for ULFO/ULMO —
  the macOS is older than 10.11 / 10.15; update the Mac (Big Sur is the
  ceiling for 2013 hardware).
- **APFS seed fails** — macOS older than 10.13; the HFS+ seeds still cover
  every chunk type.
- **A password prompt appears** — do not type into it; Ctrl+C and report which
  step it was (the script is meant to be fully non-interactive).
- **The attach step hangs** — Finder opened the volume despite `-nobrowse`;
  eject it in Finder and re-run.
