# xways-imageio-dmg — Apple DMG images in X-Ways Forensics

`ImageIO_DMG.dll` is an **Image I/O API plugin** for X-Ways Forensics that
lets you add Apple disk images (`.dmg`, UDIF) to a case like any other image:
**Case Data → File → Add Image**, or drag-and-drop. X-Ways otherwise refuses
compressed DMGs. The plugin turns the compressed container into a flat sector
array; X-Ways then parses the GPT / Apple partition map and the HFS+ / APFS
volumes inside exactly as it would for a raw image.

It is the same mechanism the Evimetry AFF4 reader (`ImageIOAFF4.dll`) uses —
an `Image*.dll` in the `x64\` folder, not an X-Tension.

Status: **0.1.0-beta**, the first public release. Requires X-Ways Forensics
19.5 or later (the release that introduced the Image I/O API); built and
verified against X-Ways Forensics 21.8 on Windows 11 x64.

Versioning: the whole `0.x` series is beta and carries the `-beta` suffix;
`1.0.0` will be the first API-stable release.

## What it reads

| Container / variant (`hdiutil` format) | Chunk type | Supported |
| --- | --- | --- |
| UDRO / UDRW read-only, read-write | raw (`0x00000001`), zero-fill (`0`, `2`) | ✓ |
| UDCO — ADC compressed | `0x80000004` | ✓ |
| UDZO — zlib compressed (the default) | `0x80000005` | ✓ |
| UDBZ — bzip2 compressed | `0x80000006` | ✓ |
| ULFO — LZFSE compressed | `0x80000007` | ✓ |
| ULMO — LZMA compressed (xz streams) | `0x80000008` | ✓ |
| Block map in the XML plist (`blkx`) | | ✓ |
| Block map in a binary resource fork only (pre-10.4 images) | | ✓ (untested) |
| Whole-disk images (GPT / APM) and single-volume images | | ✓ |
| **Encrypted images** (`encrcdsa` v2: AES-128 / AES-256, PBKDF2-SHA1 passphrase) — compressed or read-write | | ✓ password prompt, `Passwords.txt`, env var, session cache |
| **Segmented images** (`name.dmg` + `name.002.dmgpart` …) | | ✓ add the `.dmg`; the parts are found next to it |
| **`.sparseimage`** (band-allocated read-write image) | | ✓ plain or encrypted; multi-block band index (> 1008 bands) verified on a 2.4 GB sample |
| **`.sparsebundle`** (directory of band files) | | ✓ plain or encrypted; add the bundle's `Info.plist` as the image (see below) |
| Encrypted images protected only by a certificate / keybag | | ✗ declined with a message |
| Legacy encrypted images (`cdsaencr` v1, pre-10.5) | | ✗ declined with a message |
| Encrypted *and* segmented in one image (each part its own `encrcdsa` container) | | ✓ one password, every part unlocked |
| NDIF / Disk Copy images | | ✗ |

## Sparse images, sparse bundles, segmented images

- **`.sparseimage`** files are read through their band index: allocated bands
  come from the file, unallocated bands read as zeros. Large images chain
  several 4096-byte index blocks (one per 1008, then 1010 bands); the layout
  was verified against a 2.4 GB three-block sample. An encrypted sparse image
  is an `encrcdsa` container *around* the sparse container and is unlocked
  first.
- **`.sparsebundle`** is a *directory*, and X-Ways' Add Image wants a file, so
  add the bundle's **`Info.plist`** (any file inside the bundle works, but
  `Info.plist` is the stable one). The plugin recognises the enclosing
  `.sparsebundle` folder and reads `bands\<hex>`; missing or short band files
  read as zeros. X-Ways names the evidence object after the file you picked
  (`Info`), so rename the evidence object in the case if that matters. In an
  **encrypted bundle** the `encrcdsa` header sits in the bundle's `token` file,
  every band file is encrypted on its own (the IV counter restarts per band),
  and unallocated bands are plaintext zeros — all handled.
- **Segmented images**: add the first segment, the `.dmg`. The plugin locates
  `name.002.dmgpart` … next to it, checks that every segment carries the same
  SegmentID, and reads the block map from the segment that holds it (segment 1
  on hdiutil output). Adding a `.dmgpart` directly is refused with a message
  pointing at the `.dmg`, so a folder of parts does not turn into duplicate
  evidence objects. An **encrypted segmented image** (what `hdiutil convert
  -encryption … -segmentSize` produces) wraps *each part* in its own
  `encrcdsa` container with its own salt and wrapped key; the plugin unlocks
  every part with the one passphrase and then reads the segments as usual.

For all three, X-Ways is told whether the bytes look like a partitioned disk
(GPT, MBR, Apple partition map) or a single volume (HFS+, APFS) by sniffing the
first sectors, the same way it is for encrypted read-write images.

## Damaged images: what the plugin does and how you find out

The evidence file is opened read-only and is **never written to**. When a
chunk cannot be decoded (a corrupt compressed stream, a container read error),
the plugin does not fail the read — X-Ways treats a short read as a silent
failure and simply carries on with an unrecognised volume, which tells the
examiner nothing. Instead it **presents that chunk's sectors as zeros**, records
the substitution, and tells you three ways:

1. **The X-Ways Messages window** — a `WARNING` line naming the exact sector
   range, the chunk type and the reason, and stating that the file was not
   modified; a `SUMMARY` line with totals when the image is closed. (The plugin
   resolves `XWF_OutputMessage` from the X-Ways executable at load; the Image
   I/O API does not document it for plugins, but it works.)
2. **A report file** next to the DLL, `ImageIO_DMG-reports\<image>.substitutions.txt`,
   one timestamped row per substituted range. Anything X-Ways shows in those
   ranges — and any hash that covers them — reflects zeros, not evidence.
3. The TSV log, as always.

Structural repairs made at open (for example dropping overlapping chunks from
the block map) are named in the evidence object's description as
`VIRTUAL REPAIR: ...`, so they are persisted in the case file.

A `.dmg` that has lost its trailer (truncated download, incomplete copy) is
recognised by its compressed-stream header and refused with a message saying
so, instead of X-Ways' generic "DMG Images not supported" refusal.

## Integrity verification

A UDIF image records CRC32 checksums the plugin can check the decoded bytes
against, so you can prove the sectors X-Ways sees are the bytes `hdiutil`
wrote:

- **per partition** (in each block-map table): CRC32 over that partition's
  decoded sectors;
- **data fork**: CRC32 over the compressed container as stored (a cheap
  container-integrity test, no decoding);
- **master**: CRC32 over the partition checksums.

All three formulas were confirmed byte-for-byte against `hdiutil` output.

Set the environment variable **`IMAGEIO_DMG_VERIFY`** (any value) before
launching X-Ways to verify every DMG at open. The result is announced in the
Messages window (`integrity checksums OK …`, or `INTEGRITY CHECKSUM FAILURE …`
naming the partition) and written to the report file. It reads the whole
image, so it is off by default. The offline harness does the same on demand:
`dmgtest checksums <file.dmg>`.

## Encrypted images

An encrypted DMG (`encrcdsa` header, AES-128 or AES-256) is unlocked inside
`IIO_Init` and then read exactly like a plain one — the decrypted bytes are
either a compressed UDIF image or, for encrypted read-write images, a bare
disk / volume that is presented directly. The password is looked for in this
order, silently first:

1. **`IMAGEIO_DMG_PASSWORD`** environment variable — for unattended
   command-line runs (`xwforensics64.exe NewCase:… AddImage:…`).
2. **Remembered passwords** — every accepted password is kept for the rest of
   the X-Ways session (keyed by the image's UUID and its path), and when the
   dialog's *Remember this password* box is ticked it is also written to
   `ImageIO_DMG-passwords.cfg` next to the DLL, each entry **DPAPI-encrypted
   for the current Windows user** (`CryptProtectData`). Another account, or
   the same file copied to another machine, cannot decrypt those entries.
   Delete the file to forget every remembered password.
3. **`Passwords.txt`** next to the X-Ways executable — the same general
   password collection X-Ways uses for BitLocker (UTF-16 as X-Ways writes it,
   or UTF-8; one password per line). Every line is tried.
4. **A password dialog** parented to the X-Ways main window, up to three
   attempts, with the *Remember this password* checkbox (ticked by default;
   untick it for a one-off unlock that is kept for this session only). Cancel
   refuses the image with a message.

Passwords are never logged. All cryptography is Windows CNG (`bcrypt.dll`)
for the image itself — PBKDF2-HMAC-SHA1 key derivation, 3DES-CBC key unwrap,
AES-CBC blocks with HMAC-SHA1-derived IVs — and DPAPI (`crypt32.dll`) for the
remembered-password file. Unlocking costs the PBKDF2 iteration count the image
was created with (hdiutil uses ~230 000, about 0.4 s).

For an unsupported encrypted image (certificate-only, v1 `cdsaencr`) or a
`.dmgpart` added on its own the plugin reports "give up" with a message, which
X-Ways displays. What happens next is X-Ways' own behaviour (21.8): a
`.dmgpart` is then refused with its native "DMG Images not supported at
present" error; an undecryptable encrypted image (whose koly trailer is hidden inside
the ciphertext) gets the raw "Interpret Image File As Disk" dialog instead —
cancel it, a raw view of ciphertext is useless.

The image is presented with 512-byte sectors and the full `SectorCount` from
the koly trailer. The plugin flags the image as a **disk** when the block map
carries GPT / MBR / Apple partition-map entries, as a **volume** when a single
`Apple_HFS` / `Apple_APFS` entry starts at sector 0, and otherwise leaves the
decision to X-Ways.

## Install

1. Build (below) or take `ImageIO_DMG.dll` from a release.
2. Copy it into **`<X-Ways install>\x64\`** — the folder that already holds
   `ImageIOAFF4.dll` if the AFF4 reader is installed. The install root is
   silently ignored for 64-bit Image I/O plugins, and `xtensions\` is the
   wrong API class.
3. X-Ways loads at most **two** `Image*.dll` plugins. AFF4 + DMG is fine; a
   third one is not.
4. Start X-Ways and add a `.dmg`. The first time the plugin is consulted in a
   session X-Ways shows a *"The script or DLL "ImageIO_DMG.dll" is about to be
   executed"* prompt — click OK (tick "Do not display this message again" to
   stop it re-appearing).

Uninstall: close X-Ways, delete the DLL, `ImageIO_DMG-log.tsv` and (if
present) `ImageIO_DMG-passwords.cfg` from `x64\`.

## Diagnostics

Analyst-facing notices (image opened, integrity result, substitution warnings)
go to the **X-Ways Messages window**, and therefore to `msglog.txt`. The Image
I/O API does not document a way to do this — `XWF_OutputMessage` is specified
for X-Tensions — but the plugin runs inside the X-Ways process and the export
resolves, which was verified on 21.8. If a future X-Ways stops exporting it,
the plugin silently falls back to the files below.

Everything, verbose or not, is appended to `ImageIO_DMG-log.tsv` next to the
DLL: one row per `IIO_Init` decision (claim / decline / give-up with the
reason), the partition list, per-read tracing while `TRACE_WORK` is on (the
first 2000 reads in full, then a summary every 10 000), and a closing row with
cache and thread statistics. Substituted sector ranges also get their own
report file (see *Damaged images* above). Passwords are never logged.

Two constants at the top of `xways-imageio-dmg.cpp` control the volume:
`VERBOSE` (**on** — per-image decisions and close-out statistics, cheap) and
`TRACE_WORK` (**off** — a row per read, useful when investigating read
behaviour, but it makes the log large and adds a file write per read).

A decoder failure never takes X-Ways down: `IIO_Work` runs under a structured
exception guard, and a chunk that cannot be decoded is served as zeros and
reported rather than failing the read.

## Build

From this folder, in any shell (the script bootstraps the VS 2019/2022 x64
toolchain itself):

```bat
build.bat
```

Output: `xways-install-root\x64\ImageIO_DMG.dll`. Set the environment
variable `IMAGEIO_DMG_DEPLOY` (or write a one-line `.deploy.local`) to your
X-Ways install root and the build also mirrors the DLL into its `x64\`
folder. Close X-Ways first — the DLL stays loaded for the whole session.

The decoders are vendored under `vendor/` and compiled into the DLL (no
runtime dependencies, `/MT`): miniz (zlib), libbzip2, Apple's LZFSE decoder,
and xz-embedded. See [NOTICE](NOTICE) for licenses.

## Testing without X-Ways

`harness\build_harness.bat` builds `harness\dmgtest.exe` from the same
sources:

```text
dmgtest map     image.dmg                       koly, partitions, chunk table, type histogram
dmgtest extract image.dmg out.raw [--sector S --count N]
dmgtest verify  image.dmg                       decode every chunk, check lengths
dmgtest checksums image.dmg                     verify the CRC32s the image carries
dmgtest bench   image.dmg [--bufsize N] [--random N]
dmgtest decrypt image.dmg out.bin               dump the decrypted plaintext of an encrypted image
                                                (all commands take --password <p> for encrypted images)
```

Test images are large and carry their own licences, so they are not committed
here; `tools/make_test_dmg.py` and `tools/make_test_dmgs_macos.sh` build a
corpus locally.

Two gates run before every release:

- A **regression pass** over the whole corpus. Each image is checked against
  its expected outcome: UDIF images must pass `checksums` and match a
  byte-for-byte oracle, sparse / bundle / encrypted-raw images must match
  their oracle, trailer-less files must be declined cleanly, and deliberately
  damaged copies must be handled rather than crash. Currently 50 of 50.
- A **mutation fuzzer** that corrupts the koly trailer, the XML plist, the
  data fork, the sparse header, whole-file bytes, truncation points and
  length fields, then runs the harness on every mutant under a timeout. Any
  crash or hang is a failure. Latest run: **12,650 mutants, 0 crashes, 0
  hangs**.

Oracles used so far:

- **7-Zip** extracts the partitions of a DMG (`7z x image.dmg`); the
  concatenation of `0.MBR … 7.Backup GPT Header` is byte-identical to
  `dmgtest extract` for a 128 MiB GPT + APFS UDZO image (SHA-256 match).
- An **independent pure-Python extractor** written against the format notes
  rather than this code (standard-library zlib / bz2 / lzma plus a
  hand-written ADC decoder) produces the same SHA-256 on the same image.
- **`tools/make_test_dmg.py`** synthesizes UDIF files from any raw image with
  a chosen chunk type (`raw`, `zlib`, `bzip2`, `lzma`, `adc`, `lzfse`, or
  `mixed`), optional multi-partition layout and shuffled payload order. Every
  type round-trips to the source image's SHA-256 through both the harness and
  the oracle. These are synthetic: they prove the decoders and the block map,
  not `hdiutil` compatibility. Real `hdiutil` samples of UDCO / UDBZ / ULFO /
  ULMO / APM-scheme / single-volume / encrypted / segmented / sparse images
  come from [tools/make_test_dmgs_macos.md](tools/make_test_dmgs_macos.md)
  (one script, macOS 10.15+), which also produces the raw `.cdr` oracles.
- **Real `hdiutil` corpus** (macOS 12.7.6): four seed volumes (HFS+ in GPT,
  APFS in GPT, HFS+ in an Apple Partition Map, single HFS+ volume) × six
  formats (UDRO, UDCO, UDZO, UDBZ, ULFO, ULMO) = 24 images, every one
  extracted byte-identical to hdiutil's own raw `.cdr` of the same volume;
  plus four **encrypted** images (AES-128 and AES-256 over UDZO, AES-256 over
  ULFO, and an AES-256 read-write image) that decrypt and extract
  byte-identical to their plaintext oracles; plus a five-part segmented
  image, a sparse image, a sparse bundle, a 2.4 GB three-index-block sparse
  image, and an encrypted sparse image and bundle, each matching hdiutil's
  own hash of the expanded bytes.
  Recipe: [tools/make_test_dmgs_macos.md](tools/make_test_dmgs_macos.md).

- **Real-world producers**: a current hdiutil ULFO app image (APFS), Firefox
  (built with Mozilla's libdmg-hfsplus on Linux: Apple Partition Map, LZMA
  chunks, case-sensitive HFSX) and the 1.5 GB LibreOffice images (ULFO,
  ~1650 chunks) all decode fully and mount in X-Ways with their partitions.
  Read-write DMGs with no UDIF trailer (hdiutil UDRW, or a raw volume renamed
  `.dmg`) are not claimed — X-Ways opens those natively as raw images.

Throughput on the 128 MiB UDZO sample: about 185 MiB/s sequential through
the harness, decode-bound. LZFSE reaches ~330 MiB/s; bzip2 (~10 MiB/s) and
LZMA (~27 MiB/s) are the slow decoders.

## Known limitations and what is next

- **Not claimed**: NDIF / Disk Copy images, legacy `cdsaencr` v1 encryption,
  and images protected only by a certificate or keybag. Each is declined with
  a message rather than opened wrongly.
- **Untested in the wild**: the binary resource-fork block map (pre-10.4
  images). The code path exists and is exercised by synthetic samples only.
- **Segmented images** skip the data-fork checksum: the koly records a length
  spanning every segment while the plugin's container view is the first
  segment file. The per-partition and master checksums still run.
- X-Ways names a sparse bundle's evidence object after the file you added
  (`Info`), and the API offers no way to override that.
- Planned: a wider real-world corpus (other producers, other eras, other file
  systems inside the image), and the X-Ways read behaviours not yet observed
  (multi-threaded reads under a hashing refinement, `IIO_CHECK_FOR_SPARSE`).

Real-world images for testing are readily available: application DMGs from
the Homebrew cask catalogue, Firefox (built with libdmg-hfsplus rather than
`hdiutil`), Apple's legacy support downloads for pre-10.5 era images, and the
macOS installer packages for multi-volume APFS containers.

## How it works

```text
IIO_Init  ->  inside a .sparsebundle?  ->  SparseBundleSource over bands\<hex>
          ->  encrcdsa header?  ->  password (env / store / Passwords.txt / dialog)
                                ->  EncryptedSource: AES-CBC per 512-byte block, HMAC-SHA1 IVs
          ->  "sprs" header?    ->  SparseImageSource over the band index
          ->  read the 512-byte koly trailer  ->  segmented? gather name.NNN.dmgpart
          ->  XML plist (or resource fork)    ->  every blkx "mish" chunk table
          ->  one sorted, gap-filled chunk map
          ->  (no koly after decryption: present the plaintext disk directly)
IIO_Work  ->  binary-search the chunk(s) covering [ofs, ofs+len)
          ->  whole-chunk reads decode straight into X-Ways' buffer
          ->  partial reads go through a 128 MB LRU cache of decoded chunks
          ->  zero-fill ranges answer IIO_CHECK_FOR_SPARSE without touching the buffer
IIO_Done  ->  release the file, the cache and the description string
```

Source layout: `dmg_koly` (trailer), `dmg_plist` / `dmg_rsrc` (block-map
containers), `dmg_mish` (chunk tables), `dmg_blockmap` (flattening),
`dmg_decoder` (per-type decode), `udif_source` (random access + cache),
`encrypted_source` (encrcdsa header, CNG crypto, decrypting byte source),
`sparse_source` (sparse image, sparse bundle, segmented data fork),
`dmg_open` (container detection + unlock, shared by DLL and harness),
`password_dialog` + `.rc` (the prompt), `image_reader.h` / `byte_source.h`
(the layer abstractions phase-2 sources plug into), `xways-imageio-dmg.cpp`
(the three exports, password sources, logging).

## Reporting a problem

Open an issue with the `dmgtest map` output for the image (it prints the koly
trailer, the partition list and the chunk-type histogram and contains no file
content), the plugin's version, and the X-Ways version. If the image is
damaged, `dmgtest checksums` output helps too. Please do not attach evidence
images.

## License

MIT — see [LICENSE](LICENSE). Third-party components: [NOTICE](NOTICE).
X-Ways and X-Ways Forensics are trademarks of X-Ways Software Technology AG;
this is an unofficial community project.
