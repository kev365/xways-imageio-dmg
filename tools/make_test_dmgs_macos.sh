#!/bin/bash
# make_test_dmgs_macos.sh - generate the authentic hdiutil test corpus for ImageIO_DMG.
#
# Run on macOS 10.15 (Catalina) or newer:   bash make_test_dmgs_macos.sh [outdir]
# Default outdir: ~/dmg-samples. Resumable: artefacts that already exist are
# skipped, so a failed run continues where it stopped. Delete a file (or the
# whole folder) to rebuild it.
#
# Produces, per source volume (HFS+ on GPT, APFS on GPT, HFS+ on APM, HFS+ single
# volume): UDRO / UDCO / UDZO / UDBZ / ULFO / ULMO conversions, a raw .cdr of the
# same bytes (the hash oracle), and hdiutil imageinfo text. Plus AES-128 /
# AES-256 encrypted images, a segmented image, a sparse image and a sparse bundle,
# a > 1 GiB sparse image, encrypted sparse image / bundle (hash oracles), an
# encrypted + segmented image, and passphrase edge cases (non-ASCII, 200 chars).
# Finishes with SHA256SUMS.txt over everything. Never prompts for input.
set -euo pipefail
shopt -s nullglob
trap 'echo "!! FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

OUT="${1:-$HOME/dmg-samples}"
PASS="xways-test"          # password for every encrypted image (documented, test-only)
mkdir -p "$OUT"
cd "$OUT"
echo "== output: $OUT"
sw_vers | sed 's/^/   /'

have() { [ -s "$1" ]; }                              # non-empty file exists
fresh() { rm -f "$1.$2"; }                           # hdiutil refuses to overwrite

# SHA-256 of an image's *decrypted, expanded* bytes without writing a raw copy:
# attach without mounting and hash the whole-disk device. $1 = image, $2 = password or "".
hash_device() {
    local dev
    if [ -n "${2:-}" ]; then
        dev=$(printf '%s' "$2" | hdiutil attach "$1" -stdinpass -nomount -noverify | awk 'NR==1{print $1}')
    else
        dev=$(hdiutil attach "$1" -nomount -noverify | awk 'NR==1{print $1}')
    fi
    dd if="${dev/disk/rdisk}" bs=1m 2>/dev/null | shasum -a 256 | cut -d' ' -f1
    hdiutil detach "$dev" >/dev/null
}

# Detach with retries: Spotlight / fseventsd can hold a freshly written volume busy.
detach() {                   # $1 = mount point or device
    local i
    for i in 1 2 3 4 5; do
        hdiutil detach "$1" >/dev/null 2>&1 && return 0
        sleep 2
    done
    hdiutil detach "$1" -force >/dev/null
}

# Mount an image (optionally with a password on stdin) and print its mount point.
mount_image() {              # $1 = image, $2 = password or ""
    local line
    if [ -n "${2:-}" ]; then
        line=$(printf '%s' "$2" | hdiutil attach "$1" -stdinpass -nobrowse -noverify | grep '/Volumes/' | tail -1)
    else
        line=$(hdiutil attach "$1" -nobrowse -noverify | grep '/Volumes/' | tail -1)
    fi
    printf '%s' "$line" | awk -F'\t' '{print $NF}'   # mount point = last tab-separated field
}

# ---------------------------------------------------------------------------
# 1. Seed volumes with known content (read-write images, then filled)
# ---------------------------------------------------------------------------
fill_volume() {                      # $1 = mount point
    mkdir -p "$1/docs" "$1/bin" "$1/empty dir"
    printf 'ImageIO_DMG test volume\ncreated %s on %s\n' "$(date -u +%FT%TZ)" "$(sw_vers -productVersion)" > "$1/README.txt"
    head -c 3145728 /dev/urandom > "$1/bin/random-3MiB.bin"                                    # incompressible
    awk 'BEGIN{for(i=0;i<50000;i++)print "the quick brown fox jumps over the lazy dog"}' > "$1/docs/repetitive-2MiB.txt"   # very compressible
    dd if=/dev/zero of="$1/docs/zeros-1MiB.bin" bs=1m count=1 2>/dev/null                    # zero-fill chunk candidate
    seq 1 200000 > "$1/docs/sequence.txt"
    cp /usr/share/dict/words "$1/docs/words.txt" 2>/dev/null || true
    (cd "$1" && find . -type f ! -path './.*' -exec shasum -a 256 {} \; | sort -k2 > "$1/CONTENTS.sha256")
    sync
}

make_seed() {                        # $1 = name, $2 = fs, $3 = layout, $4 = size
    local name="$1" fs="$2" layout="$3" size="$4" mnt
    echo "== seed $name ($fs, layout $layout, $size)"
    if have "src_$name.dmg" && have "raw_$name.cdr"; then
        echo "   exists, skipping"; shasum -a 256 "raw_$name.cdr"; return
    fi
    fresh "src_$name" dmg
    hdiutil create -size "$size" -fs "$fs" -volname "$name" -layout "$layout" -type UDIF "src_$name.dmg" >/dev/null
    mnt=$(mount_image "src_$name.dmg" "")
    fill_volume "$mnt"
    detach "$mnt"
    fresh "raw_$name" cdr                            # raw bytes = the oracle for dmgtest extract
    hdiutil convert "src_$name.dmg" -format UDTO -o "raw_$name" >/dev/null
    shasum -a 256 "raw_$name.cdr"
}

make_seed hfsgpt  'HFS+' GPTSPUD 48m      # HFS+ inside a GPT scheme
make_seed apfsgpt 'APFS' GPTSPUD 64m      # APFS inside a GPT scheme (10.13+)
make_seed hfsapm  'HFS+' SPUD    48m      # Apple Partition Map scheme
make_seed hfsnone 'HFS+' NONE    32m      # single volume, no partition scheme

# ---------------------------------------------------------------------------
# 2. Every compression variant of every seed
# ---------------------------------------------------------------------------
for name in hfsgpt apfsgpt hfsapm hfsnone; do
    for fmt in UDRO UDCO UDZO UDBZ ULFO ULMO; do
        echo "== convert $name -> $fmt"
        if have "${name}_${fmt}.dmg"; then echo "   exists, skipping"; continue; fi
        if hdiutil convert "src_$name.dmg" -format "$fmt" -o "${name}_${fmt}" >/dev/null 2>"${name}_${fmt}.err"; then
            rm -f "${name}_${fmt}.err"
            hdiutil imageinfo "${name}_${fmt}.dmg" > "${name}_${fmt}.imageinfo.txt"
        else
            echo "   !! $fmt failed on this macOS (see ${name}_${fmt}.err)"
        fi
    done
done

# ---------------------------------------------------------------------------
# 3. Encrypted images (phase 1b): AES-128 + AES-256 over UDZO / ULFO, and an
#    encrypted read-write image whose plaintext is a raw volume (no koly inside).
#    NOTE: for `convert`, -stdinpass sets the OUTPUT password; reading an
#    encrypted input is only non-interactive via `attach -stdinpass`.
# ---------------------------------------------------------------------------
echo "== encrypted (password: $PASS)"
enc_convert() {                      # $1 = src, $2 = format, $3 = AES-128|AES-256, $4 = out basename
    if have "$4.dmg"; then echo "   exists, skipping $4"; return; fi
    printf '%s' "$PASS" | hdiutil convert "$1" -format "$2" -encryption "$3" -stdinpass -o "$4" >/dev/null
    echo "   $4.dmg"
}
enc_convert src_hfsgpt.dmg  UDZO AES-128 enc_aes128_udzo
enc_convert src_hfsgpt.dmg  UDZO AES-256 enc_aes256_udzo
enc_convert src_apfsgpt.dmg ULFO AES-256 enc_aes256_ulfo

if ! have enc_aes256_udrw.dmg; then
    printf '%s' "$PASS" | hdiutil create -size 32m -fs 'HFS+' -volname EncRW -encryption AES-256 -stdinpass -type UDIF enc_aes256_udrw.dmg >/dev/null
    mnt=$(mount_image enc_aes256_udrw.dmg "$PASS")
    fill_volume "$mnt"
    detach "$mnt"
    echo "   enc_aes256_udrw.dmg"
fi
if ! have raw_enc_aes256_udrw.cdr; then
    # plaintext oracle: attach (decrypts, no mount) and copy the whole-disk device
    dev=$(printf '%s' "$PASS" | hdiutil attach enc_aes256_udrw.dmg -stdinpass -nomount -noverify | awk 'NR==1{print $1}')
    dd if="${dev/disk/rdisk}" of=raw_enc_aes256_udrw.cdr bs=1m 2>/dev/null
    hdiutil detach "$dev" >/dev/null
    shasum -a 256 raw_enc_aes256_udrw.cdr
fi
printf '%s\n' "$PASS" > PASSWORD.txt

# ---------------------------------------------------------------------------
# 4. Segmented image (.dmgpart), sparse image, sparse bundle (phase 2)
# ---------------------------------------------------------------------------
echo "== segmented"
if have seg1m_hfsgpt_UDZO.dmg; then echo "   exists, skipping"; else
    rm -f seg1m_hfsgpt_UDZO*.dmg seg1m_hfsgpt_UDZO*.dmgpart
    hdiutil segment -o seg1m_hfsgpt_UDZO -segmentSize 1m hfsgpt_UDZO.dmg >/dev/null
    ls seg1m_hfsgpt_UDZO* | sed 's/^/   /'
fi

echo "== sparse image"
if have raw_sparse_hfs.cdr; then echo "   exists, skipping"; else
    rm -rf sparse_hfs.sparseimage
    hdiutil create -size 64m -fs 'HFS+' -volname SparseHFS -type SPARSE sparse_hfs.sparseimage >/dev/null
    mnt=$(mount_image sparse_hfs.sparseimage "")
    fill_volume "$mnt"; detach "$mnt"
    fresh raw_sparse_hfs cdr
    hdiutil convert sparse_hfs.sparseimage -format UDTO -o raw_sparse_hfs >/dev/null
    shasum -a 256 raw_sparse_hfs.cdr
fi

echo "== sparse bundle"
if have bundle_hfs.sparsebundle.zip; then echo "   exists, skipping"; else
    rm -rf bundle_hfs.sparsebundle bundle_hfs.sparsebundle.zip
    hdiutil create -size 64m -fs 'HFS+' -volname BundleHFS -type SPARSEBUNDLE bundle_hfs.sparsebundle >/dev/null
    mnt=$(mount_image bundle_hfs.sparsebundle "")
    fill_volume "$mnt"; detach "$mnt"
    fresh raw_bundle_hfs cdr
    hdiutil convert bundle_hfs.sparsebundle -format UDTO -o raw_bundle_hfs >/dev/null
    shasum -a 256 raw_bundle_hfs.cdr
    ditto -c -k --keepParent bundle_hfs.sparsebundle bundle_hfs.sparsebundle.zip    # a directory; zip it for the transfer
fi

# ---------------------------------------------------------------------------
# 4b. Gap-closers (2026-09-03): a sparse image with MORE than 1008 bands (the
#     index layout beyond the 4096-byte header is unverified), plus encrypted
#     sparse image / sparse bundle (encryption layered over band storage).
#     Oracles are *.sha256 files (hash of the expanded bytes) to save space.
# ---------------------------------------------------------------------------
echo "== large sparse image (> 2016 bands = three index blocks; ~2.2 GB on disk, ~5 min)"
if have big_sparse_hfs.sha256; then echo "   exists, skipping"; else
    # A previous aborted run may have left the volume mounted (the image file is
    # then busy): detach it before recreating the image.
    [ -d /Volumes/BigSparse ] && detach /Volumes/BigSparse || true
    rm -f big_sparse_hfs.sparseimage
    # 3000 MiB volume for 2100 MiB of fill: a 2400 MiB HFS+ volume held only
    # ~2055 MiB before ENOSPC (2026-09-03), so leave ~900 MiB of headroom.
    hdiutil create -size 3000m -fs 'HFS+' -volname BigSparse -type SPARSE big_sparse_hfs.sparseimage >/dev/null
    mnt=$(mount_image big_sparse_hfs.sparseimage "")
    df -m "$mnt" | tail -1 | awk '{print "   volume: " $2 " MiB total, " $4 " MiB free"}'
    # 2100 MiB of random data in two files forces > 2016 one-MiB bands.
    dd if=/dev/urandom of="$mnt/fill-A-1050MiB.bin" bs=1m count=1050 2>&1 | grep -v records || true
    dd if=/dev/urandom of="$mnt/fill-B-1050MiB.bin" bs=1m count=1050 2>&1 | grep -v records || true
    sync
    fill_volume "$mnt"
    detach "$mnt"
    hash_device big_sparse_hfs.sparseimage "" > big_sparse_hfs.sha256
    echo "   $(cat big_sparse_hfs.sha256)  big_sparse_hfs.sparseimage ($(du -h big_sparse_hfs.sparseimage | cut -f1))"
fi

echo "== encrypted sparse image"
if have enc_sparse_hfs.sha256; then echo "   exists, skipping"; else
    rm -f enc_sparse_hfs.sparseimage
    printf '%s' "$PASS" | hdiutil create -size 32m -fs 'HFS+' -volname EncSparse -type SPARSE -encryption AES-256 -stdinpass enc_sparse_hfs.sparseimage >/dev/null
    mnt=$(mount_image enc_sparse_hfs.sparseimage "$PASS")
    fill_volume "$mnt"
    detach "$mnt"
    hash_device enc_sparse_hfs.sparseimage "$PASS" > enc_sparse_hfs.sha256
    echo "   $(cat enc_sparse_hfs.sha256)  enc_sparse_hfs.sparseimage"
fi

echo "== encrypted sparse bundle"
if have enc_bundle_hfs.sha256; then echo "   exists, skipping"; else
    rm -rf enc_bundle_hfs.sparsebundle enc_bundle_hfs.sparsebundle.zip
    printf '%s' "$PASS" | hdiutil create -size 32m -fs 'HFS+' -volname EncBundle -type SPARSEBUNDLE -encryption AES-256 -stdinpass enc_bundle_hfs.sparsebundle >/dev/null
    mnt=$(mount_image enc_bundle_hfs.sparsebundle "$PASS")
    fill_volume "$mnt"
    detach "$mnt"
    hash_device enc_bundle_hfs.sparsebundle "$PASS" > enc_bundle_hfs.sha256
    ditto -c -k --keepParent enc_bundle_hfs.sparsebundle enc_bundle_hfs.sparsebundle.zip
    echo "   $(cat enc_bundle_hfs.sha256)  enc_bundle_hfs.sparsebundle"
fi

# ---------------------------------------------------------------------------
# 4c. Encrypted + segmented image (added 2026-09-04). `hdiutil convert` takes
#     -encryption and -segmentSize together and writes one encrcdsa container
#     per segment (every part starts with "encrcdsa"; the UDIF segment, koly
#     trailer included, is the plaintext). Oracle: raw_hfsgpt.cdr.
#     (Segmenting an already-encrypted image with `hdiutil segment` is not
#     possible non-interactively: it must read the input and prompts for the
#     password on the terminal, ignoring -stdinpass.)
# ---------------------------------------------------------------------------
echo "== encrypted + segmented: convert -encryption -segmentSize"
if have enc_seg1m_hfsgpt_UDZO.dmg; then echo "   exists, skipping"; else
    rm -f enc_seg1m_hfsgpt_UDZO*.dmg enc_seg1m_hfsgpt_UDZO*.dmgpart
    printf '%s' "$PASS" | hdiutil convert src_hfsgpt.dmg -format UDZO -encryption AES-256 -stdinpass -segmentSize 1m -o enc_seg1m_hfsgpt_UDZO >/dev/null
    for f in enc_seg1m_hfsgpt_UDZO*; do printf '   %-40s head: %s\n' "$f" "$(head -c 8 "$f" | xxd -p)"; done
fi

# ---------------------------------------------------------------------------
# 4d. Passphrase edge cases (phase-3 hardening): non-ASCII and very long
#     passphrases over the small single-volume seed. hdiutil takes the raw
#     bytes from stdin (UTF-8 here). Oracle for both: raw_hfsnone.cdr.
# ---------------------------------------------------------------------------
echo "== passphrase edge cases"
PASS_UNICODE='Ünïcødé-pässwørd-✓-日本語'
PASS_LONG=$(printf 'L%.0s' $(seq 1 200))      # 200 x 'L'
enc_pw() {                           # $1 = out basename, $2 = passphrase
    if have "$1.dmg"; then echo "   exists, skipping $1"; return; fi
    printf '%s' "$2" | hdiutil convert src_hfsnone.dmg -format UDZO -encryption AES-256 -stdinpass -o "$1" >/dev/null
    echo "   $1.dmg"
}
enc_pw enc_pw_unicode "$PASS_UNICODE"
enc_pw enc_pw_long    "$PASS_LONG"
{ printf 'enc_pw_unicode.dmg\t%s\n' "$PASS_UNICODE"; printf 'enc_pw_long.dmg\t%s\n' "$PASS_LONG"; } > PASSWORDS-EXTRA.txt

# ---------------------------------------------------------------------------
# 5. Hashes + manifest
# ---------------------------------------------------------------------------
echo "== hashing"
rm -f ._* SHA256SUMS.txt          # ._* = AppleDouble sidecars macOS drops on FAT/exFAT sticks
shasum -a 256 *.dmg *.dmgpart *.cdr *.sparseimage *.zip *.sha256 | sort -k2 > SHA256SUMS.txt
{
    echo "ImageIO_DMG test corpus - generated $(date -u +%FT%TZ)"
    sw_vers
    echo; echo "encrypted-image password: $PASS"
    echo; ls -la
} > MANIFEST.txt
count=$(ls *.dmg | wc -l | tr -d ' ')
echo
echo "Done. $count .dmg files in $OUT ($(du -sh "$OUT" | cut -f1))."
echo "Copy the whole folder to the Windows workspace test-data store (see make_test_dmgs_macos.md)."
