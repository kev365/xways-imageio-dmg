#include "dmg_open.h"
#include "dmg_koly.h"
#include "dmg_util.h"
#include "sparse_source.h"

#include <cstring>

namespace dmg {

static bool TailHasKoly(IByteSource& src) {
    if (src.Size() < kKolySize) return false;
    uint8_t t[8];
    return src.ReadAt(src.Size() - kKolySize, t, 4) && std::memcmp(t, "koly", 4) == 0;
}

static bool EndsWithNoCaseW(const std::wstring& s, const wchar_t* suffix) {
    size_t n = wcslen(suffix);
    return s.size() >= n && _wcsnicmp(s.c_str() + s.size() - n, suffix, n) == 0;
}

// Unlock an encrcdsa container whose header is already in out.enc; on success
// `payload` (the cipher-block source) becomes the plaintext source.
static OpenStatus UnlockParsed(const OpenOptions& opts, OpenedImage& out, std::shared_ptr<IByteSource>& payload, std::string& message,
                               uint64_t ivPeriodBlocks = 0) {
    std::string err;
    out.encrypted = true;
    if (!opts.passwordProvider) { message = "encrypted DMG: no password available"; return OpenStatus::GiveUp; }
    EncKeys keys;
    std::string lastErr;
    for (int attempt = 1; attempt <= opts.maxAttempts; ++attempt) {
        std::string pw;
        if (!opts.passwordProvider(out.enc, attempt, lastErr, pw)) { message = "encrypted DMG: password not provided"; return OpenStatus::GiveUp; }
        if (!UnlockWithPassword(out.enc, pw, keys, err)) {
            lastErr = err;
            if (err != "wrong password") { message = "encrypted DMG: " + err; return OpenStatus::GiveUp; }
            continue;
        }
        auto enc = EncryptedSource::Create(payload, out.enc, keys, err, ivPeriodBlocks);
        if (!enc) { message = "encrypted DMG: " + err; return OpenStatus::GiveUp; }
        std::string what;
        if (keys.trailerVerified || enc->PlaintextLooksValid(what)) {
            if (!keys.trailerVerified) out.warnings.push_back("key blob lacked the CKIE marker; accepted on plaintext signature (" + what + ")");
            out.plaintext = enc;
            out.passwordUsed = pw;
            payload = enc;
            return OpenStatus::Ok;
        }
        lastErr = "wrong password";
    }
    message = "encrypted DMG: password not accepted";
    return OpenStatus::GiveUp;
}

// Header and cipher blocks in the same file (every single-file encrypted image).
static OpenStatus Unlock(const OpenOptions& opts, OpenedImage& out, std::shared_ptr<IByteSource>& payload, std::string& message) {
    std::string err;
    out.encrypted = true;
    if (!ParseEncHeader(*payload, out.enc, err)) { message = "encrypted DMG: " + err; return OpenStatus::GiveUp; }
    return UnlockParsed(opts, out, payload, message);
}

OpenStatus OpenDmg(const wchar_t* path, const OpenOptions& opts, OpenedImage& out, std::string& message) {
    out = OpenedImage();
    std::string err;
    const std::wstring wpath = path ? path : L"";

    // --- Sparse bundle: a directory, addressed through any file inside it ---
    std::wstring bundleDir;
    if (ResolveSparseBundle(wpath, bundleDir)) {
        auto b = SparseBundleSource::Open(bundleDir, err, out.warnings);
        if (!b) { message = "sparse bundle: " + err; return OpenStatus::GiveUp; }
        out.file = b;
        std::shared_ptr<IByteSource> payload = b;
        // Encrypted bundle: the encrcdsa header lives in the bundle's `token`
        // file (122,368 bytes on hdiutil output) and the band files hold the
        // cipher blocks from logical offset 0 — so dataOffset is 0 here, not
        // the header's own value.
        auto token = RawFileSource::Open((bundleDir + L"\\token").c_str(), err);
        uint8_t head[8] = {};
        if (token && token->Size() >= kEncHeaderMin && token->ReadAt(0, head, 8) && IsEncryptedV2Header(head, 8)) {
            if (!ParseEncHeader(*token, out.enc, err)) { message = "encrypted sparse bundle: " + err; return OpenStatus::GiveUp; }
            out.enc.dataOffset = 0;
            if (out.enc.dataLen == 0 || out.enc.dataLen > b->Size()) out.enc.dataLen = b->Size();
            // Each band file is encrypted on its own: the IV block counter restarts per band.
            OpenStatus st = UnlockParsed(opts, out, payload, message, b->Info().bandSize / out.enc.bytesPerBlock);
            if (st != OpenStatus::Ok) return st;
        } else if (payload->ReadAt(0, head, 8) && IsEncryptedV2Header(head, 8)) {
            OpenStatus st = Unlock(opts, out, payload, message);      // header inside band 0 (not seen on hdiutil output)
            if (st != OpenStatus::Ok) return st;
        }
        out.reader = std::make_unique<RawImageReader>(payload);
        out.kind = out.encrypted ? "encrypted-sparsebundle" : "sparsebundle";
        out.plaintextKind = Format("%llu MiB media, %llu-byte bands, %llu band file(s)", (unsigned long long)(b->Info().size >> 20),
                                   (unsigned long long)b->Info().bandSize, (unsigned long long)b->Info().bandFiles);
        return OpenStatus::Ok;
    }

    // --- Segment part: point the analyst at the first segment -------------
    if (EndsWithNoCaseW(wpath, L".dmgpart")) {
        message = "this is one segment of a segmented image; add the first segment (the .dmg file) instead";
        return OpenStatus::GiveUp;
    }

    out.file = RawFileSource::Open(path, err);
    if (!out.file) { message = "open failed: " + err; return OpenStatus::NotDmg; }
    const uint64_t size = out.file->Size();
    if (size < kKolySize) { message = "file smaller than a koly trailer"; return OpenStatus::NotDmg; }

    uint8_t head[8] = {};
    out.file->ReadAt(0, head, 8);
    std::shared_ptr<IByteSource> payload = out.file;

    // --- Encryption wrapper ------------------------------------------------
    if (IsEncryptedV2Header(head, 8)) {
        OpenStatus st = Unlock(opts, out, payload, message);
        if (st != OpenStatus::Ok) return st;
        payload->ReadAt(0, head, 8);
    } else {
        uint8_t tail[kKolySize];
        if (!out.file->ReadAt(size - kKolySize, tail, kKolySize)) { message = "cannot read trailer"; return OpenStatus::NotDmg; }
        if (IsEncryptedV1Trailer(tail + kKolySize - 8)) { message = "encrypted DMG (cdsaencr v1) is not supported"; return OpenStatus::GiveUp; }
        if (!IsSparseImageHeader(head, 8) && std::memcmp(tail, "koly", 4) != 0) {
            // No trailer. Two very different situations share this shape:
            //  - a read-write / raw image named .dmg (UDRW, or a bare volume):
            //    decline silently, X-Ways opens those natively as raw images;
            //  - a compressed UDIF whose tail is missing (truncated download,
            //    partial copy): starts with a compressed stream, ends without
            //    the trailer. Say so, because X-Ways' own message ("DMG Images
            //    not supported") would send the analyst down the wrong path.
            uint8_t h16[16] = {};
            out.file->ReadAt(0, h16, 16);
            const bool zlib  = h16[0] == 0x78 && (h16[1] == 0x01 || h16[1] == 0x5E || h16[1] == 0x9C || h16[1] == 0xDA);
            const bool bzip2 = std::memcmp(h16, "BZh", 3) == 0;
            const bool xz    = std::memcmp(h16, "\xFD" "7zXZ\x00", 6) == 0;
            const bool lzfse = std::memcmp(h16, "bvx", 3) == 0;
            if (EndsWithNoCaseW(wpath, L".dmg") && (zlib || bzip2 || xz || lzfse)) {
                message = Format("no UDIF trailer, but the file starts with a %s stream: this looks like a truncated or incomplete compressed DMG (%llu bytes). Re-acquire or re-download it.",
                                 zlib ? "zlib" : bzip2 ? "bzip2" : xz ? "xz/LZMA" : "LZFSE", (unsigned long long)size);
                return OpenStatus::GiveUp;
            }
            message = "no koly trailer";
            return OpenStatus::NotDmg;
        }
    }

    // --- Sparse image (plain or decrypted) -------------------------------------
    if (IsSparseImageHeader(head, 8)) {
        auto s = SparseImageSource::Open(payload, err, out.warnings);
        if (!s) { message = "sparse image: " + err; return OpenStatus::GiveUp; }
        out.reader = std::make_unique<RawImageReader>(s);
        out.kind = out.encrypted ? "encrypted-sparseimage" : "sparseimage";
        out.plaintextKind = Format("v%u, %u sectors/band, %llu of %llu bands allocated", s->Info().version, s->Info().sectorsPerBand,
                                   (unsigned long long)s->Info().allocatedBands, (unsigned long long)s->Info().totalBands);
        return OpenStatus::Ok;
    }

    // --- UDIF (single file or segmented) ------------------------------------------
    if (TailHasKoly(*payload)) {
        uint8_t tail[kKolySize];
        Koly k;
        if (!payload->ReadAt(payload->Size() - kKolySize, tail, kKolySize) || !ParseKoly(tail, k, err)) { message = err; return OpenStatus::GiveUp; }
        if (k.segmentCount > 1) {
            // Each part of an encrypted segmented image is its own encrcdsa
            // container (own UUID / salt / wrapped key, same passphrase), and the
            // UDIF segment - koly trailer included - is the plaintext. Unlock each
            // part as it is discovered, trying the already-accepted password first.
            const bool wasEncrypted = out.encrypted;
            SegmentOpener opener = [&](const std::wstring& p, std::string& e) -> std::shared_ptr<IByteSource> {
                auto f = RawFileSource::Open(p.c_str(), e);
                if (!f) return nullptr;
                uint8_t h8[8] = {};
                if (!(f->Size() >= kEncHeaderMin && f->ReadAt(0, h8, 8) && IsEncryptedV2Header(h8, 8))) {
                    if (wasEncrypted) { e = "segment is not encrypted although the first one is"; return nullptr; }
                    return f;
                }
                if (!wasEncrypted) { e = "segment is encrypted although the first one is not"; return nullptr; }
                OpenedImage part;                      // scratch: header + keys for this one part
                if (!ParseEncHeader(*f, part.enc, e)) return nullptr;
                EncKeys keys;
                std::string ue;
                if (!out.passwordUsed.empty() && UnlockWithPassword(part.enc, out.passwordUsed, keys, ue)) {
                    auto enc = EncryptedSource::Create(f, part.enc, keys, e);
                    return enc ? std::shared_ptr<IByteSource>(enc) : nullptr;
                }
                // Different passphrase on this part (unusual): ask the provider.
                OpenOptions o = opts;
                std::shared_ptr<IByteSource> payload = f;
                std::string msg;
                if (UnlockParsed(o, part, payload, msg) != OpenStatus::Ok) { e = msg; return nullptr; }
                return payload;
            };
            std::vector<Segment> segs;
            if (!FindSegments(wpath, segs, err, opener)) { message = "segmented image: " + err; return OpenStatus::GiveUp; }
            // The block map lives in whichever segment has a non-trivial plist (segment 1 on hdiutil output).
            std::vector<uint8_t> mapBytes;
            bool mapIsRsrc = false;
            const Segment* mapSeg = nullptr;
            for (const Segment& s : segs) {
                if (s.koly.xmlLength > 512 && s.koly.xmlOffset + s.koly.xmlLength <= s.file->Size()) {
                    mapBytes.resize(static_cast<size_t>(s.koly.xmlLength));
                    if (s.file->ReadAt(s.koly.xmlOffset, mapBytes.data(), mapBytes.size()) &&
                        std::string(reinterpret_cast<const char*>(mapBytes.data()), mapBytes.size()).find("blkx") != std::string::npos) { mapSeg = &s; break; }
                }
                if (s.koly.rsrcForkLength > 0 && s.koly.rsrcForkOffset + s.koly.rsrcForkLength <= s.file->Size()) {
                    mapBytes.resize(static_cast<size_t>(s.koly.rsrcForkLength));
                    if (s.file->ReadAt(s.koly.rsrcForkOffset, mapBytes.data(), mapBytes.size())) { mapSeg = &s; mapIsRsrc = true; break; }
                }
            }
            if (!mapSeg) { message = "segmented image: no segment carries the block map"; return OpenStatus::GiveUp; }
            auto fork = std::make_shared<SegmentedDataFork>(segs);
            auto udif = UdifSource::OpenSegmented(fork, mapSeg->koly, mapBytes, mapIsRsrc, opts.udif, err, out.warnings);
            if (!udif) { message = "segmented image: " + err; return OpenStatus::GiveUp; }
            out.udif = udif.get();
            out.reader = std::move(udif);
            out.kind = out.encrypted ? "encrypted-udif-segmented" : "udif-segmented";
            out.plaintextKind = Format("%zu segments%s", segs.size(), out.encrypted ? ", each its own encrypted container" : "");
            return OpenStatus::Ok;
        }
        auto udif = UdifSource::Open(payload, opts.udif, err, out.warnings);
        if (!udif) { message = err; return OpenStatus::GiveUp; }
        out.udif = udif.get();
        out.reader = std::move(udif);
        out.kind = out.encrypted ? "encrypted-udif" : "udif";
        return OpenStatus::Ok;
    }

    // --- Encrypted read-write image: the plaintext is the disk itself -----------
    if (out.encrypted) {
        std::string what;
        out.plaintext->PlaintextLooksValid(what);
        out.plaintextKind = what;
        if (out.enc.dataLen % kSectorSize) out.warnings.push_back(Format("plaintext length %llu is not a multiple of 512; tail ignored", (unsigned long long)out.enc.dataLen));
        out.reader = std::make_unique<RawImageReader>(payload);
        out.kind = "encrypted-raw";
        return OpenStatus::Ok;
    }
    message = "no koly trailer";
    return OpenStatus::NotDmg;
}

} // namespace dmg
