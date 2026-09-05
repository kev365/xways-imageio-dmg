#include "sparse_source.h"
#include "dmg_util.h"

#include <algorithm>
#include <cstring>
#include <map>

namespace dmg {

// ===========================================================================
//  .sparseimage
// ===========================================================================

bool IsSparseImageHeader(const uint8_t* p, size_t n) { return p && n >= 4 && std::memcmp(p, "sprs", 4) == 0; }

std::shared_ptr<SparseImageSource> SparseImageSource::Open(std::shared_ptr<IByteSource> inner, std::string& err,
                                                           std::vector<std::string>& warnings) {
    uint8_t hdr[kSparseHeaderSize];
    if (inner->Size() < kSparseHeaderSize || !inner->ReadAt(0, hdr, sizeof(hdr))) { err = "cannot read sparse image header"; return nullptr; }
    if (!IsSparseImageHeader(hdr, 4)) { err = "no sprs magic"; return nullptr; }
    ByteReader r(hdr, sizeof(hdr));
    std::shared_ptr<SparseImageSource> s(new SparseImageSource());
    s->inner_ = inner;
    s->info_.version = r.U32(4);
    s->info_.sectorsPerBand = r.U32(8);
    s->info_.totalSectors = r.U32(16);
    if (s->info_.totalSectors == 0) s->info_.totalSectors = r.U32(32);   // second copy seen at 0x20 on v3 images
    if (s->info_.version != 3) warnings.push_back(Format("sparse image version %u (only 3 has been seen)", s->info_.version));
    if (s->info_.sectorsPerBand == 0 || s->info_.totalSectors == 0) { err = "sparse image header has zero band or sector count"; return nullptr; }

    const uint64_t bandBytes = static_cast<uint64_t>(s->info_.sectorsPerBand) * kSectorSizeBytes;
    s->info_.totalBands = (s->info_.totalSectors + s->info_.sectorsPerBand - 1) / s->info_.sectorsPerBand;
    s->bandFileOffset_.assign(static_cast<size_t>(s->info_.totalBands), 0);

    // Band index blocks. Each 4096-byte block starts with "sprs" and holds an
    // array of u32 slots: slot i (file order, bands stored right after the
    // block) = image-band-number + 1, 0 = unused; used slots form a prefix.
    //   block 0 (the file header): array at 0x40 → 1008 slots; u64 at 0x14 =
    //            file offset of the next index block (0 = none).
    //   later blocks: "sprs", u32 extension-block-index (0, 1, …), u32 1,
    //            zeros, array at 0x38 → 1010 slots; each sits right after the
    //            previous block's bands.
    // Verified on a 3000 MiB hdiutil sample with three index blocks
    // (2026-09-03): block 1 at 4096 + 1008 MiB (= the header pointer), block 2
    // at block 1 + 4096 + 1010 MiB, predicted file end == actual, SHA-256 of
    // the expanded image == hdiutil's.
    const uint64_t fileSize = inner->Size();
    std::vector<uint8_t> block(hdr, hdr + kSparseHeaderSize);
    uint64_t blockOfs = 0;
    uint64_t nextHint = r.U64(0x14);          // header's pointer to index block 1
    int blockNo = 0;
    for (;;) {
        const size_t arrayBase = (blockNo == 0) ? 0x40 : 0x38;
        const size_t slots = (kSparseHeaderSize - arrayBase) / 4;
        uint64_t fileOfs = blockOfs + kSparseHeaderSize;   // first band behind this block
        size_t used = 0;
        for (size_t i = 0; i < slots; ++i) {
            const uint32_t v = be32(block.data() + arrayBase + i * 4);
            if (v == 0) break;                                 // prefix ended
            if (fileOfs >= fileSize) break;                    // truncated file
            const uint64_t band = static_cast<uint64_t>(v) - 1;
            if (band < s->info_.totalBands) {
                if (s->bandFileOffset_[static_cast<size_t>(band)] == 0) ++s->info_.allocatedBands;
                s->bandFileOffset_[static_cast<size_t>(band)] = fileOfs;
            } else {
                warnings.push_back(Format("index block %d slot %zu: band %u beyond image (%llu bands)", blockNo, i, v, (unsigned long long)s->info_.totalBands));
            }
            fileOfs += bandBytes;
            ++used;
        }
        if (used < slots) break;                               // last (partially used) block
        // Next index block: the header's pointer for block 1, else right after the bands.
        uint64_t next = (blockNo == 0 && nextHint) ? nextHint : fileOfs;
        if (next + kSparseHeaderSize > fileSize) break;
        if (!inner->ReadAt(next, block.data(), kSparseHeaderSize)) break;
        if (!IsSparseImageHeader(block.data(), 4)) {
            warnings.push_back(Format("expected an index block at %llu but found no sprs magic; later bands unreadable", (unsigned long long)next));
            break;
        }
        blockOfs = next;
        ++blockNo;
    }
    s->info_.indexBlocks = static_cast<uint32_t>(blockNo + 1);
    return s;
}

bool SparseImageSource::IsUnallocated(uint64_t ofs, size_t len) const {
    if (len == 0 || ofs >= Size()) return false;
    const uint64_t bandBytes = static_cast<uint64_t>(info_.sectorsPerBand) * kSectorSizeBytes;
    const uint64_t first = ofs / bandBytes, last = std::min<uint64_t>((ofs + len - 1) / bandBytes, info_.totalBands - 1);
    for (uint64_t b = first; b <= last; ++b)
        if (bandFileOffset_[static_cast<size_t>(b)] != 0) return false;
    return true;
}

bool SparseImageSource::ReadAt(uint64_t ofs, void* buf, size_t len) {
    if (len == 0) return true;
    if (ofs > Size() || len > Size() - ofs) return false;
    const uint64_t bandBytes = static_cast<uint64_t>(info_.sectorsPerBand) * kSectorSizeBytes;
    uint8_t* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        const uint64_t pos = ofs + done;
        const uint64_t band = pos / bandBytes, inBand = pos % bandBytes;
        const size_t span = static_cast<size_t>(std::min<uint64_t>(len - done, bandBytes - inBand));
        const uint64_t fo = bandFileOffset_[static_cast<size_t>(band)];
        if (fo == 0) {
            std::memset(out + done, 0, span);
        } else {
            // A band at the very end of the file may be truncated; zero the rest.
            const uint64_t avail = inner_->Size() > fo + inBand ? inner_->Size() - (fo + inBand) : 0;
            const size_t have = static_cast<size_t>(std::min<uint64_t>(span, avail));
            if (have && !inner_->ReadAt(fo + inBand, out + done, have)) return false;
            if (have < span) std::memset(out + done + have, 0, span - have);
        }
        done += span;
    }
    return true;
}

// ===========================================================================
//  .sparsebundle
// ===========================================================================

static bool EndsWithNoCase(const std::wstring& s, const wchar_t* suffix) {
    size_t n = wcslen(suffix);
    if (s.size() < n) return false;
    return _wcsnicmp(s.c_str() + s.size() - n, suffix, n) == 0;
}

static bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES;
}

bool ResolveSparseBundle(const std::wstring& path, std::wstring& bundleDir) {
    std::wstring p = path;
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    // The path itself, its parent, or its grandparent (bands\<hex>) may be the bundle.
    for (int up = 0; up < 3 && !p.empty(); ++up) {
        if (EndsWithNoCase(p, L".sparsebundle") && FileExists(p + L"\\Info.plist") && FileExists(p + L"\\bands")) {
            bundleDir = p;
            return true;
        }
        size_t slash = p.find_last_of(L"\\/");
        if (slash == std::wstring::npos) break;
        p.resize(slash);
    }
    return false;
}

struct SparseBundleSource::Impl {
    CRITICAL_SECTION cs;
    std::map<uint64_t, std::shared_ptr<IByteSource>> bands;   // opened lazily; absent = nullptr cached too
    std::map<uint64_t, bool> missing;
};

static bool PlistInteger(const std::string& xml, const char* key, uint64_t& out) {
    std::string k = std::string("<key>") + key + "</key>";
    size_t p = xml.find(k);
    if (p == std::string::npos) return false;
    size_t a = xml.find_first_of("0123456789", p + k.size());
    if (a == std::string::npos) return false;
    // must be inside <integer> or <string>
    size_t tag = xml.rfind('<', a);
    if (tag == std::string::npos || (xml.compare(tag, 9, "<integer>") != 0 && xml.compare(tag, 8, "<string>") != 0)) return false;
    out = std::strtoull(xml.c_str() + a, nullptr, 10);
    return true;
}

std::shared_ptr<SparseBundleSource> SparseBundleSource::Open(const std::wstring& bundleDir, std::string& err,
                                                             std::vector<std::string>& warnings) {
    std::string e;
    auto plist = RawFileSource::Open((bundleDir + L"\\Info.plist").c_str(), e);
    if (!plist || plist->Size() == 0 || plist->Size() > (1u << 20)) { err = "cannot read Info.plist: " + e; return nullptr; }
    std::string xml(static_cast<size_t>(plist->Size()), '\0');
    if (!plist->ReadAt(0, xml.data(), xml.size())) { err = "cannot read Info.plist"; return nullptr; }
    if (xml.find("com.apple.diskimage.sparsebundle") == std::string::npos) warnings.push_back("Info.plist lacks diskimage-bundle-type = com.apple.diskimage.sparsebundle");

    std::shared_ptr<SparseBundleSource> s(new SparseBundleSource());
    s->dir_ = bundleDir;
    if (!PlistInteger(xml, "band-size", s->info_.bandSize) || !PlistInteger(xml, "size", s->info_.size)) { err = "Info.plist has no band-size / size"; return nullptr; }
    if (s->info_.bandSize == 0 || s->info_.size == 0 || (s->info_.bandSize % 512)) { err = "Info.plist band-size / size implausible"; return nullptr; }
    s->impl_ = new Impl();
    InitializeCriticalSection(&s->impl_->cs);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((bundleDir + L"\\bands\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ++s->info_.bandFiles; } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return s;
}

SparseBundleSource::~SparseBundleSource() {
    if (impl_) { DeleteCriticalSection(&impl_->cs); delete impl_; }
}

bool SparseBundleSource::IsUnallocated(uint64_t ofs, size_t len) const {
    if (len == 0 || ofs >= info_.size) return false;
    const uint64_t first = ofs / info_.bandSize, last = (ofs + len - 1) / info_.bandSize;
    for (uint64_t b = first; b <= last; ++b) {
        auto f = Band(b);
        if (!f) continue;                                  // missing band file: unallocated
        const uint64_t bandStart = b * info_.bandSize;
        const uint64_t from = ofs > bandStart ? ofs - bandStart : 0;
        if (from < f->Size()) return false;                // some backed bytes in range
    }
    return true;
}

std::shared_ptr<IByteSource> SparseBundleSource::Band(uint64_t index) const {
    EnterCriticalSection(&impl_->cs);
    auto it = impl_->bands.find(index);
    if (it != impl_->bands.end()) { auto b = it->second; LeaveCriticalSection(&impl_->cs); return b; }
    if (impl_->missing.count(index)) { LeaveCriticalSection(&impl_->cs); return nullptr; }
    LeaveCriticalSection(&impl_->cs);

    wchar_t name[32];
    swprintf(name, 32, L"%llx", (unsigned long long)index);
    std::string e;
    auto f = RawFileSource::Open((dir_ + L"\\bands\\" + name).c_str(), e);

    EnterCriticalSection(&impl_->cs);
    if (f) {
        if (impl_->bands.size() > 256) impl_->bands.clear();   // keep handle count bounded
        impl_->bands[index] = f;
    } else {
        impl_->missing[index] = true;
    }
    LeaveCriticalSection(&impl_->cs);
    return f;
}

bool SparseBundleSource::ReadAt(uint64_t ofs, void* buf, size_t len) {
    if (len == 0) return true;
    if (ofs > info_.size || len > info_.size - ofs) return false;
    uint8_t* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        const uint64_t pos = ofs + done;
        const uint64_t band = pos / info_.bandSize, inBand = pos % info_.bandSize;
        const size_t span = static_cast<size_t>(std::min<uint64_t>(len - done, info_.bandSize - inBand));
        auto f = Band(band);
        size_t have = 0;
        if (f && f->Size() > inBand) {
            have = static_cast<size_t>(std::min<uint64_t>(span, f->Size() - inBand));
            if (!f->ReadAt(inBand, out + done, have)) return false;
        }
        if (have < span) std::memset(out + done + have, 0, span - have);
        done += span;
    }
    return true;
}

// ===========================================================================
//  Segmented UDIF
// ===========================================================================

static bool ReadKolyOf(IByteSource& f, Koly& k, std::string& err) {
    if (f.Size() < kKolySize) { err = "too small"; return false; }
    uint8_t t[kKolySize];
    if (!f.ReadAt(f.Size() - kKolySize, t, kKolySize)) { err = "cannot read trailer"; return false; }
    return ParseKoly(t, k, err);
}

bool FindSegments(const std::wstring& anyPath, std::vector<Segment>& out, std::string& err,
                  const SegmentOpener& opener) {
    out.clear();
    auto openSeg = [&](const std::wstring& p, std::string& e) -> std::shared_ptr<IByteSource> {
        if (opener) return opener(p, e);
        return RawFileSource::Open(p.c_str(), e);
    };
    // Base name: strip ".dmg" or ".NNN.dmgpart".
    std::wstring base = anyPath;
    if (EndsWithNoCase(base, L".dmgpart")) {
        base.resize(base.size() - 8);                      // "name.002"
        size_t dot = base.find_last_of(L'.');
        if (dot == std::wstring::npos) { err = "unexpected .dmgpart name"; return false; }
        base.resize(dot);
    } else if (EndsWithNoCase(base, L".dmg")) {
        base.resize(base.size() - 4);
    } else {
        err = "segmented image must be named .dmg / .NNN.dmgpart";
        return false;
    }

    std::string e;
    Segment first;
    first.path = base + L".dmg";
    first.file = openSeg(first.path, e);
    if (!first.file) { err = "first segment not found or not openable: " + Utf16ToUtf8(first.path.c_str()) + (e.empty() ? "" : " (" + e + ")"); return false; }
    if (!ReadKolyOf(*first.file, first.koly, e)) { err = "first segment: " + e; return false; }
    const uint32_t count = first.koly.segmentCount;
    if (count < 2 || count > 9999) { err = Format("segment count %u", count); return false; }
    out.push_back(first);
    for (uint32_t n = 2; n <= count; ++n) {
        Segment s;
        wchar_t suffix[24];
        swprintf(suffix, 24, L".%03u.dmgpart", n);
        s.path = base + suffix;
        s.file = openSeg(s.path, e);
        if (!s.file) { err = Format("segment %u of %u missing or not openable: %s%s", n, count, Utf16ToUtf8(s.path.c_str()).c_str(), e.empty() ? "" : (" (" + e + ")").c_str()); return false; }
        if (!ReadKolyOf(*s.file, s.koly, e)) { err = Format("segment %u: %s", n, e.c_str()); return false; }
        if (std::memcmp(s.koly.segmentId, first.koly.segmentId, 16) != 0) { err = Format("segment %u has a different SegmentID", n); return false; }
        if (s.koly.segmentNumber != n) { err = Format("file %s says it is segment %u", Utf16ToUtf8(s.path.c_str()).c_str(), s.koly.segmentNumber); return false; }
        out.push_back(std::move(s));
    }
    return true;
}

SegmentedDataFork::SegmentedDataFork(std::vector<Segment> segments) : segs_(std::move(segments)) {
    uint64_t run = 0;
    for (const Segment& s : segs_) {
        start_.push_back(run);
        run += s.koly.dataForkLength;
    }
    total_ = run;
}

bool SegmentedDataFork::ReadAt(uint64_t ofs, void* buf, size_t len) {
    if (len == 0) return true;
    if (ofs > total_ || len > total_ - ofs) return false;
    uint8_t* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        const uint64_t pos = ofs + done;
        auto it = std::upper_bound(start_.begin(), start_.end(), pos);
        const size_t idx = static_cast<size_t>((it - start_.begin()) - 1);
        const Segment& s = segs_[idx];
        const uint64_t inSeg = pos - start_[idx];
        const size_t span = static_cast<size_t>(std::min<uint64_t>(len - done, s.koly.dataForkLength - inSeg));
        if (!s.file->ReadAt(s.koly.dataForkOffset + inSeg, out + done, span)) return false;
        done += span;
    }
    return true;
}

} // namespace dmg
