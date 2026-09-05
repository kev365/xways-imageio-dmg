// sparse_source.h — the phase-2 containers: sparse image, sparse bundle,
// segmented UDIF. Each is an IByteSource that presents the logical bytes.
//
//   SparseImageSource  .sparseimage — 4096-byte "sprs" header + band index
//                      array; bands stored in allocation order, unallocated
//                      bands read as zeros.
//   SparseBundleSource .sparsebundle/ — Info.plist (band-size, size) + bands/<hex>;
//                      missing or short band files read as zeros.
//   SegmentedDataFork  name.dmg + name.002.dmgpart … — the logical UDIF data
//                      fork is the concatenation of every segment's data fork,
//                      in SegmentNumber order (koly RunningDataForkOffset).
//
// Layout references: libyal libmodi "Mac OS disk image types" (LGPL — used
// as documentation only) and the hdiutil samples generated 2026-09-03.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "byte_source.h"
#include "dmg_koly.h"

namespace dmg {

// --- .sparseimage -----------------------------------------------------------

constexpr size_t kSparseHeaderSize = 4096;

struct SparseImageInfo {
    uint32_t version = 0;         // 3
    uint32_t sectorsPerBand = 0;  // 2048 = 1 MiB bands
    uint64_t totalSectors = 0;
    uint64_t totalBands = 0;
    uint64_t allocatedBands = 0;
    uint32_t indexBlocks = 1;     // 1 header block + extension blocks every 1008 / 1010 bands
};

bool IsSparseImageHeader(const uint8_t* p, size_t n);   // "sprs"

class SparseImageSource : public IByteSource {
public:
    static std::shared_ptr<SparseImageSource> Open(std::shared_ptr<IByteSource> inner, std::string& err,
                                                   std::vector<std::string>& warnings);
    uint64_t Size() const override { return info_.totalSectors * kSectorSizeBytes; }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override;
    bool IsUnallocated(uint64_t ofs, size_t len) const override;
    const SparseImageInfo& Info() const { return info_; }
private:
    static constexpr uint64_t kSectorSizeBytes = 512;
    std::shared_ptr<IByteSource> inner_;
    SparseImageInfo info_;
    std::vector<uint64_t> bandFileOffset_;   // image band -> file offset of its data, or 0 = unallocated
};

// --- .sparsebundle ----------------------------------------------------------

struct SparseBundleInfo {
    uint64_t bandSize = 0;   // bytes per band file
    uint64_t size = 0;       // media size in bytes
    uint64_t bandFiles = 0;  // band files present
};

// True when `path` is inside (or is) a *.sparsebundle directory; sets `bundleDir`.
bool ResolveSparseBundle(const std::wstring& path, std::wstring& bundleDir);

class SparseBundleSource : public IByteSource {
public:
    static std::shared_ptr<SparseBundleSource> Open(const std::wstring& bundleDir, std::string& err,
                                                    std::vector<std::string>& warnings);
    ~SparseBundleSource() override;
    uint64_t Size() const override { return info_.size; }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override;
    bool IsUnallocated(uint64_t ofs, size_t len) const override;
    const SparseBundleInfo& Info() const { return info_; }
private:
    std::shared_ptr<IByteSource> Band(uint64_t index) const;   // nullptr when absent
    std::wstring dir_;
    SparseBundleInfo info_;
    struct Impl;
    Impl* impl_ = nullptr;
};

// --- segmented UDIF ---------------------------------------------------------

struct Segment {
    std::wstring path;
    std::shared_ptr<IByteSource> file;
    Koly koly;
};

// Opens one segment file as a byte source. The default opens the raw file; a
// caller supplies its own to unwrap per-segment encryption (each part of an
// encrypted segmented image is its own encrcdsa container).
using SegmentOpener = std::function<std::shared_ptr<IByteSource>(const std::wstring& path, std::string& err)>;

// From any one segment file, locate all segments (name.dmg, name.002.dmgpart …),
// verify SegmentID / SegmentCount, return them in SegmentNumber order.
bool FindSegments(const std::wstring& anyPath, std::vector<Segment>& out, std::string& err,
                  const SegmentOpener& opener = nullptr);

class SegmentedDataFork : public IByteSource {
public:
    explicit SegmentedDataFork(std::vector<Segment> segments);
    uint64_t Size() const override { return total_; }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override;
    const std::vector<Segment>& Segments() const { return segs_; }
private:
    std::vector<Segment> segs_;
    std::vector<uint64_t> start_;   // running offset where each segment's data fork begins
    uint64_t total_ = 0;
};

} // namespace dmg
