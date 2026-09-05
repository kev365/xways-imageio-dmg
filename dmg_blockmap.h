// dmg_blockmap.h — the flattened, sorted chunk table of a whole UDIF image.
//
// Every blkx partition's mish chunks are turned into absolute-sector chunks
// (sector = mish.SectorNumber + chunk.SectorNumber, fileOfs = koly data fork
// offset + mish.DataOffset + chunk.CompressedOffset — the relative semantics
// QEMU's block/dmg.c and dmg2img both implement), sorted, de-overlapped, and
// gap-filled with synthetic zero chunks so that every sector in
// [0, totalSectors) maps to exactly one chunk. Find() is a binary search.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "dmg_koly.h"
#include "dmg_mish.h"
#include "dmg_plist.h"

namespace dmg {

constexpr uint32_t kSectorSize = 512;

struct Chunk {
    uint64_t sector = 0;        // absolute first sector in the image
    uint64_t count = 0;         // sectors
    uint32_t type = 0;          // ChunkType
    uint64_t fileOfs = 0;       // absolute offset of the compressed payload in the container
    uint64_t compLen = 0;
    int32_t  partition = -1;    // index into BlockMap::partitions, -1 for synthetic
    bool     synthetic = false; // gap / tail filler
    uint64_t Bytes() const { return count * kSectorSize; }
    uint64_t End() const { return sector + count; }
};

struct Partition {
    std::string name;
    int64_t id = -1;
    std::string attributes;
    uint64_t firstSector = 0;
    uint64_t sectorCount = 0;
    uint32_t checksumType = 0;      // 2 = CRC32 over decoded bytes of all chunks except type 2 (unallocated)
    uint32_t checksumBits = 0;
    uint8_t  checksum[128] = {};
    size_t chunkCount = 0;
};

struct BlockMap {
    std::vector<Chunk> chunks;              // sorted by sector, contiguous, no overlaps
    std::vector<Partition> partitions;
    uint64_t totalSectors = 0;
    std::map<uint32_t, uint64_t> typeCounts; // chunk type -> number of (non-synthetic) chunks
    std::map<uint32_t, uint64_t> typeBytes;  // chunk type -> uncompressed bytes
    uint64_t maxChunkBytes = 0;
    bool hadOverlap = false;
    std::vector<std::string> warnings;

    // Index of the chunk containing `sector`. Requires sector < totalSectors.
    size_t Find(uint64_t sector) const;
    bool HasType(uint32_t type) const { return typeCounts.count(type) != 0; }
};

struct BlockMapLimits {
    uint64_t maxChunkBytes = 512ull << 20;   // reject absurd per-chunk sizes
    uint64_t maxTotalChunks = 8000000;
};

bool BuildBlockMap(const Koly& koly, const std::vector<BlkxEntry>& entries, uint64_t fileSize,
                   const BlockMapLimits& limits, BlockMap& out, std::string& err);

} // namespace dmg
