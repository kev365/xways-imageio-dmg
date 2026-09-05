// dmg_mish.h — one "mish" block = the chunk table of one blkx partition entry.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dmg {

// BLKXChunkEntry.EntryType values.
enum ChunkType : uint32_t {
    kChunkZero       = 0x00000000,   // zero-fill
    kChunkRaw        = 0x00000001,   // uncompressed
    kChunkIgnore     = 0x00000002,   // unallocated, treat as zero
    kChunkAdc        = 0x80000004,   // Apple Data Compression (UDCO)
    kChunkZlib       = 0x80000005,   // UDZO
    kChunkBzip2      = 0x80000006,   // UDBZ
    kChunkLzfse      = 0x80000007,   // ULFO
    kChunkLzma       = 0x80000008,   // ULMO (xz container)
    kChunkComment    = 0x7FFFFFFE,
    kChunkTerminator = 0xFFFFFFFF,
};

const char* ChunkTypeName(uint32_t type);
bool ChunkTypeIsZero(uint32_t type);     // zero / ignore

struct MishChunk {
    uint32_t type = 0;
    uint32_t comment = 0;
    uint64_t sectorNumber = 0;       // relative to Mish::sectorNumber
    uint64_t sectorCount = 0;
    uint64_t compressedOffset = 0;   // relative to Mish::dataOffset (+ koly data fork offset)
    uint64_t compressedLength = 0;
};

struct Mish {
    uint32_t version = 0;
    uint64_t sectorNumber = 0;       // first sector of this partition in the image
    uint64_t sectorCount = 0;
    uint64_t dataOffset = 0;
    uint32_t buffersNeeded = 0;
    uint32_t blockDescriptors = 0;   // partition index / "block descriptor" id
    uint32_t checksumType = 0;       // 2 = CRC32
    uint32_t checksumBits = 0;
    uint8_t  checksum[128] = {};
    std::vector<MishChunk> chunks;   // comment + terminator entries removed
};

bool ParseMish(const uint8_t* p, size_t n, Mish& out, std::string& err);

} // namespace dmg
