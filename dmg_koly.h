// dmg_koly.h — the 512-byte UDIF "koly" trailer at the end of a .dmg.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dmg {

constexpr size_t kKolySize = 512;

struct Koly {
    uint32_t version = 0;            // 4 for every modern image
    uint32_t headerSize = 0;         // 512
    uint32_t flags = 0;
    uint64_t runningDataForkOffset = 0;
    uint64_t dataForkOffset = 0;     // usually 0
    uint64_t dataForkLength = 0;
    uint64_t rsrcForkOffset = 0;     // binary resource fork (rare on modern images)
    uint64_t rsrcForkLength = 0;
    uint32_t segmentNumber = 0;
    uint32_t segmentCount = 0;       // >1 = segmented image (.dmgpart)
    uint8_t  segmentId[16] = {};
    uint32_t dataChecksumType = 0;   // 2 = CRC32 over the compressed data fork
    uint32_t dataChecksumBits = 0;
    uint8_t  dataChecksum[128] = {}; // value, big-endian, first (bits/8) bytes used
    uint64_t xmlOffset = 0;          // property list with the blkx array
    uint64_t xmlLength = 0;
    uint32_t masterChecksumType = 0; // 2 = CRC32 over the partitions' 4-byte CRCs in blkx order
    uint32_t masterChecksumBits = 0;
    uint8_t  masterChecksum[128] = {};
    uint32_t imageVariant = 0;
    uint64_t sectorCount = 0;        // expanded image size in 512-byte sectors
};

// Parses a 512-byte buffer. Fails if the magic is wrong.
bool ParseKoly(const uint8_t* p512, Koly& out, std::string& err);

// Sanity-checks offsets against the container size.
bool ValidateKoly(const Koly& k, uint64_t fileSize, std::string& err);

} // namespace dmg
