#include "dmg_blockmap.h"
#include "dmg_util.h"

#include <algorithm>

namespace dmg {

size_t BlockMap::Find(uint64_t sector) const {
    // first chunk whose start is > sector, minus one
    auto it = std::upper_bound(chunks.begin(), chunks.end(), sector,
                               [](uint64_t s, const Chunk& c) { return s < c.sector; });
    if (it == chunks.begin()) return 0;
    return static_cast<size_t>((it - chunks.begin()) - 1);
}

bool BuildBlockMap(const Koly& koly, const std::vector<BlkxEntry>& entries, uint64_t fileSize,
                   const BlockMapLimits& limits, BlockMap& bm, std::string& err) {
    bm = BlockMap();
    const uint64_t dataEnd = (koly.dataForkLength ? koly.dataForkOffset + koly.dataForkLength : fileSize);
    std::vector<Chunk> raw;
    uint64_t total = 0;

    for (size_t pi = 0; pi < entries.size(); ++pi) {
        const BlkxEntry& e = entries[pi];
        Mish m;
        if (!ParseMish(e.mish.data(), e.mish.size(), m, err)) {
            err = Format("blkx entry %zu (%s): %s", pi, e.name.c_str(), err.c_str());
            return false;
        }
        Partition p;
        p.name = e.name;
        p.id = e.id;
        p.attributes = e.attributes;
        p.firstSector = m.sectorNumber;
        p.sectorCount = m.sectorCount;
        p.checksumType = m.checksumType;
        p.checksumBits = m.checksumBits;
        std::memcpy(p.checksum, m.checksum, 128);
        p.chunkCount = m.chunks.size();
        bm.partitions.push_back(p);

        for (const MishChunk& mc : m.chunks) {
            if (mc.sectorCount == 0) continue;
            Chunk c;
            c.sector = m.sectorNumber + mc.sectorNumber;
            c.count = mc.sectorCount;
            c.type = mc.type;
            c.fileOfs = koly.dataForkOffset + m.dataOffset + mc.compressedOffset;
            c.compLen = mc.compressedLength;
            c.partition = static_cast<int32_t>(pi);
            // The size limit protects the decode buffer; zero-fill chunks never
            // allocate one, and real images carry huge ones (a 1.5 GB LibreOffice
            // DMG has a 485 MB "ignore" chunk for its free space).
            if (!ChunkTypeIsZero(c.type) && c.count > limits.maxChunkBytes / kSectorSize) {
                err = Format("partition %zu chunk at sector %llu spans %llu sectors (over limit)",
                             pi, (unsigned long long)c.sector, (unsigned long long)c.count);
                return false;
            }
            if (!ChunkTypeIsZero(c.type)) {
                if (c.fileOfs > dataEnd || c.compLen > dataEnd - c.fileOfs) {
                    err = Format("partition %zu chunk at sector %llu: payload [%llu+%llu] outside data fork (end %llu)",
                                 pi, (unsigned long long)c.sector, (unsigned long long)c.fileOfs,
                                 (unsigned long long)c.compLen, (unsigned long long)dataEnd);
                    return false;
                }
                if (c.type == kChunkRaw && c.compLen != c.Bytes()) {
                    err = Format("partition %zu raw chunk at sector %llu: compLen %llu != %llu bytes",
                                 pi, (unsigned long long)c.sector, (unsigned long long)c.compLen,
                                 (unsigned long long)c.Bytes());
                    return false;
                }
            }
            raw.push_back(c);
            if (c.End() > total) total = c.End();
            if (raw.size() > limits.maxTotalChunks) { err = "too many chunks"; return false; }
        }
    }

    if (koly.sectorCount) {
        // Trust koly.SectorCount to set the image size (it carries trailing
        // free space), but never a value that is physically impossible: a real
        // DMG is far below 256 TiB. A bogus huge count (fuzzed / corrupt koly)
        // would otherwise make X-Ways present an exabyte image. Cap to the
        // sectors the chunks actually cover and warn.
        constexpr uint64_t kMaxSectors = (1ull << 48) / kSectorSize;   // 256 TiB
        if (koly.sectorCount > kMaxSectors && koly.sectorCount > total) {
            bm.warnings.push_back(Format("koly SectorCount %llu is implausible (> 256 TiB); using chunk coverage %llu instead",
                                         (unsigned long long)koly.sectorCount, (unsigned long long)total));
        } else if (total > koly.sectorCount) {
            bm.warnings.push_back(Format("chunks extend to sector %llu beyond koly SectorCount %llu",
                                         (unsigned long long)total, (unsigned long long)koly.sectorCount));
        } else {
            total = koly.sectorCount;
        }
    }
    if (total == 0) { err = "image has no sectors"; return false; }
    bm.totalSectors = total;

    std::stable_sort(raw.begin(), raw.end(), [](const Chunk& a, const Chunk& b) { return a.sector < b.sector; });

    // Walk in order, dropping overlaps and filling gaps.
    uint64_t cursor = 0;
    bm.chunks.reserve(raw.size() + 16);
    auto addGap = [&](uint64_t from, uint64_t to) {
        Chunk z;
        z.sector = from;
        z.count = to - from;
        z.type = kChunkZero;
        z.synthetic = true;
        bm.chunks.push_back(z);
    };
    for (Chunk c : raw) {
        if (c.sector < cursor) {
            if (c.End() <= cursor) {
                bm.hadOverlap = true;
                bm.warnings.push_back(Format("dropped chunk at sector %llu (%llu sectors): fully overlapped",
                                             (unsigned long long)c.sector, (unsigned long long)c.count));
                continue;
            }
            // Partial overlap: cannot trim a compressed chunk safely; drop it.
            bm.hadOverlap = true;
            bm.warnings.push_back(Format("dropped chunk at sector %llu (%llu sectors): partial overlap",
                                         (unsigned long long)c.sector, (unsigned long long)c.count));
            continue;
        }
        if (c.sector > cursor) addGap(cursor, c.sector);
        if (c.End() > total) {
            bm.warnings.push_back(Format("chunk at sector %llu truncated to image end", (unsigned long long)c.sector));
            c.count = total - c.sector;
            if (c.count == 0) continue;
        }
        bm.chunks.push_back(c);
        cursor = c.End();
        bm.typeCounts[c.type] += 1;
        bm.typeBytes[c.type] += c.Bytes();
        if (c.Bytes() > bm.maxChunkBytes) bm.maxChunkBytes = c.Bytes();
    }
    if (cursor < total) addGap(cursor, total);
    return true;
}

} // namespace dmg
