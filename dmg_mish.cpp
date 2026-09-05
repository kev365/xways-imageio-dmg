#include "dmg_mish.h"
#include "dmg_util.h"

namespace dmg {

const char* ChunkTypeName(uint32_t t) {
    switch (t) {
        case kChunkZero:       return "zero";
        case kChunkRaw:        return "raw";
        case kChunkIgnore:     return "ignore";
        case kChunkAdc:        return "adc";
        case kChunkZlib:       return "zlib";
        case kChunkBzip2:      return "bzip2";
        case kChunkLzfse:      return "lzfse";
        case kChunkLzma:       return "lzma";
        case kChunkComment:    return "comment";
        case kChunkTerminator: return "terminator";
        default:               return "unknown";
    }
}

bool ChunkTypeIsZero(uint32_t t) { return t == kChunkZero || t == kChunkIgnore; }

bool ParseMish(const uint8_t* p, size_t n, Mish& m, std::string& err) {
    ByteReader r(p, n);
    if (!r.Magic(0, "mish", 4)) { err = "no mish magic"; return false; }
    if (!r.Has(0, 204)) { err = "mish block truncated"; return false; }
    m.version          = r.U32(4);
    m.sectorNumber     = r.U64(8);
    m.sectorCount      = r.U64(16);
    m.dataOffset       = r.U64(24);
    m.buffersNeeded    = r.U32(32);
    m.blockDescriptors = r.U32(36);
    m.checksumType     = r.U32(64);
    m.checksumBits     = r.U32(68);
    std::memcpy(m.checksum, p + 72, 128);
    uint32_t count     = r.U32(200);
    if (count > 4000000u) { err = Format("mish chunk count %u implausible", count); return false; }
    if (!r.Has(204, static_cast<size_t>(count) * 40)) {
        err = Format("mish declares %u chunks but block is only %zu bytes", count, n);
        return false;
    }
    m.chunks.clear();
    m.chunks.reserve(count);
    size_t off = 204;
    for (uint32_t i = 0; i < count; ++i, off += 40) {
        MishChunk c;
        c.type             = r.U32(off);
        c.comment          = r.U32(off + 4);
        c.sectorNumber     = r.U64(off + 8);
        c.sectorCount      = r.U64(off + 16);
        c.compressedOffset = r.U64(off + 24);
        c.compressedLength = r.U64(off + 32);
        if (c.type == kChunkTerminator) break;
        if (c.type == kChunkComment) continue;
        m.chunks.push_back(c);
    }
    return true;
}

} // namespace dmg
