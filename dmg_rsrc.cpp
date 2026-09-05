#include "dmg_rsrc.h"
#include "dmg_util.h"

namespace dmg {

// Resource fork layout (Inside Macintosh: More Macintosh Toolbox, "Resource
// Manager"): 16-byte header {dataOffset, mapOffset, dataLength, mapLength};
// data section = sequence of {u32 length, bytes}; map = header copy (16) +
// nextResMap(4) + refNum(2) + attrs(2) + typeListOffset(2) + nameListOffset(2);
// type list = u16 (numTypes-1) then {type(4), numRes-1 (2), refListOffset(2)};
// reference entries (12 bytes) = {id(2), nameOffset(2), attrs(1), dataOffset(3), handle(4)}.
static bool WalkResourceMap(ByteReader r, std::vector<BlkxEntry>& out) {
    uint32_t dataOff = r.U32(0), mapOff = r.U32(4), dataLen = r.U32(8), mapLen = r.U32(12);
    if (!r.Has(dataOff, dataLen) || !r.Has(mapOff, mapLen) || mapLen < 30) return false;
    if (!r.Has(mapOff + 24, 4)) return false;
    size_t typeList = mapOff + be16(r.p + mapOff + 24);
    size_t nameList = mapOff + be16(r.p + mapOff + 26);
    if (!r.Has(typeList, 2)) return false;
    uint32_t numTypes = be16(r.p + typeList) + 1u;
    size_t te = typeList + 2;
    for (uint32_t t = 0; t < numTypes; ++t, te += 8) {
        if (!r.Has(te, 8)) return false;
        bool isBlkx = r.Magic(te, "blkx", 4);
        uint32_t numRes = be16(r.p + te + 4) + 1u;
        size_t refList = typeList + be16(r.p + te + 6);
        if (!isBlkx) continue;
        for (uint32_t i = 0; i < numRes; ++i) {
            size_t re = refList + static_cast<size_t>(i) * 12;
            if (!r.Has(re, 12)) return false;
            BlkxEntry e;
            e.id = static_cast<int16_t>(be16(r.p + re));
            uint16_t nameOff = be16(r.p + re + 2);
            uint32_t dOff = (static_cast<uint32_t>(r.p[re + 5]) << 16) |
                            (static_cast<uint32_t>(r.p[re + 6]) << 8) | r.p[re + 7];
            size_t d = dataOff + dOff;
            if (!r.Has(d, 4)) return false;
            uint32_t len = r.U32(d);
            if (!r.Has(d + 4, len)) return false;
            e.mish.assign(r.p + d + 4, r.p + d + 4 + len);
            if (nameOff != 0xFFFF && r.Has(nameList + nameOff, 1)) {
                uint8_t nl = r.p[nameList + nameOff];
                if (r.Has(nameList + nameOff + 1, nl))
                    e.name.assign(reinterpret_cast<const char*>(r.p + nameList + nameOff + 1), nl);
            }
            out.push_back(std::move(e));
        }
    }
    return !out.empty();
}

// QEMU-style fallback: walk the data section and keep every blob that starts
// with the mish magic.
static bool ScanDataSection(ByteReader r, std::vector<BlkxEntry>& out) {
    uint32_t dataOff = r.U32(0), dataLen = r.U32(8);
    if (!r.Has(dataOff, dataLen)) return false;
    size_t p = dataOff, end = dataOff + dataLen;
    int idx = 0;
    while (p + 4 <= end) {
        uint32_t len = r.U32(p);
        p += 4;
        if (len == 0 || !r.Has(p, len)) break;
        if (r.Magic(p, "mish", 4)) {
            BlkxEntry e;
            e.id = idx++;
            e.name = Format("resource %d", idx);
            e.mish.assign(r.p + p, r.p + p + len);
            out.push_back(std::move(e));
        }
        p += len;
    }
    return !out.empty();
}

bool ParseBlkxResourceFork(const uint8_t* rsrc, size_t n, std::vector<BlkxEntry>& out, std::string& err) {
    out.clear();
    ByteReader r(rsrc, n);
    if (n < 16) { err = "resource fork too small"; return false; }
    std::vector<BlkxEntry> tmp;
    if (WalkResourceMap(r, tmp)) { out = std::move(tmp); return true; }
    tmp.clear();
    if (ScanDataSection(r, tmp)) { out = std::move(tmp); return true; }
    err = "resource fork carries no blkx resources";
    return false;
}

} // namespace dmg
