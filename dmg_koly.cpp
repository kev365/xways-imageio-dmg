#include "dmg_koly.h"
#include "dmg_util.h"

namespace dmg {

bool ParseKoly(const uint8_t* p, Koly& k, std::string& err) {
    ByteReader r(p, kKolySize);
    if (!r.Magic(0, "koly", 4)) { err = "no koly magic"; return false; }
    k.version               = r.U32(4);
    k.headerSize            = r.U32(8);
    k.flags                 = r.U32(12);
    k.runningDataForkOffset = r.U64(16);
    k.dataForkOffset        = r.U64(24);
    k.dataForkLength        = r.U64(32);
    k.rsrcForkOffset        = r.U64(40);
    k.rsrcForkLength        = r.U64(48);
    k.segmentNumber         = r.U32(56);
    k.segmentCount          = r.U32(60);
    std::memcpy(k.segmentId, p + 64, 16);
    k.dataChecksumType      = r.U32(80);
    k.dataChecksumBits      = r.U32(84);
    std::memcpy(k.dataChecksum, p + 88, 128);
    k.xmlOffset             = r.U64(216);
    k.xmlLength             = r.U64(224);
    k.masterChecksumType    = r.U32(352);
    k.masterChecksumBits    = r.U32(356);
    std::memcpy(k.masterChecksum, p + 360, 128);
    k.imageVariant          = r.U32(488);
    k.sectorCount           = r.U64(492);
    return true;
}

bool ValidateKoly(const Koly& k, uint64_t fileSize, std::string& err) {
    if (k.headerSize != kKolySize) {
        err = Format("koly HeaderSize %u (expected 512)", k.headerSize);
        return false;
    }
    if (k.dataForkOffset > fileSize || k.dataForkLength > fileSize - k.dataForkOffset) {
        err = "koly data fork extends past end of file";
        return false;
    }
    if (k.xmlLength && (k.xmlOffset > fileSize || k.xmlLength > fileSize - k.xmlOffset)) {
        err = "koly XML plist extends past end of file";
        return false;
    }
    if (k.rsrcForkLength && (k.rsrcForkOffset > fileSize || k.rsrcForkLength > fileSize - k.rsrcForkOffset)) {
        err = "koly resource fork extends past end of file";
        return false;
    }
    if (k.xmlLength > (64ull << 20)) {
        err = "koly XML plist implausibly large";
        return false;
    }
    return true;
}

} // namespace dmg
