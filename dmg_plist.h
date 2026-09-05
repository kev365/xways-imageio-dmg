// dmg_plist.h — pulls the blkx partition entries out of the UDIF XML plist.
//
// A deliberately minimal XML walker: it scopes to <key>blkx</key><array>,
// walks each <dict>, and collects Name / CFName / ID / Attributes / Data.
// The sibling <key>plst</key> array (and anything else) is ignored. No XML
// library is involved; the plist that hdiutil writes is regular enough.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dmg {

struct BlkxEntry {
    std::string name;            // e.g. "disk image (Apple_APFS : 4)"
    int64_t id = -1;
    std::string attributes;      // e.g. "0x0050"
    std::vector<uint8_t> mish;   // decoded <data> blob (a mish block)
};

bool ParseBlkxPlist(const char* xml, size_t n, std::vector<BlkxEntry>& out, std::string& err);

} // namespace dmg
