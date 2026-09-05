// dmg_rsrc.h — blkx block map from a classic binary resource fork.
//
// Old (pre-10.4-era) UDIF images carry the block map only as a Macintosh
// resource fork (koly RsrcForkOffset/Length) instead of an XML plist.
// The approach follows QEMU's block/dmg.c (dmg_read_resource_fork, MIT
// licensed: Copyright (c) 2004 Johannes E. Schindelin) but walks the
// resource map by type so only 'blkx' resources are taken; it falls back to
// QEMU's sequential scan of the data section when the map is unusable.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dmg_plist.h"   // BlkxEntry

namespace dmg {

bool ParseBlkxResourceFork(const uint8_t* rsrc, size_t n, std::vector<BlkxEntry>& out, std::string& err);

} // namespace dmg
