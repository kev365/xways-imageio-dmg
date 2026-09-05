// dmg_verify.h — UDIF integrity verification against the checksums the
// container carries.
//
// A UDIF image records three CRC32 values (checksum type 2 is the only one
// hdiutil emits):
//   * per partition, in each mish table: CRC32 over the *decoded* bytes of
//     every chunk of that partition except type 2 (unallocated); zero-fill
//     chunks are included as zeros. A partition made only of unallocated
//     chunks records 0x00000000 ("nothing to check").
//   * koly DataChecksum: CRC32 over the compressed data fork as stored.
//   * koly master checksum: CRC32 over the concatenation of the partitions'
//     4-byte CRCs, in blkx order.
// All three were confirmed byte-for-byte against hdiutil output on
// 2026-09-05 (hdiutil zlib/LZFSE/ADC images, a 1.5 GB LibreOffice image).
//
// The partition check is the one that matters forensically: it proves the
// bytes X-Ways sees are the bytes hdiutil wrote. The data-fork check is a
// cheap container-integrity test (no decoding). Verification only reads.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "byte_source.h"
#include "dmg_koly.h"
#include "udif_source.h"

namespace dmg {

// Progress callback: return false to cancel.
using VerifyProgress = std::function<bool(uint64_t done, uint64_t total)>;

enum class CheckStatus { Ok, Mismatch, NoChecksum, Unsupported, Cancelled };

struct PartitionCheck {
    size_t index = 0;
    std::string name;
    uint32_t checksumType = 0;
    uint32_t expected = 0;
    uint32_t actual = 0;
    uint64_t bytesChecked = 0;
    CheckStatus status = CheckStatus::NoChecksum;
};

struct VerifyReport {
    std::vector<PartitionCheck> partitions;
    size_t ok = 0, mismatch = 0, unchecked = 0;   // partitions
    bool dataForkChecked = false, dataForkOk = false;
    uint32_t dataForkExpected = 0, dataForkActual = 0;
    bool masterChecked = false, masterOk = false;
    uint32_t masterExpected = 0, masterActual = 0;
    bool cancelled = false;
    uint64_t bytesRead = 0;
    double seconds = 0;

    bool AnyMismatch() const { return mismatch > 0 || (dataForkChecked && !dataForkOk) || (masterChecked && !masterOk); }
    // One line for the Messages window / description, e.g.
    // "checksums OK: 8/8 partitions, data fork, master (48 MiB in 0.3 s)".
    std::string Summary() const;
    // Multi-line detail for reports and the harness.
    std::string Detail() const;
};

const char* CheckStatusName(CheckStatus s);

// CRC32 of the compressed data fork vs koly.dataChecksum. `container` is the
// byte source the koly offsets refer to (the file, the decrypted plaintext,
// or the concatenated segment fork).
void VerifyDataFork(IByteSource& container, const Koly& koly, VerifyReport& r, const VerifyProgress& progress = nullptr);

// Per-partition CRC32 over decoded chunks (skips type-2 chunks), plus the
// master checksum, using the reader's block map and cache.
void VerifyPartitions(UdifSource& udif, VerifyReport& r, const VerifyProgress& progress = nullptr);

// Convenience: everything.
VerifyReport VerifyAll(IByteSource& container, UdifSource& udif, const VerifyProgress& progress = nullptr);

} // namespace dmg
