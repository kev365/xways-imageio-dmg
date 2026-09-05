#include "dmg_verify.h"
#include "dmg_util.h"

#include <windows.h>
#include <cstring>
#include <cstdio>

#include "miniz.h"   // mz_crc32: standard zlib CRC-32, the polynomial UDIF uses

namespace dmg {

constexpr uint32_t kChecksumCrc32 = 2;
constexpr size_t   kVerifyBuf = 4u << 20;

const char* CheckStatusName(CheckStatus s) {
    switch (s) {
        case CheckStatus::Ok:          return "OK";
        case CheckStatus::Mismatch:    return "MISMATCH";
        case CheckStatus::NoChecksum:  return "no checksum";
        case CheckStatus::Unsupported: return "unsupported checksum type";
        case CheckStatus::Cancelled:   return "cancelled";
    }
    return "?";
}

static uint32_t Crc32Update(uint32_t crc, const uint8_t* p, size_t n) {
    return static_cast<uint32_t>(mz_crc32(crc, p, n));
}

void VerifyDataFork(IByteSource& container, const Koly& koly, VerifyReport& r, const VerifyProgress& progress) {
    r.dataForkChecked = false;
    if (koly.dataChecksumType != kChecksumCrc32 || koly.dataChecksumBits != 32) return;   // nothing verifiable
    r.dataForkExpected = be32(koly.dataChecksum);
    const uint64_t start = koly.dataForkOffset, len = koly.dataForkLength;
    if (start > container.Size() || len > container.Size() - start) return;
    std::vector<uint8_t> buf(kVerifyBuf);
    uint32_t crc = 0;
    uint64_t done = 0;
    while (done < len) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(buf.size(), len - done));
        if (!container.ReadAt(start + done, buf.data(), want)) return;    // container unreadable: leave unchecked
        crc = Crc32Update(crc, buf.data(), want);
        done += want;
        r.bytesRead += want;
        if (progress && !progress(done, len)) { r.cancelled = true; return; }
    }
    r.dataForkActual = crc;
    r.dataForkChecked = true;
    r.dataForkOk = (crc == r.dataForkExpected);
}

void VerifyPartitions(UdifSource& udif, VerifyReport& r, const VerifyProgress& progress) {
    const BlockMap& bm = udif.Map();
    const Koly& koly = udif.Trailer();
    r.partitions.clear();
    r.ok = r.mismatch = r.unchecked = 0;

    // Total work = bytes of every non-ignore chunk with a real partition.
    uint64_t total = 0, done = 0;
    for (const Chunk& c : bm.chunks)
        if (c.partition >= 0 && !c.synthetic && c.type != kChunkIgnore) total += c.Bytes();

    std::vector<uint8_t> buf(kVerifyBuf);
    std::vector<uint32_t> partCrc(bm.partitions.size(), 0);
    std::vector<bool> partHasData(bm.partitions.size(), false);

    // Chunks are sorted by sector and each partition's chunks are contiguous
    // in that order, which is the order hdiutil accumulated the CRC in.
    for (const Chunk& c : bm.chunks) {
        if (c.partition < 0 || c.synthetic || c.type == kChunkIgnore) continue;
        const size_t pi = static_cast<size_t>(c.partition);
        if (pi >= partCrc.size()) continue;   // defensive: never seen, but a bad map must not corrupt the heap
        uint64_t ofs = c.sector * kSectorSize;
        uint64_t left = c.Bytes();
        while (left) {
            const uint64_t want = std::min<uint64_t>(buf.size(), left);
            std::string err;
            const uint64_t got = udif.Read(ofs, buf.data(), want, false, nullptr, &err);
            if (got != want) { left = 0; break; }               // reader already zero-filled/recorded; CRC will mismatch
            partCrc[pi] = Crc32Update(partCrc[pi], buf.data(), static_cast<size_t>(want));
            partHasData[pi] = true;
            ofs += want; left -= want; done += want; r.bytesRead += want;
            if (progress && !progress(done, total)) { r.cancelled = true; break; }
        }
        if (r.cancelled) break;
    }

    std::string masterInput;
    for (size_t i = 0; i < bm.partitions.size(); ++i) {
        const Partition& p = bm.partitions[i];
        PartitionCheck pc;
        pc.index = i; pc.name = p.name; pc.checksumType = p.checksumType;
        pc.expected = be32(p.checksum);
        pc.actual = partCrc[i];
        // the master checksum is over the recorded 4-byte values, whatever we think of them
        masterInput.append(reinterpret_cast<const char*>(p.checksum), 4);
        if (r.cancelled) pc.status = CheckStatus::Cancelled;
        else if (p.checksumType != kChecksumCrc32 || p.checksumBits != 32) { pc.status = CheckStatus::Unsupported; ++r.unchecked; }
        else if (!partHasData[i] && pc.expected == 0) { pc.status = CheckStatus::NoChecksum; ++r.unchecked; }   // all-unallocated partition
        else if (pc.actual == pc.expected) { pc.status = CheckStatus::Ok; ++r.ok; }
        else { pc.status = CheckStatus::Mismatch; ++r.mismatch; }
        for (const Chunk& c : bm.chunks) if (c.partition == static_cast<int32_t>(i) && c.type != kChunkIgnore) pc.bytesChecked += c.Bytes();
        r.partitions.push_back(pc);
    }

    r.masterChecked = false;
    if (!r.cancelled && koly.masterChecksumType == kChecksumCrc32 && koly.masterChecksumBits == 32) {
        r.masterExpected = be32(koly.masterChecksum);
        r.masterActual = Crc32Update(0, reinterpret_cast<const uint8_t*>(masterInput.data()), masterInput.size());
        r.masterChecked = true;
        r.masterOk = (r.masterActual == r.masterExpected);
    }
}

VerifyReport VerifyAll(IByteSource& container, UdifSource& udif, const VerifyProgress& progress) {
    VerifyReport r;
    const ULONGLONG t0 = GetTickCount64();
    VerifyDataFork(container, udif.Trailer(), r, progress);
    if (!r.cancelled) VerifyPartitions(udif, r, progress);
    r.seconds = (GetTickCount64() - t0) / 1000.0;
    return r;
}

std::string VerifyReport::Summary() const {
    if (cancelled) return "checksum verification cancelled";
    std::string s;
    if (AnyMismatch()) {
        s = "CHECKSUM FAILURE:";
        for (const auto& p : partitions)
            if (p.status == CheckStatus::Mismatch)
                s += Format(" partition %zu '%s' expected %08X got %08X;", p.index, p.name.c_str(), p.expected, p.actual);
        if (dataForkChecked && !dataForkOk) s += Format(" data fork expected %08X got %08X;", dataForkExpected, dataForkActual);
        if (masterChecked && !masterOk) s += Format(" master expected %08X got %08X;", masterExpected, masterActual);
        if (!s.empty() && s.back() == ';') s.pop_back();
    } else {
        s = Format("checksums OK: %zu/%zu partitions", ok, ok + mismatch);
        if (unchecked) s += Format(" (%zu without checksum)", unchecked);
        if (dataForkChecked) s += ", data fork";
        if (masterChecked) s += ", master";
    }
    s += Format(" (%llu MiB read in %.1f s)", (unsigned long long)(bytesRead >> 20), seconds);
    return s;
}

std::string VerifyReport::Detail() const {
    std::string s;
    for (const auto& p : partitions)
        s += Format("partition %zu %-46s type=%u expected=%08X actual=%08X bytes=%llu  %s\n", p.index, p.name.c_str(), p.checksumType,
                    p.expected, p.actual, (unsigned long long)p.bytesChecked, CheckStatusName(p.status));
    if (dataForkChecked) s += Format("data fork (compressed)  expected=%08X actual=%08X  %s\n", dataForkExpected, dataForkActual, dataForkOk ? "OK" : "MISMATCH");
    else s += "data fork: no verifiable checksum\n";
    if (masterChecked) s += Format("master (over partition CRCs) expected=%08X actual=%08X  %s\n", masterExpected, masterActual, masterOk ? "OK" : "MISMATCH");
    else s += "master: no verifiable checksum\n";
    return s;
}

} // namespace dmg
