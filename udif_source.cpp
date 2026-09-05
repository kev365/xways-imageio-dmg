#include "udif_source.h"
#include "dmg_decoder.h"
#include "dmg_rsrc.h"
#include "dmg_util.h"

#include <algorithm>
#include <cstring>

namespace dmg {

// ---------------------------------------------------------------------------
//  ChunkCache
// ---------------------------------------------------------------------------

ChunkCache::ChunkCache(size_t capBytes) : cap_(capBytes) { InitializeCriticalSection(&cs_); }
ChunkCache::~ChunkCache() { DeleteCriticalSection(&cs_); }

ChunkCache::Data ChunkCache::Get(size_t idx) {
    EnterCriticalSection(&cs_);
    Data d;
    auto it = map_.find(idx);
    if (it != map_.end()) {
        lru_.splice(lru_.begin(), lru_, it->second);   // move to front
        d = it->second->data;
    }
    LeaveCriticalSection(&cs_);
    return d;
}

void ChunkCache::Put(size_t idx, Data data) {
    if (!data || data->size() > cap_) return;
    EnterCriticalSection(&cs_);
    auto it = map_.find(idx);
    if (it != map_.end()) {                              // another thread won the race
        lru_.splice(lru_.begin(), lru_, it->second);
        LeaveCriticalSection(&cs_);
        return;
    }
    while (used_ + data->size() > cap_ && !lru_.empty()) {
        Node& victim = lru_.back();
        used_ -= victim.data->size();
        map_.erase(victim.idx);
        lru_.pop_back();
    }
    used_ += data->size();
    lru_.push_front(Node{idx, std::move(data)});
    map_[idx] = lru_.begin();
    LeaveCriticalSection(&cs_);
}

// ---------------------------------------------------------------------------
//  UdifSource
// ---------------------------------------------------------------------------

std::unique_ptr<UdifSource> UdifSource::Open(std::shared_ptr<IByteSource> inner, const UdifOptions& opts,
                                             std::string& err, std::vector<std::string>& warnings) {
    if (!inner) { err = "no inner source"; return nullptr; }
    const uint64_t size = inner->Size();
    if (size < kKolySize) { err = "file smaller than a koly trailer"; return nullptr; }

    uint8_t trailer[kKolySize];
    if (!inner->ReadAt(size - kKolySize, trailer, kKolySize)) { err = "cannot read trailer"; return nullptr; }

    std::unique_ptr<UdifSource> u(new UdifSource(std::move(inner), opts.cacheBytes));
    u->onSubstitution_ = opts.onSubstitution;
    if (!ParseKoly(trailer, u->koly_, err)) return nullptr;
    if (!ValidateKoly(u->koly_, size, err)) return nullptr;
    if (u->koly_.segmentCount > 1) {
        err = Format("segmented image (segment %u of %u): use OpenSegmented", u->koly_.segmentNumber, u->koly_.segmentCount);
        return nullptr;
    }

    std::vector<BlkxEntry> entries;
    if (u->koly_.xmlLength) {
        std::vector<char> xml(static_cast<size_t>(u->koly_.xmlLength));
        if (!u->inner_->ReadAt(u->koly_.xmlOffset, xml.data(), xml.size())) { err = "cannot read XML plist"; return nullptr; }
        if (!ParseBlkxPlist(xml.data(), xml.size(), entries, err)) return nullptr;
        u->sourceKind_ = "xml";
    } else if (u->koly_.rsrcForkLength) {
        if (u->koly_.rsrcForkLength > (64ull << 20)) { err = "resource fork implausibly large"; return nullptr; }
        std::vector<uint8_t> rs(static_cast<size_t>(u->koly_.rsrcForkLength));
        if (!u->inner_->ReadAt(u->koly_.rsrcForkOffset, rs.data(), rs.size())) { err = "cannot read resource fork"; return nullptr; }
        if (!ParseBlkxResourceFork(rs.data(), rs.size(), entries, err)) return nullptr;
        u->sourceKind_ = "rsrc";
    } else {
        err = "image has neither an XML plist nor a resource fork";
        return nullptr;
    }

    return Finish(std::move(u), entries, size, opts, err, warnings);
}

std::unique_ptr<UdifSource> UdifSource::OpenSegmented(std::shared_ptr<IByteSource> dataFork, const Koly& koly,
                                                      const std::vector<uint8_t>& mapBytes, bool mapIsRsrc,
                                                      const UdifOptions& opts, std::string& err,
                                                      std::vector<std::string>& warnings) {
    if (!dataFork) { err = "no data fork"; return nullptr; }
    std::unique_ptr<UdifSource> u(new UdifSource(dataFork, opts.cacheBytes));
    u->koly_ = koly;
    // Chunk offsets are relative to the logical data fork, which is exactly
    // what `dataFork` presents — so the fork starts at 0 and spans it all.
    u->koly_.dataForkOffset = 0;
    u->koly_.dataForkLength = dataFork->Size();
    std::vector<BlkxEntry> entries;
    if (mapIsRsrc) {
        if (!ParseBlkxResourceFork(mapBytes.data(), mapBytes.size(), entries, err)) return nullptr;
        u->sourceKind_ = "rsrc (segmented)";
    } else {
        if (!ParseBlkxPlist(reinterpret_cast<const char*>(mapBytes.data()), mapBytes.size(), entries, err)) return nullptr;
        u->sourceKind_ = "xml (segmented)";
    }
    return Finish(std::move(u), entries, dataFork->Size(), opts, err, warnings);
}

std::unique_ptr<UdifSource> UdifSource::Finish(std::unique_ptr<UdifSource> u, const std::vector<BlkxEntry>& entries,
                                               uint64_t payloadSize, const UdifOptions& opts, std::string& err,
                                               std::vector<std::string>& warnings) {
    if (!BuildBlockMap(u->koly_, entries, payloadSize, opts.limits, u->map_, err)) return nullptr;
    for (const auto& kv : u->map_.typeCounts) {
        if (!ChunkTypeSupported(kv.first)) {
            err = Format("chunk type 0x%08X (%s) is not supported", kv.first, ChunkTypeName(kv.first));
            return nullptr;
        }
    }
    for (const auto& w : u->map_.warnings) warnings.push_back(w);
    DecoderGlobalInit();
    return u;
}

UdifSource::~UdifSource() { DeleteCriticalSection(&subsLock_); }

std::vector<Substitution> UdifSource::Substitutions() const {
    EnterCriticalSection(&subsLock_);
    std::vector<Substitution> copy = subs_;
    LeaveCriticalSection(&subsLock_);
    return copy;
}

bool UdifSource::AlreadyFailed(size_t idx) const {
    EnterCriticalSection(&subsLock_);
    bool f = failedChunks_.count(idx) != 0;
    LeaveCriticalSection(&subsLock_);
    return f;
}

// Returns true when this is the first failure of that chunk (caller notifies).
bool UdifSource::RecordSubstitution(size_t idx, const Chunk& c, const std::string& reason, bool ioError) {
    Substitution s;
    s.chunk = idx; s.sector = c.sector; s.count = c.count; s.type = c.type; s.reason = reason; s.ioError = ioError;
    EnterCriticalSection(&subsLock_);
    const bool first = failedChunks_.insert(idx).second;
    if (first) {
        if (subs_.size() < 256) subs_.push_back(s);
        InterlockedIncrement64(&stats_.substitutedChunks);
        InterlockedAdd64(&stats_.substitutedSectors, static_cast<LONG64>(c.count));
    }
    LeaveCriticalSection(&subsLock_);
    if (first && onSubstitution_) onSubstitution_(s);
    return first;
}

bool UdifSource::DecodeChunkInto(const Chunk& c, uint8_t* out, std::string& err) {
    const size_t outLen = static_cast<size_t>(c.Bytes());
    if (ChunkTypeIsZero(c.type)) { std::memset(out, 0, outLen); return true; }
    std::vector<uint8_t> comp(static_cast<size_t>(c.compLen));
    if (!inner_->ReadAt(c.fileOfs, comp.data(), comp.size())) {
        err = Format("read of %llu bytes at %llu failed", (unsigned long long)c.compLen, (unsigned long long)c.fileOfs);
        return false;
    }
    return DecodeChunk(c.type, comp.data(), comp.size(), out, outLen, err);
}

bool UdifSource::ReadAt(uint64_t ofs, void* buf, size_t len) {
    std::string err;
    return Read(ofs, buf, len, false, nullptr, &err) == len;
}

uint64_t UdifSource::Read(uint64_t ofs, void* buf, uint64_t len, bool checkSparse, bool* sparse, std::string* err) {
    if (sparse) *sparse = false;
    const uint64_t imageBytes = Size();
    if (ofs >= imageBytes || len == 0) return 0;
    if (len > imageBytes - ofs) len = imageBytes - ofs;
    InterlockedIncrement64(&stats_.reads);

    // Pass 1: is the whole range zero-fill? (cheap: binary searches only)
    if (checkSparse) {
        bool allZero = true;
        uint64_t pos = ofs, end = ofs + len;
        while (pos < end) {
            const Chunk& c = map_.chunks[map_.Find(pos / kSectorSize)];
            if (!ChunkTypeIsZero(c.type)) { allZero = false; break; }
            pos = c.End() * kSectorSize;
        }
        if (allZero) {
            if (sparse) *sparse = true;
            InterlockedIncrement64(&stats_.sparseAnswers);
            InterlockedAdd64(&stats_.bytesOut, static_cast<LONG64>(len));
            return len;
        }
    }

    uint8_t* out = static_cast<uint8_t*>(buf);
    uint64_t done = 0;
    while (done < len) {
        const uint64_t pos = ofs + done;
        const size_t idx = map_.Find(pos / kSectorSize);
        const Chunk& c = map_.chunks[idx];
        const uint64_t chunkStart = c.sector * kSectorSize;
        const uint64_t chunkBytes = c.Bytes();
        const uint64_t inChunk = pos - chunkStart;
        const uint64_t span = std::min<uint64_t>(len - done, chunkBytes - inChunk);

        if (ChunkTypeIsZero(c.type)) {
            std::memset(out + done, 0, static_cast<size_t>(span));
        } else if (inChunk == 0 && span == chunkBytes) {
            // Whole-chunk request: decode straight into the caller's buffer.
            std::string e;
            if (AlreadyFailed(idx) || !DecodeChunkInto(c, out + done, e)) {
                // Policy: a chunk that cannot be delivered is presented as zeros,
                // recorded, and reported once. X-Ways treats a short read as a
                // silent failure (verified 2026-09-05), so zeros + a notice are
                // the only way the examiner learns anything.
                std::memset(out + done, 0, static_cast<size_t>(span));
                if (!e.empty()) {
                    InterlockedIncrement64(&stats_.decodeErrors);
                    RecordSubstitution(idx, c, e, e.rfind("read of", 0) == 0);
                    if (err) *err = Format("chunk %zu (%s, sector %llu) substituted with zeros: %s", idx, ChunkTypeName(c.type), (unsigned long long)c.sector, e.c_str());
                }
            } else {
                InterlockedIncrement64(&stats_.directDecodes);
            }
        } else {
            ChunkCache::Data d = cache_.Get(idx);
            if (d) {
                InterlockedIncrement64(&stats_.cacheHits);
            } else {
                InterlockedIncrement64(&stats_.cacheMisses);
                d = std::make_shared<std::vector<uint8_t>>(static_cast<size_t>(chunkBytes));   // zero-initialised
                std::string e;
                if (AlreadyFailed(idx) || !DecodeChunkInto(c, d->data(), e)) {
                    std::memset(d->data(), 0, d->size());      // decoder may have written partial output
                    if (!e.empty()) {
                        InterlockedIncrement64(&stats_.decodeErrors);
                        RecordSubstitution(idx, c, e, e.rfind("read of", 0) == 0);
                        if (err) *err = Format("chunk %zu (%s, sector %llu) substituted with zeros: %s", idx, ChunkTypeName(c.type), (unsigned long long)c.sector, e.c_str());
                    }
                }
                cache_.Put(idx, d);   // cache the zeros too: no repeated decode attempts
            }
            std::memcpy(out + done, d->data() + inChunk, static_cast<size_t>(span));
        }
        done += span;
    }
    InterlockedAdd64(&stats_.bytesOut, static_cast<LONG64>(done));
    return done;
}

} // namespace dmg
