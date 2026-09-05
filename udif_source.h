// udif_source.h — random-access reads over a UDIF (.dmg) container.
//
// UdifSource wraps any IByteSource that holds a UDIF file (a plain file, an
// EncryptedSource, or a segmented data fork), parses the koly trailer and
// block map once,
// and serves byte-range reads by decoding the chunks that cover the range.
// Decoded chunks go through a byte-capped LRU cache; a request that covers a
// whole chunk is decoded straight into the caller's buffer instead, so
// sequential hashing / refinement does not churn the cache.
#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "byte_source.h"
#include "dmg_blockmap.h"
#include "dmg_koly.h"
#include "dmg_plist.h"
#include "image_reader.h"

namespace dmg {

// One chunk the reader could not deliver and served as zeros instead. The
// evidence file is never touched; this is a substitution in the *presented*
// sector array, and every one is recorded so the examiner can be told.
struct Substitution {
    size_t   chunk = 0;
    uint64_t sector = 0;       // first sector of the chunk
    uint64_t count = 0;        // sectors substituted
    uint32_t type = 0;         // ChunkType
    std::string reason;        // decoder / read error text
    bool     ioError = false;  // true = the container itself could not be read
};

struct UdifOptions {
    size_t cacheBytes = 128u << 20;     // decoded-chunk LRU cap
    BlockMapLimits limits;
    // Called (on the reading thread) the first time each chunk is substituted.
    std::function<void(const Substitution&)> onSubstitution;
};

struct UdifStats {
    volatile LONG64 reads = 0;
    volatile LONG64 bytesOut = 0;
    volatile LONG64 cacheHits = 0;
    volatile LONG64 cacheMisses = 0;
    volatile LONG64 directDecodes = 0;
    volatile LONG64 sparseAnswers = 0;
    volatile LONG64 decodeErrors = 0;
    volatile LONG64 substitutedChunks = 0;    // distinct chunks served as zeros
    volatile LONG64 substitutedSectors = 0;
};

class ChunkCache {
public:
    using Data = std::shared_ptr<std::vector<uint8_t>>;
    explicit ChunkCache(size_t capBytes);
    ~ChunkCache();
    Data Get(size_t idx);
    void Put(size_t idx, Data data);
    size_t Used() const { return used_; }
private:
    struct Node { size_t idx; Data data; };
    CRITICAL_SECTION cs_;
    size_t cap_;
    size_t used_ = 0;
    std::list<Node> lru_;                                   // front = most recent
    std::unordered_map<size_t, std::list<Node>::iterator> map_;
};

class UdifSource : public IByteSource, public IImageReader {
public:
    // Parses the trailer and block map. `warnings` receives non-fatal notes.
    static std::unique_ptr<UdifSource> Open(std::shared_ptr<IByteSource> inner, const UdifOptions& opts,
                                            std::string& err, std::vector<std::string>& warnings);

    // Segmented image: `dataFork` is the logical (concatenated) data fork,
    // `koly` the trailer of the segment carrying the block map, and `mapBytes`
    // that segment's XML plist (or resource fork when `mapIsRsrc`).
    static std::unique_ptr<UdifSource> OpenSegmented(std::shared_ptr<IByteSource> dataFork, const Koly& koly,
                                                     const std::vector<uint8_t>& mapBytes, bool mapIsRsrc,
                                                     const UdifOptions& opts, std::string& err,
                                                     std::vector<std::string>& warnings);

    ~UdifSource() override;
    uint64_t Size() const override { return map_.totalSectors * kSectorSize; }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override;

    // Partial read: returns bytes transferred (short at end of image, or on a
    // decode error after logging via `err`). When `checkSparse` is set and the
    // whole range is zero-fill, nothing is written, `*sparse` is set, and the
    // full `len` is returned.
    uint64_t Read(uint64_t ofs, void* buf, uint64_t len, bool checkSparse, bool* sparse, std::string* err) override;

    const Koly& Trailer() const { return koly_; }
    const BlockMap& Map() const { return map_; }
    const UdifStats* Stats() const override { return &stats_; }
    // Copy of the recorded substitutions (bounded to the first 256; the
    // counters in Stats() are exact).
    std::vector<Substitution> Substitutions() const;
    const std::string& Source() const { return sourceKind_; }   // "xml" or "rsrc"

private:
    UdifSource(std::shared_ptr<IByteSource> inner, size_t cacheBytes) : inner_(std::move(inner)), cache_(cacheBytes) {
        InitializeCriticalSection(&subsLock_);   // must cover Open and OpenSegmented alike
    }
    bool DecodeChunkInto(const Chunk& c, uint8_t* out, std::string& err);
    static std::unique_ptr<UdifSource> Finish(std::unique_ptr<UdifSource> u, const std::vector<BlkxEntry>& entries,
                                              uint64_t payloadSize, const UdifOptions& opts, std::string& err,
                                              std::vector<std::string>& warnings);

    std::shared_ptr<IByteSource> inner_;
    Koly koly_;
    BlockMap map_;
    ChunkCache cache_;
    UdifStats stats_;
    std::string sourceKind_;
    std::function<void(const Substitution&)> onSubstitution_;
    // Chunks that already failed: served as zeros without retrying the decoder,
    // and reported once. Guarded by subsLock_.
    mutable CRITICAL_SECTION subsLock_;
    std::set<size_t> failedChunks_;
    std::vector<Substitution> subs_;
    bool RecordSubstitution(size_t idx, const Chunk& c, const std::string& reason, bool ioError);
    bool AlreadyFailed(size_t idx) const;
};

} // namespace dmg
