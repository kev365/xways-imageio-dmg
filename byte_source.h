// byte_source.h — the byte-source abstraction every DMG layer is built on.
//
//   IIO_Work -> UdifSource (chunk map + decoders + cache) -> RawFileSource
//                                                         -> EncryptedSource(RawFileSource)
//            -> SparseImageSource / SparseBundleSource
//
// Every source is thread-safe and stateless per call: ReadAt() is a
// positional read, there is no shared file pointer.
#pragma once

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace dmg {

struct IByteSource {
    virtual ~IByteSource() = default;
    virtual uint64_t Size() const = 0;
    // Reads exactly `len` bytes at `ofs`. Returns false on a short read or error.
    virtual bool ReadAt(uint64_t ofs, void* buf, size_t len) = 0;
    // True when the whole range has no backing storage (an unallocated band of
    // a sparse image / bundle). ReadAt returns zeros there; an encryption layer
    // above must pass those zeros through instead of "decrypting" them.
    virtual bool IsUnallocated(uint64_t /*ofs*/, size_t /*len*/) const { return false; }
};

// Plain file on disk, opened with full sharing so the analyst (and X-Ways'
// own parsers) can keep the file open concurrently.
class RawFileSource : public IByteSource {
public:
    static std::shared_ptr<RawFileSource> Open(const wchar_t* path, std::string& err) {
        HANDLE h = CreateFileW(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            err = "CreateFileW failed, gle=" + std::to_string(GetLastError());
            return nullptr;
        }
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) {
            err = "GetFileSizeEx failed, gle=" + std::to_string(GetLastError());
            CloseHandle(h);
            return nullptr;
        }
        auto src = std::shared_ptr<RawFileSource>(new RawFileSource());
        src->h_ = h;
        src->size_ = static_cast<uint64_t>(sz.QuadPart);
        return src;
    }
    ~RawFileSource() override { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    uint64_t Size() const override { return size_; }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override {
        if (len == 0) return true;
        if (ofs > size_ || len > size_ - ofs) return false;
        uint8_t* p = static_cast<uint8_t*>(buf);
        size_t done = 0;
        while (done < len) {
            OVERLAPPED ov{};
            uint64_t pos = ofs + done;
            ov.Offset = static_cast<DWORD>(pos & 0xFFFFFFFFu);
            ov.OffsetHigh = static_cast<DWORD>(pos >> 32);
            DWORD want = static_cast<DWORD>((len - done) > 0x40000000u ? 0x40000000u : (len - done));
            DWORD got = 0;
            if (!ReadFile(h_, p + done, want, &got, &ov) || got == 0) return false;
            done += got;
        }
        return true;
    }
private:
    RawFileSource() = default;
    HANDLE h_ = INVALID_HANDLE_VALUE;
    uint64_t size_ = 0;
};

// In-memory source, used by the harness and unit tests.
class MemorySource : public IByteSource {
public:
    explicit MemorySource(std::vector<uint8_t> data) : data_(std::move(data)) {}
    uint64_t Size() const override { return data_.size(); }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override {
        if (ofs > data_.size() || len > data_.size() - ofs) return false;
        std::memcpy(buf, data_.data() + ofs, len);
        return true;
    }
private:
    std::vector<uint8_t> data_;
};

} // namespace dmg
