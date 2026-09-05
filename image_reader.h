// image_reader.h — what IIO_Work talks to, whatever the container turned out to be.
//
//   UdifSource      : compressed UDIF (plain or decrypted) — chunk map + cache
//   RawImageReader  : a bare disk/volume, e.g. the plaintext of an encrypted
//                     read-write image (no koly trailer, nothing to decode)
#pragma once

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "byte_source.h"

namespace dmg {

struct UdifStats;

struct IImageReader {
    virtual ~IImageReader() = default;
    virtual uint64_t Size() const = 0;
    // Returns bytes transferred (short at end of image or on error, with `err`
    // set). With `checkSparse`, an all-zero range sets `*sparse` and returns
    // `len` without touching the buffer.
    virtual uint64_t Read(uint64_t ofs, void* buf, uint64_t len, bool checkSparse, bool* sparse, std::string* err) = 0;
    virtual const UdifStats* Stats() const { return nullptr; }
};

class RawImageReader : public IImageReader {
public:
    explicit RawImageReader(std::shared_ptr<IByteSource> src) : src_(std::move(src)) {}
    uint64_t Size() const override { return src_->Size(); }
    uint64_t Read(uint64_t ofs, void* buf, uint64_t len, bool /*checkSparse*/, bool* sparse, std::string* err) override {
        if (sparse) *sparse = false;
        const uint64_t size = src_->Size();
        if (ofs >= size || len == 0) return 0;
        if (len > size - ofs) len = size - ofs;
        if (!src_->ReadAt(ofs, buf, static_cast<size_t>(len))) {
            if (err) *err = "read failed";
            return 0;
        }
        return len;
    }
private:
    std::shared_ptr<IByteSource> src_;
};

} // namespace dmg
