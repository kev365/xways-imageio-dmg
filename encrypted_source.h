// encrypted_source.h — Apple encrypted disk image ("encrcdsa" v2) layer.
//
// An encrypted DMG is a plain header followed by AES-CBC ciphertext in
// bytesPerBlock (observed: 512) blocks, each with its own IV =
// HMAC-SHA1(hmacKey, big-endian block number)[:blockIvLen]. The AES key and
// the HMAC key are wrapped in a 3DES-CBC blob protected by a PBKDF2-SHA1
// derived key. The plaintext is either a UDIF image (koly trailer at the end,
// compressed variants) or a bare disk/volume (read-write variants).
//
// Everything cryptographic goes through Windows CNG (bcrypt.dll) — no vendored
// crypto. Layout reference: nlitsme/encrypteddmg (MIT) and the real hdiutil
// samples (macOS 12.7.6, 2026-09-03).
#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "byte_source.h"

namespace dmg {

constexpr size_t kEncHeaderMin = 0x4C;

struct EncPassItem {
    uint32_t kdfAlgorithm = 0;      // 0x67 = PBKDF2
    uint64_t iterations = 0;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> blobIv;    // 8 bytes for 3DES
    uint32_t blobKeyBits = 0;       // 192
    uint32_t blobAlgorithm = 0;     // 0x11 = 3DES
    uint32_t blobPadding = 0;       // 7 = PKCS7
    uint32_t blobMode = 0;          // 6 = CBC
    std::vector<uint8_t> blob;      // wrapped {aesKey | hmacKey | "CKIE\0"} + PKCS7
};

struct EncHeader {
    uint32_t version = 0;           // 2
    uint32_t blockIvLen = 0;        // 16
    uint32_t blockMode = 0;         // 5 = CBC
    uint32_t blockAlgorithm = 0;    // 0x80000001 = AES
    uint32_t keyBits = 0;           // 128 / 256
    uint32_t ivKeyAlgorithm = 0;    // 0x5B = HMAC-SHA1
    uint32_t ivKeyBits = 0;         // 160
    uint8_t  uuid[16] = {};
    uint32_t bytesPerBlock = 0;     // 512
    uint64_t dataLen = 0;           // plaintext length
    uint64_t dataOffset = 0;        // first cipher block
    uint32_t itemCount = 0;
    std::vector<EncPassItem> passItems;   // itemtype 1 entries
    int otherItems = 0;                   // certificate / keybag entries we cannot use
};

struct EncKeys {
    std::vector<uint8_t> aesKey;
    std::vector<uint8_t> hmacKey;
    bool trailerVerified = false;   // "CKIE" marker seen in the unwrapped blob
};

bool IsEncryptedV2Header(const uint8_t* p, size_t n);    // "encrcdsa"
bool IsEncryptedV1Trailer(const uint8_t* tail8);          // "cdsaencr"

// Parses the header from the start of `src`. Fails on unsupported parameters.
bool ParseEncHeader(IByteSource& src, EncHeader& out, std::string& err);

// PBKDF2 → 3DES unwrap → key split. Returns false with err = "wrong password"
// when the blob does not decrypt to a well-formed key blob.
bool UnlockWithPassword(const EncHeader& h, const std::string& passwordUtf8, EncKeys& out, std::string& err);

std::string EncSummary(const EncHeader& h);   // e.g. "AES-256, 512-byte blocks, PBKDF2 238095 iterations"
std::string UuidString(const uint8_t uuid[16]);

// Decrypting byte source. Size() == header.dataLen. Thread-safe (one CNG
// context, guarded by a critical section; AES on 512-byte blocks is far
// cheaper than the chunk decompression above it).
class EncryptedSource : public IByteSource {
public:
    // `ivPeriodBlocks` > 0 makes the IV block number restart every that many
    // blocks — sparse bundles encrypt each band file independently, so the
    // period is bandSize / bytesPerBlock. 0 = continuous numbering (files).
    static std::shared_ptr<EncryptedSource> Create(std::shared_ptr<IByteSource> inner, const EncHeader& h,
                                                   const EncKeys& keys, std::string& err, uint64_t ivPeriodBlocks = 0);
    ~EncryptedSource() override;
    uint64_t Size() const override { return hdr_.dataLen; }
    bool ReadAt(uint64_t ofs, void* buf, size_t len) override;
    const EncHeader& Header() const { return hdr_; }

    // Cheap plausibility check on the decrypted bytes: koly trailer, GPT / MBR
    // / HFS+ / APFS signatures. Used to confirm a password whose blob lacked
    // the "CKIE" marker.
    bool PlaintextLooksValid(std::string& what);

private:
    EncryptedSource() = default;
    bool DecryptBlocks(uint64_t firstBlock, uint64_t count, uint8_t* inout);

    std::shared_ptr<IByteSource> inner_;
    EncHeader hdr_;
    uint64_t ivPeriod_ = 0;
    std::vector<uint8_t> hmacKey_;
    BCRYPT_ALG_HANDLE hAes_ = nullptr;
    BCRYPT_KEY_HANDLE hAesKey_ = nullptr;
    BCRYPT_ALG_HANDLE hHmac_ = nullptr;
    BCRYPT_HASH_HANDLE hHash_ = nullptr;   // reusable HMAC object
    CRITICAL_SECTION cs_;
    bool csInit_ = false;
};

} // namespace dmg
