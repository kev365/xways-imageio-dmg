#include "encrypted_source.h"
#include "dmg_util.h"

#include <algorithm>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace dmg {

bool IsEncryptedV2Header(const uint8_t* p, size_t n) { return p && n >= 8 && std::memcmp(p, "encrcdsa", 8) == 0; }
bool IsEncryptedV1Trailer(const uint8_t* t) { return t && std::memcmp(t, "cdsaencr", 8) == 0; }

std::string UuidString(const uint8_t u[16]) {
    return Format("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                  u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

std::string EncSummary(const EncHeader& h) {
    std::string s = Format("encrypted (encrcdsa v%u): AES-%u CBC, %u-byte blocks", h.version, h.keyBits, h.bytesPerBlock);
    if (!h.passItems.empty()) s += Format(", PBKDF2-SHA1 %llu iterations", (unsigned long long)h.passItems[0].iterations);
    if (h.otherItems) s += Format(", %d non-passphrase key entr%s", h.otherItems, h.otherItems == 1 ? "y" : "ies");
    return s;
}

bool ParseEncHeader(IByteSource& src, EncHeader& h, std::string& err) {
    uint8_t hdr[0x4C];
    if (src.Size() < sizeof(hdr) || !src.ReadAt(0, hdr, sizeof(hdr))) { err = "cannot read encrypted header"; return false; }
    if (!IsEncryptedV2Header(hdr, sizeof(hdr))) { err = "no encrcdsa magic"; return false; }
    ByteReader r(hdr, sizeof(hdr));
    h.version        = r.U32(0x08);
    h.blockIvLen     = r.U32(0x0C);
    h.blockMode      = r.U32(0x10);
    h.blockAlgorithm = r.U32(0x14);
    h.keyBits        = r.U32(0x18);
    h.ivKeyAlgorithm = r.U32(0x1C);
    h.ivKeyBits      = r.U32(0x20);
    std::memcpy(h.uuid, hdr + 0x24, 16);
    h.bytesPerBlock  = r.U32(0x34);
    h.dataLen        = r.U64(0x38);
    h.dataOffset     = r.U64(0x40);
    h.itemCount      = r.U32(0x48);

    if (h.version != 2) { err = Format("encrcdsa version %u not supported", h.version); return false; }
    if (h.blockAlgorithm != 0x80000001u || h.blockMode != 5) {
        err = Format("cipher %08X mode %u not supported (expected AES-CBC)", h.blockAlgorithm, h.blockMode);
        return false;
    }
    if (h.keyBits != 128 && h.keyBits != 192 && h.keyBits != 256) { err = Format("AES key size %u not supported", h.keyBits); return false; }
    if (h.ivKeyAlgorithm != 0x5B) { err = Format("IV key algorithm %08X not supported (expected HMAC-SHA1)", h.ivKeyAlgorithm); return false; }
    if (h.blockIvLen != 16) { err = Format("block IV length %u not supported", h.blockIvLen); return false; }
    if (h.bytesPerBlock == 0 || (h.bytesPerBlock % 16) || h.bytesPerBlock > (1u << 20)) { err = Format("bytesPerBlock %u implausible", h.bytesPerBlock); return false; }
    // A sparse bundle's `token` holds only the header: dataOffset == its size and dataLen == 0.
    if (h.dataOffset > src.Size() || h.dataLen > src.Size() - h.dataOffset) { err = "encrypted payload extends past end of file"; return false; }
    if (h.itemCount > 64) { err = "implausible key entry count"; return false; }

    // Key entry table follows the fixed header: {itemtype u32, offset u64, size u64} x itemCount.
    std::vector<uint8_t> table(static_cast<size_t>(h.itemCount) * 20);
    if (!table.empty() && !src.ReadAt(0x4C, table.data(), table.size())) { err = "cannot read key entry table"; return false; }
    ByteReader tr(table.data(), table.size());
    for (uint32_t i = 0; i < h.itemCount; ++i) {
        uint32_t type = tr.U32(i * 20);
        uint64_t off = tr.U64(i * 20 + 4), size = tr.U64(i * 20 + 12);
        if (type != 1) { ++h.otherItems; continue; }
        if (size < 0x68 || size > 65536 || off > src.Size() || size > src.Size() - off) { err = "malformed passphrase key entry"; return false; }
        std::vector<uint8_t> item(static_cast<size_t>(size));
        if (!src.ReadAt(off, item.data(), item.size())) { err = "cannot read passphrase key entry"; return false; }
        ByteReader ir(item.data(), item.size());
        EncPassItem p;
        p.kdfAlgorithm = ir.U32(0x00);
        p.iterations   = ir.U64(0x04);
        uint32_t saltLen = ir.U32(0x0C);
        if (saltLen > 32) { err = "salt length > 32"; return false; }
        p.salt.assign(item.begin() + 0x10, item.begin() + 0x10 + saltLen);
        uint32_t ivLen = ir.U32(0x30);
        if (ivLen > 32) { err = "blob IV length > 32"; return false; }
        p.blobIv.assign(item.begin() + 0x34, item.begin() + 0x34 + ivLen);
        p.blobKeyBits   = ir.U32(0x54);
        p.blobAlgorithm = ir.U32(0x58);
        p.blobPadding   = ir.U32(0x5C);
        p.blobMode      = ir.U32(0x60);
        uint32_t blobLen = ir.U32(0x64);
        if (blobLen == 0 || (blobLen % 8) || !ir.Has(0x68, blobLen)) { err = "malformed wrapped key blob"; return false; }
        p.blob.assign(item.begin() + 0x68, item.begin() + 0x68 + blobLen);
        if (p.kdfAlgorithm != 0x67) { err = Format("KDF %08X not supported (expected PBKDF2)", p.kdfAlgorithm); return false; }
        if (p.blobAlgorithm != 0x11 || p.blobKeyBits != 192 || p.blobIv.size() < 8) { err = "key blob is not 3DES-192/CBC"; return false; }
        h.passItems.push_back(std::move(p));
    }
    if (h.passItems.empty()) {
        err = h.otherItems ? "image is protected by a certificate / keybag only (no passphrase entry)" : "no key entries";
        return false;
    }
    return true;
}

// --- CNG helpers -----------------------------------------------------------

namespace {

struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct KeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
};

bool OpenAlg(AlgHandle& a, LPCWSTR alg, ULONG flags, const wchar_t* chain, std::string& err) {
    NTSTATUS s = BCryptOpenAlgorithmProvider(&a.h, alg, nullptr, flags);
    if (!NT_SUCCESS(s)) { err = Format("BCryptOpenAlgorithmProvider failed 0x%08X", (unsigned)s); return false; }
    if (chain) {
        s = BCryptSetProperty(a.h, BCRYPT_CHAINING_MODE, (PUCHAR)chain, static_cast<ULONG>((wcslen(chain) + 1) * sizeof(wchar_t)), 0);
        if (!NT_SUCCESS(s)) { err = Format("BCryptSetProperty(chaining) failed 0x%08X", (unsigned)s); return false; }
    }
    return true;
}

// DES ignores the low bit of every key byte, but some providers insist on odd
// parity — normalise so the effective key is unchanged either way.
void FixDesParity(uint8_t* k, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        uint8_t b = k[i] & 0xFE;
        int bits = 0;
        for (int j = 1; j < 8; ++j) bits += (b >> j) & 1;
        k[i] = static_cast<uint8_t>(b | ((bits & 1) ? 0 : 1));
    }
}

} // namespace

bool UnlockWithPassword(const EncHeader& h, const std::string& password, EncKeys& out, std::string& err) {
    std::string lastErr = "wrong password";
    for (const EncPassItem& item : h.passItems) {
        // 1. PBKDF2-HMAC-SHA1 → 32 bytes
        AlgHandle hmacAlg;
        if (!OpenAlg(hmacAlg, BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG, nullptr, err)) return false;
        uint8_t derived[32];
        NTSTATUS s = BCryptDeriveKeyPBKDF2(hmacAlg.h, (PUCHAR)password.data(), static_cast<ULONG>(password.size()),
                                           (PUCHAR)item.salt.data(), static_cast<ULONG>(item.salt.size()),
                                           item.iterations, derived, sizeof(derived), 0);
        if (!NT_SUCCESS(s)) { err = Format("BCryptDeriveKeyPBKDF2 failed 0x%08X", (unsigned)s); return false; }

        // 2. 3DES-CBC unwrap of the key blob
        uint8_t desKey[24];
        std::memcpy(desKey, derived, 24);
        FixDesParity(desKey, 24);
        AlgHandle des;
        if (!OpenAlg(des, BCRYPT_3DES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_CBC, err)) return false;
        KeyHandle desKeyH;
        s = BCryptGenerateSymmetricKey(des.h, &desKeyH.h, nullptr, 0, desKey, sizeof(desKey), 0);
        if (!NT_SUCCESS(s)) { err = Format("3DES key import failed 0x%08X", (unsigned)s); return false; }
        uint8_t iv[8];
        std::memcpy(iv, item.blobIv.data(), 8);
        std::vector<uint8_t> plain(item.blob.size());
        ULONG got = 0;
        s = BCryptDecrypt(desKeyH.h, (PUCHAR)item.blob.data(), static_cast<ULONG>(item.blob.size()), nullptr, iv, 8,
                          plain.data(), static_cast<ULONG>(plain.size()), &got, 0);
        SecureZeroMemory(derived, sizeof(derived));
        SecureZeroMemory(desKey, sizeof(desKey));
        if (!NT_SUCCESS(s)) { err = Format("3DES decrypt failed 0x%08X", (unsigned)s); return false; }
        plain.resize(got);

        // 3. PKCS7 padding check — the password test. Then the optional "CKIE\0" marker.
        if (plain.empty()) { lastErr = "wrong password"; continue; }
        uint8_t pad = plain.back();
        if (pad < 1 || pad > 8 || pad > plain.size()) { lastErr = "wrong password"; continue; }
        bool padOk = true;
        for (size_t i = plain.size() - pad; i < plain.size(); ++i) padOk = padOk && plain[i] == pad;
        if (!padOk) { lastErr = "wrong password"; continue; }
        plain.resize(plain.size() - pad);

        EncKeys k;
        static const uint8_t kMarker[5] = {'C', 'K', 'I', 'E', 0};
        if (plain.size() >= 5 && std::memcmp(plain.data() + plain.size() - 5, kMarker, 5) == 0) {
            plain.resize(plain.size() - 5);
            k.trailerVerified = true;
        }
        const size_t aesLen = h.keyBits / 8;
        if (plain.size() < aesLen + 1) { lastErr = "wrong password"; continue; }
        k.aesKey.assign(plain.begin(), plain.begin() + aesLen);
        k.hmacKey.assign(plain.begin() + aesLen, plain.end());
        SecureZeroMemory(plain.data(), plain.size());
        out = std::move(k);
        return true;
    }
    err = lastErr;
    return false;
}

// --- EncryptedSource -------------------------------------------------------

std::shared_ptr<EncryptedSource> EncryptedSource::Create(std::shared_ptr<IByteSource> inner, const EncHeader& h,
                                                         const EncKeys& keys, std::string& err, uint64_t ivPeriodBlocks) {
    std::shared_ptr<EncryptedSource> e(new EncryptedSource());
    e->inner_ = std::move(inner);
    e->hdr_ = h;
    e->ivPeriod_ = ivPeriodBlocks;
    e->hmacKey_ = keys.hmacKey;
    InitializeCriticalSection(&e->cs_);
    e->csInit_ = true;

    NTSTATUS s = BCryptOpenAlgorithmProvider(&e->hAes_, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) { err = Format("AES provider failed 0x%08X", (unsigned)s); return nullptr; }
    s = BCryptSetProperty(e->hAes_, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(s)) { err = Format("AES CBC mode failed 0x%08X", (unsigned)s); return nullptr; }
    s = BCryptGenerateSymmetricKey(e->hAes_, &e->hAesKey_, nullptr, 0, (PUCHAR)keys.aesKey.data(),
                                   static_cast<ULONG>(keys.aesKey.size()), 0);
    if (!NT_SUCCESS(s)) { err = Format("AES key import failed 0x%08X", (unsigned)s); return nullptr; }
    s = BCryptOpenAlgorithmProvider(&e->hHmac_, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
    if (!NT_SUCCESS(s)) { err = Format("HMAC provider failed 0x%08X", (unsigned)s); return nullptr; }
    s = BCryptCreateHash(e->hHmac_, &e->hHash_, nullptr, 0, (PUCHAR)e->hmacKey_.data(),
                         static_cast<ULONG>(e->hmacKey_.size()), BCRYPT_HASH_REUSABLE_FLAG);
    if (!NT_SUCCESS(s)) { err = Format("HMAC create failed 0x%08X", (unsigned)s); return nullptr; }
    return e;
}

EncryptedSource::~EncryptedSource() {
    if (hHash_) BCryptDestroyHash(hHash_);
    if (hHmac_) BCryptCloseAlgorithmProvider(hHmac_, 0);
    if (hAesKey_) BCryptDestroyKey(hAesKey_);
    if (hAes_) BCryptCloseAlgorithmProvider(hAes_, 0);
    if (!hmacKey_.empty()) SecureZeroMemory(hmacKey_.data(), hmacKey_.size());
    if (csInit_) DeleteCriticalSection(&cs_);
}

// Decrypts `count` consecutive cipher blocks in place. Caller holds no lock.
bool EncryptedSource::DecryptBlocks(uint64_t firstBlock, uint64_t count, uint8_t* inout) {
    const ULONG bpb = hdr_.bytesPerBlock;
    EnterCriticalSection(&cs_);
    bool ok = true;
    for (uint64_t i = 0; i < count && ok; ++i) {
        uint8_t be[4];
        const uint64_t abs = firstBlock + i;
        const uint32_t n = static_cast<uint32_t>(ivPeriod_ ? abs % ivPeriod_ : abs);
        be[0] = static_cast<uint8_t>(n >> 24); be[1] = static_cast<uint8_t>(n >> 16);
        be[2] = static_cast<uint8_t>(n >> 8);  be[3] = static_cast<uint8_t>(n);
        uint8_t mac[20];
        if (!NT_SUCCESS(BCryptHashData(hHash_, be, 4, 0)) || !NT_SUCCESS(BCryptFinishHash(hHash_, mac, sizeof(mac), 0))) { ok = false; break; }
        uint8_t iv[16];
        std::memcpy(iv, mac, 16);
        ULONG got = 0;
        uint8_t* blk = inout + i * bpb;
        NTSTATUS s = BCryptDecrypt(hAesKey_, blk, bpb, nullptr, iv, 16, blk, bpb, &got, 0);
        if (!NT_SUCCESS(s) || got != bpb) ok = false;
    }
    LeaveCriticalSection(&cs_);
    return ok;
}

bool EncryptedSource::ReadAt(uint64_t ofs, void* buf, size_t len) {
    if (len == 0) return true;
    if (ofs > hdr_.dataLen || len > hdr_.dataLen - ofs) return false;
    const uint64_t bpb = hdr_.bytesPerBlock;
    const uint64_t first = ofs / bpb, last = (ofs + len - 1) / bpb;
    const uint64_t count = last - first + 1;
    std::vector<uint8_t> tmp(static_cast<size_t>(count * bpb));
    const uint64_t cipherOfs = hdr_.dataOffset + first * bpb;
    // The file always holds whole cipher blocks (verified on the hdiutil corpus),
    // but clamp anyway and treat a short tail as zero.
    size_t avail = tmp.size();
    if (cipherOfs + avail > inner_->Size()) avail = static_cast<size_t>(inner_->Size() - cipherOfs);
    avail -= avail % bpb;
    if (avail && !inner_->ReadAt(cipherOfs, tmp.data(), avail)) return false;
    if (!DecryptBlocks(first, avail / bpb, tmp.data())) return false;
    // Sparse bundles keep the cipher blocks in band files; a band that was
    // never written has no ciphertext and reads as plaintext zeros (macOS does
    // the same). Re-zero any block whose storage is unallocated.
    const uint64_t nBlocks = avail / bpb;
    for (uint64_t i = 0; i < nBlocks;) {
        if (inner_->IsUnallocated(cipherOfs + i * bpb, static_cast<size_t>(bpb))) {
            // extend the run to the end of the unallocated region cheaply
            uint64_t j = i + 1;
            while (j < nBlocks && inner_->IsUnallocated(cipherOfs + j * bpb, static_cast<size_t>(bpb))) ++j;
            std::memset(tmp.data() + i * bpb, 0, static_cast<size_t>((j - i) * bpb));
            i = j;
        } else {
            ++i;
        }
    }
    std::memcpy(buf, tmp.data() + (ofs - first * bpb), len);
    SecureZeroMemory(tmp.data(), tmp.size());
    return true;
}

bool EncryptedSource::PlaintextLooksValid(std::string& what) {
    uint8_t head[1536];
    const size_t n = static_cast<size_t>(std::min<uint64_t>(sizeof(head), hdr_.dataLen));
    if (n < 512 || !ReadAt(0, head, n)) { what = "unreadable"; return false; }
    if (hdr_.dataLen >= 512) {
        uint8_t tail[512];
        if (ReadAt(hdr_.dataLen - 512, tail, 512) && std::memcmp(tail, "koly", 4) == 0) { what = "UDIF trailer"; return true; }
    }
    if (n >= 1024 && std::memcmp(head + 512, "EFI PART", 8) == 0) { what = "GPT"; return true; }
    if (std::memcmp(head, "ER", 2) == 0 && head[2] == 0x02 && head[3] == 0x00) { what = "Apple partition map"; return true; }
    if (n >= 1536 && (std::memcmp(head + 1024, "H+", 2) == 0 || std::memcmp(head + 1024, "HX", 2) == 0)) { what = "HFS+"; return true; }
    if (std::memcmp(head + 32, "NXSB", 4) == 0) { what = "APFS"; return true; }
    if (head[510] == 0x55 && head[511] == 0xAA) { what = "MBR"; return true; }
    what = "no recognised signature";
    return false;
}

} // namespace dmg
