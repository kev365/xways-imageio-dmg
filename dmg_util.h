// dmg_util.h — small shared helpers for the DMG (UDIF) reader.
//
// Big-endian field readers, a bounds-checked byte reader, base64, UTF
// conversions, and a printf-style std::string formatter. Header-only.
#pragma once

#include <windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace dmg {

inline uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}
inline uint64_t be64(const uint8_t* p) {
    return (static_cast<uint64_t>(be32(p)) << 32) | be32(p + 4);
}

// Bounds-checked view over a byte buffer. Every accessor returns false / zero
// instead of reading past the end.
struct ByteReader {
    const uint8_t* p = nullptr;
    size_t n = 0;
    ByteReader() = default;
    ByteReader(const uint8_t* data, size_t len) : p(data), n(len) {}
    bool Has(size_t off, size_t len) const { return off <= n && len <= n - off; }
    uint32_t U32(size_t off) const { return Has(off, 4) ? be32(p + off) : 0; }
    uint64_t U64(size_t off) const { return Has(off, 8) ? be64(p + off) : 0; }
    bool Magic(size_t off, const char* m, size_t len) const {
        return Has(off, len) && std::memcmp(p + off, m, len) == 0;
    }
};

inline std::string Format(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return std::string();
    if (static_cast<size_t>(n) < sizeof(buf)) return std::string(buf, static_cast<size_t>(n));
    std::string big(static_cast<size_t>(n) + 1, '\0');
    va_start(ap, fmt);
    std::vsnprintf(big.data(), big.size(), fmt, ap);
    va_end(ap);
    big.resize(static_cast<size_t>(n));
    return big;
}

inline std::string Utf16ToUtf8(const wchar_t* w) {
    if (!w || !*w) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string out(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
    return out;
}

inline std::wstring Utf8ToUtf16(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (len <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

// Base64 decoder tolerant of whitespace / line breaks (plist <data> blobs
// are wrapped at 68 columns). Returns false on a non-base64 character.
inline bool Base64Decode(const char* s, size_t n, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(n / 4 * 3 + 3);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else if (c == '=') break;                                   // padding: done
        else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        else return false;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return true;
}

inline std::string ToLowerAscii(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

} // namespace dmg
