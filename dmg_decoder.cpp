#include "dmg_decoder.h"
#include "dmg_mish.h"
#include "dmg_util.h"

#include <cstring>
#include <vector>

#include "miniz.h"
#include "bzlib.h"
#include "lzfse.h"
extern "C" {
#include "xz.h"
}

// libbz2 is built with BZ_NO_STDIO; it expects the host to supply this.
extern "C" void bz_internal_error(int errcode) {
    (void)errcode;   // BZ2_bzBuffToBuffDecompress reports failures via return codes
}

namespace dmg {

void DecoderGlobalInit() {
    static bool done = false;
    if (done) return;
    xz_crc32_init();
#ifdef XZ_USE_CRC64
    xz_crc64_init();
#endif
    done = true;
}

bool ChunkTypeSupported(uint32_t t) {
    switch (t) {
        case kChunkZero: case kChunkRaw: case kChunkIgnore:
        case kChunkAdc: case kChunkZlib: case kChunkBzip2:
        case kChunkLzfse: case kChunkLzma:
            return true;
        default:
            return false;
    }
}

// Apple Data Compression (used by UDCO images). Three token kinds keyed on
// the top bits of the control byte:
//   1xxxxxxx            literal run of (x+1) bytes
//   01xxxxxx hh ll      back-reference, length (x+4), distance (hhll+1)
//   00xxxxyy ll         back-reference, length (x+3), distance (yyll+1)
// Distances may be shorter than the length (overlapping copy).
bool AdcDecode(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, size_t& produced) {
    size_t ip = 0, op = 0;
    while (ip < inLen && op < outLen) {
        uint8_t b = in[ip++];
        if (b & 0x80) {
            size_t len = static_cast<size_t>(b & 0x7F) + 1;
            if (ip + len > inLen || op + len > outLen) { produced = op; return false; }
            std::memcpy(out + op, in + ip, len);
            ip += len; op += len;
        } else {
            size_t len, dist;
            if (b & 0x40) {
                if (ip + 2 > inLen) { produced = op; return false; }
                len = static_cast<size_t>(b & 0x3F) + 4;
                dist = (static_cast<size_t>(in[ip]) << 8 | in[ip + 1]) + 1;
                ip += 2;
            } else {
                if (ip + 1 > inLen) { produced = op; return false; }
                len = static_cast<size_t>((b & 0x3F) >> 2) + 3;
                dist = (static_cast<size_t>(b & 0x03) << 8 | in[ip]) + 1;
                ip += 1;
            }
            if (dist > op || op + len > outLen) { produced = op; return false; }
            for (size_t i = 0; i < len; ++i) out[op + i] = out[op - dist + i];
            op += len;
        }
    }
    produced = op;
    return true;
}

static bool DecodeZlib(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, std::string& err) {
    size_t got = tinfl_decompress_mem_to_mem(out, outLen, in, inLen, TINFL_FLAG_PARSE_ZLIB_HEADER);
    if (got == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED) { err = "zlib inflate failed"; return false; }
    if (got != outLen) { err = Format("zlib produced %zu bytes, expected %zu", got, outLen); return false; }
    return true;
}

static bool DecodeBzip2(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, std::string& err) {
    if (inLen > 0xFFFFFFFFu || outLen > 0xFFFFFFFFu) { err = "bzip2 chunk too large"; return false; }
    unsigned int destLen = static_cast<unsigned int>(outLen);
    int rc = BZ2_bzBuffToBuffDecompress(reinterpret_cast<char*>(out), &destLen,
                                        const_cast<char*>(reinterpret_cast<const char*>(in)),
                                        static_cast<unsigned int>(inLen), 0, 0);
    if (rc != BZ_OK) { err = Format("bzip2 decompress rc=%d", rc); return false; }
    if (destLen != outLen) { err = Format("bzip2 produced %u bytes, expected %zu", destLen, outLen); return false; }
    return true;
}

static bool DecodeLzfse(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, std::string& err) {
    std::vector<uint8_t> scratch(lzfse_decode_scratch_size());
    // lzfse_decode_buffer returns the number of bytes written; a result equal
    // to outLen means the whole chunk fit (QEMU dmg-lzfse.c relies on the same).
    size_t got = lzfse_decode_buffer(out, outLen, in, inLen, scratch.data());
    if (got != outLen) { err = Format("lzfse produced %zu bytes, expected %zu", got, outLen); return false; }
    return true;
}

static bool DecodeXz(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, std::string& err) {
    DecoderGlobalInit();
    struct xz_dec* s = xz_dec_init(XZ_DYNALLOC, 1u << 28);
    if (!s) { err = "xz_dec_init failed"; return false; }
    struct xz_buf b;
    std::memset(&b, 0, sizeof(b));
    b.in = in; b.in_pos = 0; b.in_size = inLen;
    b.out = out; b.out_pos = 0; b.out_size = outLen;
    bool ok = false;
    for (;;) {
        enum xz_ret r = xz_dec_run(s, &b);
        if (r == XZ_STREAM_END) { ok = (b.out_pos == outLen); if (!ok) err = Format("xz produced %zu bytes, expected %zu", b.out_pos, outLen); break; }
        if (r == XZ_OK || r == XZ_UNSUPPORTED_CHECK) {
            if (b.in_pos >= b.in_size && b.out_pos < b.out_size) { err = "xz stream truncated"; break; }
            if (b.out_pos >= b.out_size) { err = "xz output exceeds chunk size"; break; }
            continue;
        }
        err = Format("xz_dec_run returned %d", static_cast<int>(r));
        break;
    }
    xz_dec_end(s);
    return ok;
}

bool DecodeChunk(uint32_t type, const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, std::string& err) {
    switch (type) {
        case kChunkZero:
        case kChunkIgnore:
            std::memset(out, 0, outLen);
            return true;
        case kChunkRaw:
            if (inLen != outLen) { err = Format("raw chunk length %zu != %zu", inLen, outLen); return false; }
            std::memcpy(out, in, outLen);
            return true;
        case kChunkAdc: {
            size_t produced = 0;
            if (!AdcDecode(in, inLen, out, outLen, produced)) { err = Format("adc decode failed after %zu bytes", produced); return false; }
            if (produced != outLen) { err = Format("adc produced %zu bytes, expected %zu", produced, outLen); return false; }
            return true;
        }
        case kChunkZlib:  return DecodeZlib(in, inLen, out, outLen, err);
        case kChunkBzip2: return DecodeBzip2(in, inLen, out, outLen, err);
        case kChunkLzfse: return DecodeLzfse(in, inLen, out, outLen, err);
        case kChunkLzma:  return DecodeXz(in, inLen, out, outLen, err);
        default:
            err = Format("unsupported chunk type 0x%08X", type);
            return false;
    }
}

} // namespace dmg
