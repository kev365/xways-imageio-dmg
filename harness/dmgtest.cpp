// dmgtest — offline console harness for the ImageIO_DMG reader (no X-Ways).
//
//   dmgtest map     <file.dmg>                       koly, partitions, chunk table, type histogram
//   dmgtest extract <file.dmg> <out.raw> [--sector S --count N] [--bufsize BYTES]
//   dmgtest verify  <file.dmg>                       decode every chunk, check lengths
//   dmgtest checksums <file.dmg>                     verify the partition / data-fork / master CRC32s the image carries
//   dmgtest bench   <file.dmg> [--bufsize BYTES] [--random N]
//   dmgtest decrypt <file.dmg> <out.bin>             dump the decrypted plaintext of an encrypted image
//   dmgtest adc     <in.adc> <out.bin> <outLen>      decode one raw ADC stream (tests)
//
// Encrypted images: add --password <p> (or set IMAGEIO_DMG_PASSWORD).
// Built by harness\build_harness.bat from the same sources as the DLL.

#include <windows.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "byte_source.h"
#include "dmg_decoder.h"
#include "dmg_open.h"
#include "dmg_util.h"
#include "dmg_verify.h"
#include "udif_source.h"

using namespace dmg;

static std::wstring ToW(const char* s) { return Utf8ToUtf16(s); }

static std::string g_password;
static bool g_havePassword = false;

static bool OpenImage(const char* path, OpenedImage& img) {
    OpenOptions opts;
    if (g_havePassword) {
        opts.passwordProvider = [](const EncHeader&, int attempt, const std::string& lastErr, std::string& pw) {
            if (attempt > 1) { std::fprintf(stderr, "password rejected: %s\n", lastErr.c_str()); return false; }
            pw = g_password;
            return true;
        };
    }
    std::string message;
    OpenStatus st = OpenDmg(ToW(path).c_str(), opts, img, message);
    if (st != OpenStatus::Ok) {
        std::fprintf(stderr, "%s: %s%s\n", st == OpenStatus::NotDmg ? "not a DMG" : "cannot open", message.c_str(),
                     (img.encrypted && !g_havePassword) ? " (use --password)" : "");
        return false;
    }
    if (img.encrypted) std::printf("encrypted: %s; uuid=%s; plaintext=%s\n", EncSummary(img.enc).c_str(), UuidString(img.enc.uuid).c_str(),
                                   img.udif ? "UDIF" : img.plaintextKind.c_str());
    for (const auto& w : img.warnings) std::printf("warning: %s\n", w.c_str());
    return true;
}

static int CmdMap(const char* path) {
    OpenedImage img;
    if (!OpenImage(path, img)) return 2;
    if (!img.udif) {
        std::printf("kind=%s size=%llu bytes (%llu sectors) — no UDIF block map (bare plaintext)\n", img.kind.c_str(),
                    (unsigned long long)img.reader->Size(), (unsigned long long)img.reader->Size() / 512);
        return 0;
    }
    UdifSource* u = img.udif;
    const Koly& k = u->Trailer();
    const BlockMap& bm = u->Map();
    std::printf("koly: version=%u flags=0x%X dataFork=[%llu+%llu] rsrcFork=[%llu+%llu] xml=[%llu+%llu] segment=%u/%u variant=%u sectors=%llu (%.1f MiB) blockmap=%s\n",
                k.version, k.flags, (unsigned long long)k.dataForkOffset, (unsigned long long)k.dataForkLength,
                (unsigned long long)k.rsrcForkOffset, (unsigned long long)k.rsrcForkLength,
                (unsigned long long)k.xmlOffset, (unsigned long long)k.xmlLength, k.segmentNumber, k.segmentCount,
                k.imageVariant, (unsigned long long)k.sectorCount, k.sectorCount * 512.0 / 1048576.0, u->Source().c_str());
    std::printf("image: %llu sectors, %zu chunks (max chunk %llu bytes)\n", (unsigned long long)bm.totalSectors, bm.chunks.size(), (unsigned long long)bm.maxChunkBytes);
    std::printf("partitions (%zu):\n", bm.partitions.size());
    for (size_t i = 0; i < bm.partitions.size(); ++i) {
        const Partition& p = bm.partitions[i];
        std::printf("  [%zu] id=%lld sector=%llu count=%llu (%llu bytes) chunks=%zu cksum=%u attrs=%s name=\"%s\"\n",
                    i, (long long)p.id, (unsigned long long)p.firstSector, (unsigned long long)p.sectorCount,
                    (unsigned long long)p.sectorCount * 512, p.chunkCount, p.checksumType, p.attributes.c_str(), p.name.c_str());
    }
    std::printf("chunk types:\n");
    for (const auto& kv : bm.typeCounts)
        std::printf("  %-8s (0x%08X): %llu chunks, %llu bytes\n", ChunkTypeName(kv.first), kv.first,
                    (unsigned long long)kv.second, (unsigned long long)bm.typeBytes.at(kv.first));
    std::printf("chunks:\n");
    for (size_t i = 0; i < bm.chunks.size(); ++i) {
        const Chunk& c = bm.chunks[i];
        std::printf("  %6zu %-8s sector=%-10llu count=%-8llu fileOfs=%-12llu compLen=%-10llu part=%d%s\n",
                    i, ChunkTypeName(c.type), (unsigned long long)c.sector, (unsigned long long)c.count,
                    (unsigned long long)c.fileOfs, (unsigned long long)c.compLen, c.partition, c.synthetic ? " (synthetic)" : "");
    }
    return 0;
}

static int DumpRange(IImageReader& r, const char* outPath, uint64_t ofs, uint64_t end, size_t bufSize, const char* what) {
    HANDLE h = CreateFileW(ToW(outPath).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { std::fprintf(stderr, "cannot create %s\n", outPath); return 2; }
    std::vector<uint8_t> buf(bufSize);
    uint64_t done = 0;
    ULONGLONG t0 = GetTickCount64();
    while (ofs < end) {
        uint64_t want = std::min<uint64_t>(bufSize, end - ofs);
        std::string err;
        uint64_t got = r.Read(ofs, buf.data(), want, false, nullptr, &err);
        if (got != want) { std::fprintf(stderr, "read at %llu failed: %s\n", (unsigned long long)ofs, err.c_str()); CloseHandle(h); return 3; }
        DWORD w = 0;
        if (!WriteFile(h, buf.data(), static_cast<DWORD>(got), &w, nullptr) || w != got) { std::fprintf(stderr, "write failed\n"); CloseHandle(h); return 3; }
        ofs += got; done += got;
    }
    CloseHandle(h);
    ULONGLONG ms = GetTickCount64() - t0;
    std::printf("%s %llu bytes to %s in %llu ms (%.1f MiB/s)", what, (unsigned long long)done, outPath, ms, ms ? done / 1048576.0 / (ms / 1000.0) : 0.0);
    if (const UdifStats* st = r.Stats())
        std::printf("; reads=%lld hits=%lld misses=%lld direct=%lld errors=%lld", st->reads, st->cacheHits, st->cacheMisses, st->directDecodes, st->decodeErrors);
    std::printf("\n");
    return 0;
}

static int CmdExtract(const char* path, const char* outPath, uint64_t sector, uint64_t count, size_t bufSize) {
    OpenedImage img;
    if (!OpenImage(path, img)) return 2;
    const uint64_t total = img.reader->Size() / 512;
    if (sector >= total) { std::fprintf(stderr, "sector %llu beyond image (%llu)\n", (unsigned long long)sector, (unsigned long long)total); return 2; }
    if (count == 0 || sector + count > total) count = total - sector;
    return DumpRange(*img.reader, outPath, sector * 512, (sector + count) * 512, bufSize, "extracted");
}

static int CmdDecrypt(const char* path, const char* outPath) {
    OpenedImage img;
    if (!OpenImage(path, img)) return 2;
    if (!img.plaintext) { std::fprintf(stderr, "%s is not encrypted\n", path); return 2; }
    RawImageReader r(img.plaintext);
    return DumpRange(r, outPath, 0, img.plaintext->Size(), 1u << 20, "decrypted");
}

static int CmdChecksums(const char* path) {
    OpenedImage img;
    if (!OpenImage(path, img)) return 2;
    if (!img.udif) { std::printf("no UDIF checksums to verify (kind=%s)\n", img.kind.c_str()); return 0; }
    // The koly offsets refer to the container the reader parsed: the plain
    // file, the decrypted plaintext, or the concatenated segment fork.
    IByteSource& container = img.plaintext ? static_cast<IByteSource&>(*img.plaintext) : *img.file;
    uint64_t lastPct = 100;
    VerifyReport r = VerifyAll(container, *img.udif, [&](uint64_t done, uint64_t total) {
        uint64_t pct = total ? done * 100 / total : 100;
        if (pct / 10 != lastPct / 10) { std::fprintf(stderr, "%llu%%..", (unsigned long long)pct); lastPct = pct; }
        return true;
    });
    std::fprintf(stderr, "\n");
    std::printf("%s%s\n", r.Detail().c_str(), r.Summary().c_str());
    return r.AnyMismatch() ? 3 : 0;
}

static int CmdVerify(const char* path) {
    OpenedImage img;
    if (!OpenImage(path, img)) return 2;
    if (!img.udif) { std::printf("no chunk table to verify (bare plaintext of %llu bytes)\n", (unsigned long long)img.reader->Size()); return 0; }
    UdifSource* u = img.udif;
    const BlockMap& bm = u->Map();
    std::vector<uint8_t> buf;
    size_t bad = 0;
    ULONGLONG t0 = GetTickCount64();
    for (size_t i = 0; i < bm.chunks.size(); ++i) {
        const Chunk& c = bm.chunks[i];
        if (ChunkTypeIsZero(c.type)) continue;
        buf.resize(static_cast<size_t>(c.Bytes()));
        std::string err;
        uint64_t got = u->Read(c.sector * 512, buf.data(), c.Bytes(), false, nullptr, &err);
        if (got != c.Bytes()) { ++bad; std::printf("chunk %zu (%s @%llu): FAIL %s\n", i, ChunkTypeName(c.type), (unsigned long long)c.sector, err.c_str()); }
    }
    std::printf("verified %zu chunks in %llu ms: %zu failed\n", bm.chunks.size(), GetTickCount64() - t0, bad);
    return bad ? 3 : 0;
}

static int CmdBench(const char* path, size_t bufSize, int randomReads) {
    OpenedImage img;
    if (!OpenImage(path, img)) return 2;
    IImageReader& r = *img.reader;
    const uint64_t size = r.Size();
    std::vector<uint8_t> buf(bufSize);
    ULONGLONG t0 = GetTickCount64();
    uint64_t done = 0;
    for (uint64_t ofs = 0; ofs < size; ofs += bufSize) {
        std::string err;
        uint64_t got = r.Read(ofs, buf.data(), std::min<uint64_t>(bufSize, size - ofs), false, nullptr, &err);
        if (!got) { std::fprintf(stderr, "read failed at %llu: %s\n", (unsigned long long)ofs, err.c_str()); return 3; }
        done += got;
    }
    ULONGLONG seqMs = GetTickCount64() - t0;
    std::printf("sequential: %llu bytes in %llu ms (%.1f MiB/s) buf=%zu\n", (unsigned long long)done, seqMs, seqMs ? done / 1048576.0 / (seqMs / 1000.0) : 0.0, bufSize);
    std::mt19937_64 rng(42);
    t0 = GetTickCount64();
    for (int i = 0; i < randomReads; ++i) {
        uint64_t ofs = (rng() % (size / 512)) * 512;
        std::string err;
        if (!r.Read(ofs, buf.data(), std::min<uint64_t>(bufSize, size - ofs), false, nullptr, &err)) { std::fprintf(stderr, "random read failed: %s\n", err.c_str()); return 3; }
    }
    ULONGLONG rndMs = GetTickCount64() - t0;
    std::printf("random: %d reads in %llu ms", randomReads, rndMs);
    if (const UdifStats* st = r.Stats()) std::printf("; reads=%lld hits=%lld misses=%lld direct=%lld", st->reads, st->cacheHits, st->cacheMisses, st->directDecodes);
    std::printf("\n");
    return 0;
}

static int CmdAdc(const char* inPath, const char* outPath, size_t outLen) {
    std::string err;
    auto f = RawFileSource::Open(ToW(inPath).c_str(), err);
    if (!f) { std::fprintf(stderr, "%s\n", err.c_str()); return 2; }
    std::vector<uint8_t> in(static_cast<size_t>(f->Size())), out(outLen);
    f->ReadAt(0, in.data(), in.size());
    size_t produced = 0;
    bool ok = AdcDecode(in.data(), in.size(), out.data(), out.size(), produced);
    std::printf("adc: ok=%d produced=%zu\n", ok ? 1 : 0, produced);
    HANDLE h = CreateFileW(ToW(outPath).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD w = 0;
    WriteFile(h, out.data(), static_cast<DWORD>(produced), &w, nullptr);
    CloseHandle(h);
    return ok ? 0 : 3;
}

static uint64_t ArgU64(int argc, char** argv, const char* name, uint64_t def) {
    for (int i = 0; i + 1 < argc; ++i) if (std::strcmp(argv[i], name) == 0) return std::strtoull(argv[i + 1], nullptr, 10);
    return def;
}

int main(int, char**) {
    DecoderGlobalInit();
    // Take the arguments from the wide command line and convert them to UTF-8,
    // so a non-ASCII passphrase reaches the decryptor byte-for-byte (the ANSI
    // argv would mangle anything outside the console code page). This mirrors
    // what the DLL does with the password dialog's UTF-16 text.
    int argc = 0;
    wchar_t** wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> a8;
    std::vector<char*> av;
    for (int i = 0; i < argc; ++i) a8.push_back(Utf16ToUtf8(wargv[i]));
    for (auto& s : a8) av.push_back(const_cast<char*>(s.c_str()));
    av.push_back(nullptr);
    char** argv = av.data();
    LocalFree(wargv);
    for (int i = 0; i + 1 < argc; ++i) if (std::strcmp(argv[i], "--password") == 0) { g_password = argv[i + 1]; g_havePassword = true; }
    if (!g_havePassword) {
        char env[1025] = {0};
        if (GetEnvironmentVariableA("IMAGEIO_DMG_PASSWORD", env, 1024) > 0) { g_password = env; g_havePassword = true; }
    }
    if (argc < 3) {
        std::fprintf(stderr, "usage: dmgtest map|extract|verify|checksums|bench|decrypt|adc ... [--password p] (see header comment)\n");
        return 1;
    }
    std::string cmd = argv[1];
    if (cmd == "map")     return CmdMap(argv[2]);
    if (cmd == "verify")  return CmdVerify(argv[2]);
    if (cmd == "checksums") return CmdChecksums(argv[2]);
    if (cmd == "bench")   return CmdBench(argv[2], static_cast<size_t>(ArgU64(argc, argv, "--bufsize", 65536)), static_cast<int>(ArgU64(argc, argv, "--random", 2000)));
    if (cmd == "extract") {
        if (argc < 4) { std::fprintf(stderr, "extract needs <file.dmg> <out.raw>\n"); return 1; }
        return CmdExtract(argv[2], argv[3], ArgU64(argc, argv, "--sector", 0), ArgU64(argc, argv, "--count", 0), static_cast<size_t>(ArgU64(argc, argv, "--bufsize", 1u << 20)));
    }
    if (cmd == "decrypt") {
        if (argc < 4) { std::fprintf(stderr, "decrypt needs <file.dmg> <out.bin>\n"); return 1; }
        return CmdDecrypt(argv[2], argv[3]);
    }
    if (cmd == "adc") {
        if (argc < 5) { std::fprintf(stderr, "adc needs <in.adc> <out.bin> <outLen>\n"); return 1; }
        return CmdAdc(argv[2], argv[3], static_cast<size_t>(std::strtoull(argv[4], nullptr, 10)));
    }
    std::fprintf(stderr, "unknown command %s\n", cmd.c_str());
    return 1;
}
