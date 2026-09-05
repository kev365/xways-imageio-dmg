// xways-imageio-dmg — X-Ways Forensics Image I/O API plugin for Apple DMG
// (UDIF) disk images. Builds as ImageIO_DMG.dll; deploy into <X-Ways>\x64\.
//
// This is NOT an XT_* X-Tension. The Image I/O API (X-Ways 19.5+) lets a DLL
// named Image*.dll claim an image file X-Ways is about to open and serve all
// sector reads for it. X-Ways parses partition tables and file systems
// itself; this plugin only turns a compressed (and/or encrypted) .dmg into a
// flat sector array.
//
//   IIO_Init  - called for every candidate image file (and again on case
//               reopen). Claims .dmg / koly-trailer / encrcdsa files.
//   IIO_Work  - byte-range read (or write, which we refuse). Multi-threaded.
//   IIO_Done  - releases the per-image state.
//
// Supported: unencrypted UDIF with zero / raw / ADC / zlib / bzip2 / LZFSE /
// LZMA chunks (XML plist or resource-fork block maps); encrypted images
// (encrcdsa v2, AES-128/256) whose plaintext is UDIF or a bare disk/volume,
// unlocked via a password prompt, the X-Ways Passwords.txt collection, the
// IMAGEIO_DMG_PASSWORD environment variable, the session cache, or the
// DPAPI-encrypted per-user store next to the DLL (ImageIO_DMG-passwords.cfg).
// Also: segmented images (name.dmg + name.NNN.dmgpart), .sparseimage files and
// .sparsebundle directories (add the bundle's Info.plist as the image).
// Declined with a message: cdsaencr v1, certificate-only encryption.
//
// References: docs in the xways-xtension-builder-skill KB
// (xways-image-io-api.md), the official Image_IO_API.html + IIO.zip Delphi
// demo, QEMU block/dmg.c (MIT) for the UDIF reading model.

#include <windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "byte_source.h"
#include "dmg_decoder.h"
#include "dmg_open.h"
#include "dmg_util.h"
#include "password_dialog.h"
#include "sparse_source.h"
#include "dmg_verify.h"
#include "udif_source.h"

#pragma comment(lib, "crypt32.lib")

// ---------------------------------------------------------------------------
//  Identity + tunables
// ---------------------------------------------------------------------------

static const char*  NAME    = "ImageIO_DMG";
static const char*  VERSION = "0.1.0-beta";

// VERBOSE keeps the per-image decisions (claim / decline / give-up, partition
// list, close-out statistics) in ImageIO_DMG-log.tsv; it is cheap and stays on
// so an analyst always has a record of what the plugin did.
//
// TRACE_WORK additionally logs *every* IIO_Work call (the first
// kTraceFullCalls in full, then a summary every kTraceEvery). That is a
// development aid: it makes the log large and adds a file write per read, so
// it ships OFF. Turn it on locally when investigating read behaviour.
static constexpr bool   VERBOSE          = true;
static constexpr bool   TRACE_WORK       = false;
static constexpr LONG   kTraceFullCalls  = 2000;
static constexpr LONG   kTraceEvery      = 10000;
static constexpr size_t kCacheBytes      = 128u << 20;
static constexpr int    kPasswordTries   = 3;

// ---------------------------------------------------------------------------
//  Image I/O API surface (Image_IO_API.html / IIO.zip Delphi demo)
// ---------------------------------------------------------------------------

#pragma pack(push, 2)
struct ImageInfo {
    DWORD  nSize;            // preset by caller (28 on x64); we overwrite with what we support
    INT64  nSectorCount;
    DWORD  nSectorSize;      // 512 / 1024 / 2048 / 4096 / 8192
    DWORD  nFlags;           // IIO_INIT_*
    LPWSTR lpTextualDescr;   // optional; freed by the caller via IIO_Done
};
#pragma pack(pop)

constexpr DWORD IIO_INIT_READ          = 0x0001;
constexpr DWORD IIO_INIT_WRITE         = 0x0002;
constexpr DWORD IIO_INIT_DISK          = 0x0010;
constexpr DWORD IIO_INIT_VOLUME        = 0x0020;
constexpr DWORD IIO_INIT_THREADSAFE    = 0x0100;
constexpr DWORD IIO_INIT_UNALIGNED_OK  = 0x0200;
constexpr DWORD IIO_INIT_ERROR_MILD    = 0x1000;
constexpr DWORD IIO_INIT_ERROR_SEVERE  = 0x2000;
constexpr DWORD IIO_INIT_ERROR_GIVE_UP = 0x4000;

constexpr BYTE IIO_WRITE               = 0x01;
constexpr BYTE IIO_CHECK_FOR_SPARSE    = 0x20;
constexpr BYTE IIO_SPARSE_DETECTED     = 0x40;

// ---------------------------------------------------------------------------
//  Globals
// ---------------------------------------------------------------------------

static HMODULE          g_hSelf = nullptr;

// --- Messages-window experiment ---------------------------------------------
// The Image I/O API defines no way to talk to the X-Ways Messages window; the
// XWF_* functions are documented for X-Tensions only. But they are plain
// exports of the X-Ways executable, and this DLL lives in the same process, so
// resolve XWF_OutputMessage at load and use it if it is there. If X-Ways ever
// stops exporting it (or it misbehaves from this context) we fall back to the
// TSV log and the report file.
typedef void (__stdcall* fptr_XWF_OutputMessage)(const wchar_t* lpMessage, DWORD nFlags);
static fptr_XWF_OutputMessage g_xwfOutputMessage = nullptr;
static CRITICAL_SECTION g_logLock;
static CRITICAL_SECTION g_pwLock;
static volatile LONG    g_initSeq = 0;
static volatile LONG    g_workSeq = 0;
static volatile LONG    g_doneSeq = 0;

// Password stores, both keyed by "uuid:<UUID>" and "path:<lower-cased path>"
// -> UTF-8 password. g_sessionPw holds every accepted password for this
// X-Ways process; g_persistPw is the subset the analyst asked to remember,
// mirrored to ImageIO_DMG-passwords.cfg next to the DLL with each entry
// DPAPI-encrypted for the current Windows user (CryptProtectData). Deleting
// that file forgets everything. Passwords never appear in the log.
static std::map<std::string, std::string> g_sessionPw;
static std::map<std::string, std::string> g_persistPw;
static bool g_persistLoaded = false;

// --- Diagnostic fault injection (test builds and probes only) ---------------
// IMAGEIO_DMG_FAULT=<sector>[:short|zero] makes every IIO_Work request that
// covers <sector> misbehave on purpose: "short" (default) returns only the
// bytes before that sector (0 if it starts there), "zero" serves the sector
// as zeros. Used to learn how X-Ways reacts to each kind of read failure.
// Never set in production; nothing here is reachable without the variable.
static bool     g_faultEnabled = false;
static uint64_t g_faultSector = 0;
static bool     g_faultZero = false;

static void LoadFaultInjection() {
    wchar_t v[64] = {0};
    if (GetEnvironmentVariableW(L"IMAGEIO_DMG_FAULT", v, 63) == 0) return;
    g_faultSector = _wcstoui64(v, nullptr, 10);
    g_faultZero = wcsstr(v, L":zero") != nullptr;
    g_faultEnabled = true;
}

// ---------------------------------------------------------------------------
//  Logging — TSV beside the DLL (ImageIO_DMG-log.tsv) for everything, plus
//  the X-Ways Messages window (XWF_OutputMessage, resolved from the host at
//  load — works from an Image I/O plugin, verified 2026-09-05) for the notices
//  an analyst must see. Passwords are never logged.
// ---------------------------------------------------------------------------

static std::wstring SelfDir() {
    wchar_t path[MAX_PATH + 16] = {0};
    DWORD n = GetModuleFileNameW(g_hSelf, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash) *slash = L'\0';
    return path;
}

static std::wstring GetLogPath() {
    wchar_t path[MAX_PATH + 16] = {0};
    DWORD n = GetModuleFileNameW(g_hSelf, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".\\ImageIO_DMG-log.tsv";
    wchar_t* dot = wcsrchr(path, L'.');
    if (dot) *dot = L'\0';
    return std::wstring(path) + L"-log.tsv";
}

static std::string IsoTimestampLocal() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    return dmg::Format("%04u-%02u-%02uT%02u:%02u:%02u.%03u",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static std::string EscapeForTsv(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            case '\n': out += "\\n"; break;
            case '\0': out += "\\0"; break;
            default:   out += c;
        }
    }
    return out;
}

static void Log(const char* callback, LONG seq, const std::string& msg) {
    EnterCriticalSection(&g_logLock);
    std::wstring path = GetLogPath();
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size = {};
        GetFileSizeEx(h, &size);
        DWORD wrote = 0;
        if (size.QuadPart == 0) {
            const char* header = "\xEF\xBB\xBFts\ttid\tcallback\tseq\tmessage\n";
            WriteFile(h, header, static_cast<DWORD>(strlen(header)), &wrote, nullptr);
        }
        std::string row = IsoTimestampLocal() + "\t" + std::to_string(GetCurrentThreadId()) + "\t" +
                          callback + "\t" + std::to_string(seq) + "\t" + EscapeForTsv(msg) + "\n";
        WriteFile(h, row.data(), static_cast<DWORD>(row.size()), &wrote, nullptr);
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_logLock);
}

static void LogVerbose(const char* callback, LONG seq, const std::string& msg) {
    if (VERBOSE) Log(callback, seq, msg);
}

// Analyst-facing notice: Messages window when available, always the TSV log.
static void Notify(const char* callback, LONG seq, const std::string& msg) {
    Log(callback, seq, "NOTIFY " + msg);
    if (g_xwfOutputMessage) {
        std::wstring w = dmg::Utf8ToUtf16(std::string(NAME) + ": " + msg);
        g_xwfOutputMessage(w.c_str(), 0);
    }
}

// ---------------------------------------------------------------------------
//  Per-image state
// ---------------------------------------------------------------------------

constexpr uint32_t kStateMagic = 0x31474D44;  // "DMG1"

struct DmgImage {
    uint32_t magic = kStateMagic;
    LONG     initSeq = 0;
    std::wstring path;
    dmg::OpenedImage img;                       // reader null on the GIVE_UP path
    LPWSTR   descr = nullptr;                   // HeapAlloc'd; freed in IIO_Done
    volatile LONG workCalls = 0;
    volatile LONG workErrors = 0;
    volatile LONG writesRefused = 0;
    CRITICAL_SECTION tidLock;
    std::set<DWORD> tids;
    uint64_t minOfs = ~0ull, maxEnd = 0;
    uint64_t maxReq = 0, minReq = ~0ull;
    LONG unalignedCalls = 0;
    ULONGLONG t0 = 0;
    volatile LONG substitutionsNotified = 0;   // Messages-window notices sent for this image
    std::wstring reportPath;                   // ImageIO_DMG-reports\<image>.txt, created on first substitution

    DmgImage() { InitializeCriticalSection(&tidLock); t0 = GetTickCount64(); }
    ~DmgImage() { DeleteCriticalSection(&tidLock); }
    void NoteThread(DWORD tid) {
        EnterCriticalSection(&tidLock);
        tids.insert(tid);
        LeaveCriticalSection(&tidLock);
    }
};

static LPWSTR AllocDescr(const std::string& utf8) {
    std::wstring w = dmg::Utf8ToUtf16(utf8);
    size_t bytes = (w.size() + 1) * sizeof(wchar_t);
    LPWSTR p = static_cast<LPWSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes));
    if (p) memcpy(p, w.c_str(), bytes);
    return p;
}

// ---------------------------------------------------------------------------
//  Detection helpers
// ---------------------------------------------------------------------------

static std::string ExtensionOf(const wchar_t* path) {
    if (!path) return std::string();
    const wchar_t* dot = wcsrchr(path, L'.');
    if (!dot || !dot[1]) return std::string();
    if (wcspbrk(dot, L"\\/")) return std::string();
    return dmg::ToLowerAscii(dmg::Utf16ToUtf8(dot + 1));
}

static std::wstring FileNameOf(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
}

// Extensions that are structured containers X-Ways handles itself (or that
// can never be a DMG). Anything else — including raw-looking names such as
// .img / .bin / .iso — gets the cheap trailer probe, so a renamed .dmg still
// opens; a genuine raw image simply has no koly trailer and is declined.
static bool IsKnownOtherFormat(const std::string& ext) {
    static const char* const kOther[] = {
        "e01", "ex01", "l01", "lx01", "s01", "ad1", "aff", "aff4", "afd", "afm",
        "vhd", "vhdx", "vdi", "vmdk", "vmem", "vmsn", "vmss", "qcow", "qcow2",
        "mem", "dmp", "ctr", "zip", "7z", "tar",
    };
    for (const char* k : kOther) if (ext == k) return true;
    if (!ext.empty() && ext.size() <= 3) {           // .001 .002 ... split raw images
        bool digits = true;
        for (char c : ext) if (c < '0' || c > '9') digits = false;
        if (digits) return true;
    }
    return false;
}

static bool NameContains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// For containers without a blkx partition list (sparse images, bundles,
// encrypted read-write images): sniff the first sectors for a partition
// scheme or a file-system signature to pick IIO_INIT_DISK / _VOLUME.
static std::string SniffLayout(dmg::IImageReader& r) {
    uint8_t head[1536] = {};
    std::string err;
    const uint64_t n = std::min<uint64_t>(sizeof(head), r.Size());
    if (n < 512 || r.Read(0, head, n, false, nullptr, &err) != n) return "";
    if (n >= 1024 && memcmp(head + 512, "EFI PART", 8) == 0) return "GPT";
    if (memcmp(head, "ER", 2) == 0 && head[2] == 0x02 && head[3] == 0x00) return "Apple partition map";
    if (n >= 1536 && (memcmp(head + 1024, "H+", 2) == 0 || memcmp(head + 1024, "HX", 2) == 0)) return "HFS+";
    if (memcmp(head + 32, "NXSB", 4) == 0) return "APFS";
    if (head[510] == 0x55 && head[511] == 0xAA) return "MBR";
    return "";
}

// ---------------------------------------------------------------------------
//  Password sources (in order): environment variable, session cache,
//  X-Ways' general Passwords.txt collection (next to the X-Ways exe), dialog.
// ---------------------------------------------------------------------------

static std::string LowerPathKey(const std::wstring& path) {
    std::wstring w = path;
    for (auto& c : w) c = static_cast<wchar_t>(towlower(c));
    return "path:" + dmg::Utf16ToUtf8(w.c_str());
}

static std::vector<std::string> ReadPasswordsTxt() {
    std::vector<std::string> out;
    wchar_t exe[MAX_PATH + 16] = {0};
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return out;
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (!slash) return out;
    *slash = L'\0';
    std::wstring path = std::wstring(exe) + L"\\Passwords.txt";
    std::string err;
    auto f = dmg::RawFileSource::Open(path.c_str(), err);
    if (!f || f->Size() == 0 || f->Size() > (4u << 20)) return out;
    std::vector<uint8_t> bytes(static_cast<size_t>(f->Size()));
    if (!f->ReadAt(0, bytes.data(), bytes.size())) return out;
    std::string text;
    if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {            // UTF-16LE (what X-Ways writes)
        std::wstring w(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (bytes.size() - 2) / 2);
        text = dmg::Utf16ToUtf8(w.c_str());
    } else if (bytes.size() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
        text.assign(reinterpret_cast<const char*>(bytes.data() + 3), bytes.size() - 3);
    } else {
        text.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    size_t start = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        std::string line = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return out;
}

// --- DPAPI-encrypted persistent store --------------------------------------

static std::wstring PersistPath() { return SelfDir() + L"\\ImageIO_DMG-passwords.cfg"; }

static const wchar_t* kDpapiDescr = L"ImageIO_DMG password";

static bool DpapiProtect(const std::string& plain, std::string& b64) {
    DATA_BLOB in{ static_cast<DWORD>(plain.size()), (BYTE*)plain.data() }, out{};
    if (!CryptProtectData(&in, kDpapiDescr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    DWORD len = 0;
    CryptBinaryToStringA(out.pbData, out.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &len);
    std::string tmp(len, '\0');
    bool ok = CryptBinaryToStringA(out.pbData, out.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, tmp.data(), &len) != 0;
    LocalFree(out.pbData);
    if (!ok) return false;
    while (!tmp.empty() && (tmp.back() == '\0' || tmp.back() == '\r' || tmp.back() == '\n')) tmp.pop_back();
    b64 = tmp;
    return true;
}

static bool DpapiUnprotect(const std::string& b64, std::string& plain) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr)) return false;
    std::vector<BYTE> bin(len);
    if (!CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, bin.data(), &len, nullptr, nullptr)) return false;
    DATA_BLOB in{ len, bin.data() }, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    plain.assign(reinterpret_cast<const char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return true;
}

// File format: UTF-8, one entry per line, "<key>=<base64 DPAPI blob>"; '#' comments.
static void LoadPersistedPasswords() {
    if (g_persistLoaded) return;
    g_persistLoaded = true;
    std::string err;
    auto f = dmg::RawFileSource::Open(PersistPath().c_str(), err);
    if (!f || f->Size() == 0 || f->Size() > (4u << 20)) return;
    std::string text(static_cast<size_t>(f->Size()), '\0');
    if (!f->ReadAt(0, text.data(), text.size())) return;
    size_t start = 0, loaded = 0, failed = 0;
    while (start < text.size()) {
        size_t nl = text.find('\n', start);
        std::string line = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
        start = (nl == std::string::npos) ? text.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq), plain;
        if (DpapiUnprotect(line.substr(eq + 1), plain)) { g_persistPw[key] = plain; g_sessionPw[key] = plain; ++loaded; }
        else ++failed;   // another Windows user's entry, or a damaged line
    }
    if (VERBOSE) Log("IIO_Init", 0, dmg::Format("password store: %zu entr%s loaded, %zu undecryptable | %s", loaded, loaded == 1 ? "y" : "ies", failed, dmg::Utf16ToUtf8(PersistPath().c_str()).c_str()));
}

static void SavePersistedPasswords() {
    std::string text = "# ImageIO_DMG remembered passwords - each value is DPAPI-encrypted for the Windows user\n"
                       "# who saved it and cannot be read by anyone else. Delete this file to forget them all.\n";
    for (const auto& kv : g_persistPw) {
        std::string b64;
        if (DpapiProtect(kv.second, b64)) text += kv.first + "=" + b64 + "\n";
    }
    HANDLE h = CreateFileW(PersistPath().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { Log("IIO_Init", 0, dmg::Format("password store: cannot write (gle=%lu)", GetLastError())); return; }
    DWORD w = 0;
    WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &w, nullptr);
    CloseHandle(h);
}

struct PasswordContext {
    HWND hMainWnd = nullptr;
    std::wstring path;
    LONG seq = 0;
    std::vector<std::string> candidates;   // tried silently before the dialog
    std::vector<std::string> candidateSources;
    size_t nextCandidate = 0;
    int dialogAttempts = 0;
    bool remember = true;
    std::string source;                    // how the accepted password was obtained
};

static bool ProvidePassword(PasswordContext& ctx, const dmg::EncHeader& hdr, int attempt, const std::string& lastErr, std::string& pw) {
    (void)attempt;
    if (ctx.nextCandidate == 0) {
        // Build the silent candidate list once.
        wchar_t env[1025] = {0};
        if (GetEnvironmentVariableW(L"IMAGEIO_DMG_PASSWORD", env, 1024) > 0) { ctx.candidates.push_back(dmg::Utf16ToUtf8(env)); ctx.candidateSources.push_back("environment"); }
        EnterCriticalSection(&g_pwLock);
        LoadPersistedPasswords();
        const std::string uuidKey = "uuid:" + dmg::UuidString(hdr.uuid), pathKey = LowerPathKey(ctx.path);
        for (const std::string& key : { uuidKey, pathKey }) {
            auto it = g_sessionPw.find(key);
            if (it != g_sessionPw.end()) {
                ctx.candidates.push_back(it->second);
                ctx.candidateSources.push_back(g_persistPw.count(key) ? "password store" : "session cache");
            }
        }
        LeaveCriticalSection(&g_pwLock);
        for (const auto& p : ReadPasswordsTxt()) { ctx.candidates.push_back(p); ctx.candidateSources.push_back("Passwords.txt"); }
    }
    if (ctx.nextCandidate < ctx.candidates.size()) {
        pw = ctx.candidates[ctx.nextCandidate];
        ctx.source = ctx.candidateSources[ctx.nextCandidate];
        ++ctx.nextCandidate;
        return true;
    }
    if (ctx.dialogAttempts >= kPasswordTries) return false;
    ++ctx.dialogAttempts;
    dmg::PasswordPrompt p;
    p.fileName = FileNameOf(ctx.path);
    p.detail = dmg::Utf8ToUtf16(dmg::EncSummary(hdr));
    p.attempt = ctx.dialogAttempts;
    p.maxAttempts = kPasswordTries;
    p.lastError = (ctx.dialogAttempts > 1 || !ctx.candidates.empty()) && !lastErr.empty() ? dmg::Utf8ToUtf16(lastErr) : L"";
    p.remember = ctx.remember;
    if (!dmg::ShowPasswordDialog(g_hSelf, ctx.hMainWnd, p)) return false;
    pw = dmg::Utf16ToUtf8(p.password.c_str());
    ctx.remember = p.remember;
    ctx.source = "dialog";
    SecureZeroMemory(p.password.data(), p.password.size() * sizeof(wchar_t));
    return true;
}

// The silent candidates are unlimited; the dialog gets kPasswordTries. Total
// attempts handed to OpenDmg must cover both.
static int MaxAttemptsFor(const PasswordContext& ctx) { return static_cast<int>(ctx.candidates.size()) + kPasswordTries + 8; }

// ---------------------------------------------------------------------------
//  IIO_Init
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//  Substitution reporting. The evidence file is never written; when a chunk
//  cannot be decoded the reader presents zeros in its place. Every such
//  substitution is (1) appended to a per-image report next to the DLL under
//  ImageIO_DMG-reports\, (2) announced in the Messages window (first one in
//  full, then every 50th, then a summary at close), (3) in the TSV log.
// ---------------------------------------------------------------------------

static std::wstring ReportPathFor(const std::wstring& imagePath) {
    std::wstring dir = SelfDir() + L"\\ImageIO_DMG-reports";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring name = FileNameOf(imagePath);
    for (auto& c : name) if (c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|') c = L'_';
    return dir + L"\\" + name + L".substitutions.txt";
}

static void AppendReport(const std::wstring& path, const std::string& line, bool header) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{};
    GetFileSizeEx(h, &size);
    std::string text;
    if (size.QuadPart == 0 || header) {
        text += "# ImageIO_DMG substitution report. The image file was NOT modified. Sector ranges listed\n"
                "# here could not be decoded from the container and were presented to X-Ways as zeros.\n"
                "# Anything X-Ways shows in these ranges (and hashes over them) reflects zeros, not evidence.\n"
                "# columns: timestamp\tsectors (first..last, 512-byte)\tchunk type\treason\n";
    }
    text += line + "\n";
    DWORD w = 0;
    WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &w, nullptr);
    CloseHandle(h);
}

static void OnSubstitution(DmgImage* img, const dmg::Substitution& sb) {
    const uint64_t first = sb.sector, last = sb.sector + sb.count - 1;
    const std::string range = dmg::Format("%llu..%llu", (unsigned long long)first, (unsigned long long)last);
    if (img->reportPath.empty()) {
        img->reportPath = ReportPathFor(img->path);
        AppendReport(img->reportPath, dmg::Format("# image: %s", dmg::Utf16ToUtf8(img->path.c_str()).c_str()), true);
    }
    AppendReport(img->reportPath, IsoTimestampLocal() + "\t" + range + "\t" + dmg::ChunkTypeName(sb.type) + "\t" + sb.reason, false);
    const LONG n = InterlockedIncrement(&img->substitutionsNotified);
    const std::string name = dmg::Utf16ToUtf8(FileNameOf(img->path).c_str());
    if (n == 1) {
        Notify("IIO_Work", 0, dmg::Format("WARNING %s: sectors %s (%llu sectors, %s chunk) could not be %s and are presented as ZEROS. The image file was not modified. Report: %s",
                                          name.c_str(), range.c_str(), (unsigned long long)sb.count, dmg::ChunkTypeName(sb.type),
                                          sb.ioError ? "read from the container" : "decoded", dmg::Utf16ToUtf8(img->reportPath.c_str()).c_str()));
    } else if ((n % 50) == 0) {
        Notify("IIO_Work", 0, dmg::Format("WARNING %s: %ld chunks substituted with zeros so far (latest: sectors %s)", name.c_str(), n, range.c_str()));
    } else {
        Log("IIO_Work", 0, dmg::Format("substitution #%ld sectors %s %s: %s", n, range.c_str(), dmg::ChunkTypeName(sb.type), sb.reason.c_str()));
    }
}

// Returns a state object with IIO_INIT_ERROR_GIVE_UP so X-Ways shows `why`.
// Observed on 21.8 SR-5 (2026-09-03): X-Ways does NOT call IIO_Done for a
// give-up state (contrary to the API doc), so this state and its description
// string live until the DLL unloads — a few hundred bytes per refused image.
// We do not free them ourselves: a build that does call IIO_Done would then
// double-free. X-Ways also re-calls IIO_Init once with the description text in
// lpFilePath; that call declines because the "path" cannot be opened.
static PVOID GiveUp(std::unique_ptr<DmgImage> img, ImageInfo* info, const std::string& why) {
    Log("IIO_Init", img->initSeq, "GIVE_UP: " + why + " | " + dmg::Utf16ToUtf8(img->path.c_str()));
    info->nSize = sizeof(ImageInfo);
    info->nSectorCount = 0;
    info->nSectorSize = 512;
    info->nFlags = IIO_INIT_ERROR_GIVE_UP;
    img->descr = AllocDescr(std::string(NAME) + ": " + why);
    info->lpTextualDescr = img->descr;
    return img.release();
}

extern "C" PVOID __stdcall IIO_Init(HANDLE hMainWnd, LPWSTR lpFilePath, PVOID pHeaderBuf,
                                    DWORD nHeaderBufSize, ImageInfo* pImgInfo, PVOID pReserved) {
    (void)pReserved;
    const LONG seq = InterlockedIncrement(&g_initSeq);
    if (!lpFilePath || !pImgInfo) return nullptr;

    const std::string ext = ExtensionOf(lpFilePath);
    const bool isDmgExt = (ext == "dmg" || ext == "dmgpart" || ext == "udif" || ext == "sparseimage");
    const uint8_t* hdr = static_cast<const uint8_t*>(pHeaderBuf);
    const bool encryptedHeader = dmg::IsEncryptedV2Header(hdr, nHeaderBufSize) || dmg::IsSparseImageHeader(hdr, nHeaderBufSize);
    if (!isDmgExt && !encryptedHeader && IsKnownOtherFormat(ext)) {
        LogVerbose("IIO_Init", seq, "decline (extension ." + ext + ") " + dmg::Utf16ToUtf8(lpFilePath));
        return nullptr;
    }

    auto img = std::make_unique<DmgImage>();
    img->initSeq = seq;
    img->path = lpFilePath;

    PasswordContext pwctx;
    pwctx.hMainWnd = static_cast<HWND>(hMainWnd);
    pwctx.path = img->path;
    pwctx.seq = seq;

    dmg::OpenOptions opts;
    opts.udif.cacheBytes = kCacheBytes;
    DmgImage* imgRaw = img.get();
    opts.udif.onSubstitution = [imgRaw](const dmg::Substitution& sb) { OnSubstitution(imgRaw, sb); };
    opts.passwordProvider = [&](const dmg::EncHeader& h, int attempt, const std::string& lastErr, std::string& pw) {
        return ProvidePassword(pwctx, h, attempt, lastErr, pw);
    };
    opts.maxAttempts = 64;   // the provider enforces its own limits

    std::string message;
    const ULONGLONG tOpen0 = GetTickCount64();
    dmg::OpenStatus st = dmg::OpenDmg(lpFilePath, opts, img->img, message);
    const ULONGLONG openMs = GetTickCount64() - tOpen0;
    if (st == dmg::OpenStatus::NotDmg) {
        LogVerbose("IIO_Init", seq, std::string("decline (") + message + (isDmgExt ? ", .dmg extension" : "") + ") " + dmg::Utf16ToUtf8(lpFilePath));
        return nullptr;
    }
    if (st == dmg::OpenStatus::GiveUp) return GiveUp(std::move(img), pImgInfo, message);

    dmg::OpenedImage& oi = img->img;
    if (oi.encrypted && !oi.passwordUsed.empty()) {
        // Always remember for this X-Ways session (case reopen re-runs IIO_Init);
        // persist (DPAPI) when the analyst left "Remember" ticked.
        const std::string uuidKey = "uuid:" + dmg::UuidString(oi.enc.uuid), pathKey = LowerPathKey(img->path);
        EnterCriticalSection(&g_pwLock);
        g_sessionPw[uuidKey] = oi.passwordUsed;
        g_sessionPw[pathKey] = oi.passwordUsed;
        if (pwctx.remember && pwctx.source == "dialog") {
            g_persistPw[uuidKey] = oi.passwordUsed;
            g_persistPw[pathKey] = oi.passwordUsed;
            SavePersistedPasswords();
        }
        LeaveCriticalSection(&g_pwLock);
        Log("IIO_Init", seq, dmg::Format("unlocked via %s (%s; remember=%d; dialog attempts=%d)", pwctx.source.c_str(),
                                         dmg::EncSummary(oi.enc).c_str(), pwctx.remember ? 1 : 0, pwctx.dialogAttempts));
    }

    // --- Describe + flag ---------------------------------------------------
    DWORD flags = IIO_INIT_READ | IIO_INIT_THREADSAFE | IIO_INIT_UNALIGNED_OK;
    std::string descr = dmg::Format("Apple disk image (%s %s); ", NAME, VERSION);
    uint64_t sectors = oi.reader->Size() / dmg::kSectorSize;

    if (oi.udif) {
        const dmg::BlockMap& bm = oi.udif->Map();
        const dmg::Koly& k = oi.udif->Trailer();
        sectors = bm.totalSectors;

        // DISK vs VOLUME heuristic from the blkx partition names; leave both
        // unset when unsure so X-Ways makes its own determination.
        bool hasScheme = false, singleVolume = false;
        std::string firstFsName;
        size_t nonFree = 0;
        for (const auto& p : bm.partitions) {
            if (NameContains(p.name, "GPT") || NameContains(p.name, "MBR") || NameContains(p.name, "Apple_partition_map") || NameContains(p.name, "Driver"))
                hasScheme = true;
            if (!NameContains(p.name, "Apple_Free") && !NameContains(p.name, "GPT") && !NameContains(p.name, "MBR")) {
                ++nonFree;
                if (firstFsName.empty()) firstFsName = p.name;
            }
        }
        if (!hasScheme && nonFree == 1) {
            for (const auto& p : bm.partitions)
                if (p.name == firstFsName && p.firstSector == 0 &&
                    (NameContains(p.name, "Apple_HFS") || NameContains(p.name, "Apple_APFS") || NameContains(p.name, "Apple_UFS") || NameContains(p.name, "Apple_HFSX")))
                    singleVolume = true;
        }
        if (hasScheme) flags |= IIO_INIT_DISK;
        else if (singleVolume) flags |= IIO_INIT_VOLUME;
        if (bm.hadOverlap) flags |= IIO_INIT_ERROR_MILD;

        std::string comp;
        for (const auto& kv : bm.typeCounts) {
            if (!comp.empty()) comp += ", ";
            comp += dmg::Format("%s %llu", dmg::ChunkTypeName(kv.first), (unsigned long long)kv.second);
        }
        std::string parts;
        size_t shown = 0;
        for (const auto& p : bm.partitions) {
            if (NameContains(p.name, "Apple_Free")) continue;
            if (shown++ >= 6) { parts += ", ..."; break; }
            if (!parts.empty()) parts += ", ";
            parts += p.name;
        }
        descr += dmg::Format("UDIF koly v%u; %zu blkx entries [%s]; chunks: %s; block map from %s",
                             k.version, bm.partitions.size(), parts.c_str(), comp.c_str(), oi.udif->Source().c_str());
    } else {
        // No blkx partition list (sparse image / bundle / encrypted read-write
        // image): the bytes are the disk itself — sniff the layout.
        const std::string layout = SniffLayout(*oi.reader);
        if (layout == "GPT" || layout == "MBR" || layout == "Apple partition map") flags |= IIO_INIT_DISK;
        else if (layout == "HFS+" || layout == "APFS") flags |= IIO_INIT_VOLUME;
        descr += oi.kind + " (" + oi.plaintextKind + (layout.empty() ? "" : "; " + layout) + ")";
    }
    if (oi.kind == "udif-segmented") descr += " [" + oi.plaintextKind + "]";
    if (oi.encrypted) descr += "; " + dmg::EncSummary(oi.enc);
    if (oi.udif && oi.udif->Map().hadOverlap)
        descr += "; VIRTUAL REPAIR: overlapping chunks in the block map were dropped and read as zeros (file not modified)";
    descr += dmg::Format("; %llu MiB", (unsigned long long)((sectors * dmg::kSectorSize) >> 20));
    if (!oi.warnings.empty()) descr += dmg::Format("; %zu warning(s), see log", oi.warnings.size());

    pImgInfo->nSize = sizeof(ImageInfo);
    pImgInfo->nSectorCount = static_cast<INT64>(sectors);
    pImgInfo->nSectorSize = dmg::kSectorSize;
    pImgInfo->nFlags = flags;
    img->descr = AllocDescr(descr);
    pImgInfo->lpTextualDescr = img->descr;

    Log("IIO_Init", seq, dmg::Format("CLAIM kind=%s sectors=%llu flags=0x%04X open_ms=%llu preset_nSize=%lu hdrbuf=%lu | %s | %s",
                                     oi.kind.c_str(), (unsigned long long)sectors, flags, openMs, (unsigned long)pImgInfo->nSize,
                                     (unsigned long)nHeaderBufSize, descr.c_str(), dmg::Utf16ToUtf8(lpFilePath).c_str()));
    for (const auto& w : oi.warnings) Log("IIO_Init", seq, "warning: " + w);
    Notify("IIO_Init", seq, dmg::Format("opened %s (%s, %llu MiB%s)", dmg::Utf16ToUtf8(FileNameOf(img->path).c_str()).c_str(),
                                        oi.kind.c_str(), (unsigned long long)((sectors * dmg::kSectorSize) >> 20),
                                        oi.warnings.empty() ? "" : dmg::Format(", %zu warning(s)", oi.warnings.size()).c_str()));
    if (VERBOSE && oi.udif) {
        const dmg::BlockMap& bm = oi.udif->Map();
        for (size_t i = 0; i < bm.partitions.size(); ++i) {
            const auto& p = bm.partitions[i];
            Log("IIO_Init", seq, dmg::Format("partition %zu id=%lld sector=%llu count=%llu chunks=%zu name=%s",
                                             i, (long long)p.id, (unsigned long long)p.firstSector,
                                             (unsigned long long)p.sectorCount, p.chunkCount, p.name.c_str()));
        }
    }

    // Opt-in integrity verification: IMAGEIO_DMG_VERIFY set (any value) makes
    // IIO_Init read the whole image and check the CRC32s the container carries
    // before the case sees it. Off by default because it reads every byte.
    if (oi.udif && GetEnvironmentVariableW(L"IMAGEIO_DMG_VERIFY", nullptr, 0) > 0) {
        dmg::IByteSource& container = oi.plaintext ? static_cast<dmg::IByteSource&>(*oi.plaintext) : *oi.file;
        dmg::VerifyReport vr = dmg::VerifyAll(container, *oi.udif);
        Log("IIO_Init", seq, "VERIFY " + vr.Detail());
        if (vr.AnyMismatch()) Notify("IIO_Init", seq, "INTEGRITY " + vr.Summary() + " — the image does not match its own checksums; treat its contents with caution");
        else Notify("IIO_Init", seq, "integrity " + vr.Summary());
        if (img->reportPath.empty() && vr.AnyMismatch()) img->reportPath = ReportPathFor(img->path);
        if (!img->reportPath.empty()) AppendReport(img->reportPath, "# integrity check at open:\n" + vr.Detail(), false);
    }
    return img.release();
}

// ---------------------------------------------------------------------------
//  IIO_Work
// ---------------------------------------------------------------------------

static INT64 WorkImpl(DmgImage* img, INT64 nOfs, INT64 nSize, PVOID lpBuffer, PBYTE pFlags) {
    const LONG seq = InterlockedIncrement(&g_workSeq);
    const LONG call = InterlockedIncrement(&img->workCalls);
    const BYTE flagsIn = pFlags ? *pFlags : 0;
    img->NoteThread(GetCurrentThreadId());

    if (nOfs < 0 || nSize < 0 || !lpBuffer) return 0;
    if (flagsIn & IIO_WRITE) {
        InterlockedIncrement(&img->writesRefused);
        if (VERBOSE) Log("IIO_Work", seq, dmg::Format("write refused ofs=%lld size=%lld", (long long)nOfs, (long long)nSize));
        return 0;
    }

    const uint64_t ofs = static_cast<uint64_t>(nOfs), len = static_cast<uint64_t>(nSize);
    if (ofs < img->minOfs) img->minOfs = ofs;
    if (ofs + len > img->maxEnd) img->maxEnd = ofs + len;
    if (len > img->maxReq) img->maxReq = len;
    if (len < img->minReq) img->minReq = len;
    if ((ofs % dmg::kSectorSize) || (len % dmg::kSectorSize)) InterlockedIncrement(&img->unalignedCalls);

    bool sparse = false;
    std::string err;
    const ULONGLONG t0 = TRACE_WORK ? GetTickCount64() : 0;
    uint64_t got = img->img.reader->Read(ofs, lpBuffer, len, (flagsIn & IIO_CHECK_FOR_SPARSE) != 0, &sparse, &err);
    if (g_faultEnabled) {
        const uint64_t fb = g_faultSector * dmg::kSectorSize;
        if (fb >= ofs && fb < ofs + len) {
            if (g_faultZero) {
                std::memset(static_cast<uint8_t*>(lpBuffer) + (fb - ofs), 0, static_cast<size_t>(std::min<uint64_t>(dmg::kSectorSize, ofs + len - fb)));
                Log("IIO_Work", seq, dmg::Format("FAULT zero-filled sector %llu inside [%llu,%llu)", (unsigned long long)g_faultSector, (unsigned long long)ofs, (unsigned long long)(ofs + len)));
            } else {
                got = fb - ofs;
                Log("IIO_Work", seq, dmg::Format("FAULT short read: %llu of %llu bytes for [%llu,%llu)", (unsigned long long)got, (unsigned long long)len, (unsigned long long)ofs, (unsigned long long)(ofs + len)));
            }
        }
    }
    if (pFlags) {
        if (sparse) *pFlags = static_cast<BYTE>(*pFlags | IIO_SPARSE_DETECTED);
        else        *pFlags = static_cast<BYTE>(*pFlags & ~IIO_SPARSE_DETECTED);
    }
    if (!err.empty()) {
        InterlockedIncrement(&img->workErrors);
        Log("IIO_Work", seq, dmg::Format("ERROR ofs=%llu size=%llu got=%llu: %s", (unsigned long long)ofs, (unsigned long long)len, (unsigned long long)got, err.c_str()));
    }
    if (TRACE_WORK) {
        if (call <= kTraceFullCalls) {
            Log("IIO_Work", seq, dmg::Format("ofs=%llu size=%llu got=%llu flags_in=0x%02X sparse=%d ms=%llu",
                                             (unsigned long long)ofs, (unsigned long long)len, (unsigned long long)got,
                                             flagsIn, sparse ? 1 : 0, GetTickCount64() - t0));
        } else if ((call % kTraceEvery) == 0) {
            const dmg::UdifStats* st = img->img.reader->Stats();
            Log("IIO_Work", seq, dmg::Format("summary calls=%ld hits=%lld misses=%lld direct=%lld sparse=%lld bytes_out=%lld errors=%lld unaligned=%ld range=[%llu,%llu) req=[%llu..%llu] threads=%zu",
                                             call, st ? st->cacheHits : 0, st ? st->cacheMisses : 0, st ? st->directDecodes : 0,
                                             st ? st->sparseAnswers : 0, st ? st->bytesOut : 0, st ? st->decodeErrors : 0,
                                             img->unalignedCalls, (unsigned long long)img->minOfs, (unsigned long long)img->maxEnd,
                                             (unsigned long long)img->minReq, (unsigned long long)img->maxReq, img->tids.size()));
        }
    }
    return static_cast<INT64>(got);
}

static void LogWorkException(DmgImage* img, DWORD code, INT64 nOfs, INT64 nSize) {
    InterlockedIncrement(&img->workErrors);
    Log("IIO_Work", 0, dmg::Format("EXCEPTION 0x%08lX ofs=%lld size=%lld", code, (long long)nOfs, (long long)nSize));
}

// SEH guard lives in its own frame: only POD locals here, so no C++ object
// unwinding is needed (C2712). Any decoder crash becomes a 0-byte read
// instead of taking X-Ways down.
static INT64 WorkGuarded(DmgImage* img, INT64 nOfs, INT64 nSize, PVOID lpBuffer, PBYTE pFlags) {
    __try {
        return WorkImpl(img, nOfs, nSize, lpBuffer, pFlags);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LogWorkException(img, GetExceptionCode(), nOfs, nSize);
        return 0;
    }
}

extern "C" INT64 __stdcall IIO_Work(PVOID lpImage, INT64 nOfs, INT64 nSize, PVOID lpBuffer, PBYTE pFlags) {
    DmgImage* img = static_cast<DmgImage*>(lpImage);
    if (!img || img->magic != kStateMagic || !img->img.reader) return 0;
    return WorkGuarded(img, nOfs, nSize, lpBuffer, pFlags);
}

// ---------------------------------------------------------------------------
//  IIO_Done
// ---------------------------------------------------------------------------

extern "C" DWORD __stdcall IIO_Done(PVOID lpImage, LPWSTR lpTextualDescr) {
    const LONG seq = InterlockedIncrement(&g_doneSeq);
    DmgImage* img = static_cast<DmgImage*>(lpImage);
    if (!img || img->magic != kStateMagic) {
        Log("IIO_Done", seq, "called with an unknown image pointer");
        if (lpTextualDescr) HeapFree(GetProcessHeap(), 0, lpTextualDescr);
        return 1;
    }
    if (img->img.reader) {
        if (const dmg::UdifStats* st0 = img->img.reader->Stats(); st0 && st0->substitutedChunks > 0) {
            Notify("IIO_Done", seq, dmg::Format("SUMMARY %s: %lld chunk(s) / %lld sectors could not be decoded and were presented as zeros; the image file was not modified. Report: %s",
                                                dmg::Utf16ToUtf8(FileNameOf(img->path).c_str()).c_str(), st0->substitutedChunks, st0->substitutedSectors,
                                                dmg::Utf16ToUtf8(img->reportPath.c_str()).c_str()));
        }
        const dmg::UdifStats* st = img->img.reader->Stats();
        Log("IIO_Done", seq, dmg::Format("init_seq=%ld kind=%s lifetime_ms=%llu calls=%ld hits=%lld misses=%lld direct=%lld sparse=%lld bytes_out=%lld errors=%ld writes_refused=%ld unaligned=%ld range=[%llu,%llu) req=[%llu..%llu] threads=%zu | %s",
                                         img->initSeq, img->img.kind.c_str(), GetTickCount64() - img->t0, img->workCalls,
                                         st ? st->cacheHits : 0, st ? st->cacheMisses : 0, st ? st->directDecodes : 0,
                                         st ? st->sparseAnswers : 0, st ? st->bytesOut : 0, img->workErrors, img->writesRefused,
                                         img->unalignedCalls, (unsigned long long)img->minOfs, (unsigned long long)img->maxEnd,
                                         (unsigned long long)img->minReq, (unsigned long long)img->maxReq, img->tids.size(),
                                         dmg::Utf16ToUtf8(img->path.c_str()).c_str()));
    } else {
        Log("IIO_Done", seq, dmg::Format("init_seq=%ld (give-up state) | %s", img->initSeq, dmg::Utf16ToUtf8(img->path.c_str()).c_str()));
    }
    img->magic = 0;
    if (lpTextualDescr && lpTextualDescr != img->descr) HeapFree(GetProcessHeap(), 0, lpTextualDescr);
    if (img->descr) HeapFree(GetProcessHeap(), 0, img->descr);
    delete img;
    return 1;
}

// ---------------------------------------------------------------------------
//  DllMain
// ---------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*lpReserved*/) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            g_hSelf = hModule;
            InitializeCriticalSection(&g_logLock);
            InitializeCriticalSection(&g_pwLock);
            DisableThreadLibraryCalls(hModule);
            dmg::DecoderGlobalInit();
            LoadFaultInjection();
            if (g_faultEnabled) Log("DllMain", 0, dmg::Format("FAULT INJECTION ACTIVE: sector %llu mode %s", (unsigned long long)g_faultSector, g_faultZero ? "zero" : "short"));
            g_xwfOutputMessage = reinterpret_cast<fptr_XWF_OutputMessage>(
                GetProcAddress(GetModuleHandleW(nullptr), "XWF_OutputMessage"));
            Log("DllMain", 0, g_xwfOutputMessage ? "XWF_OutputMessage resolved from the host executable"
                                                 : "XWF_OutputMessage not exported by the host executable");
            break;
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&g_pwLock);
            DeleteCriticalSection(&g_logLock);
            break;
    }
    return TRUE;
}
