// dmg_open.h — one entry point that turns a path into a readable image.
//
// Shared by the DLL (IIO_Init) and the offline harness so both open images
// identically: detect the container, unlock encryption through a caller-
// supplied password provider, then layer UdifSource or RawImageReader on top.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "byte_source.h"
#include "encrypted_source.h"
#include "image_reader.h"
#include "udif_source.h"

namespace dmg {

enum class OpenStatus {
    Ok,        // `out` is usable
    NotDmg,    // not ours — decline silently (return NULL from IIO_Init)
    GiveUp,    // ours, but cannot be opened — `message` says why
};

// Called for each attempt (1-based). Return false to stop trying.
using PasswordProvider = std::function<bool(const EncHeader& hdr, int attempt, const std::string& lastError,
                                            std::string& passwordUtf8)>;

struct OpenOptions {
    UdifOptions udif;
    PasswordProvider passwordProvider;   // null = encrypted images give up
    int maxAttempts = 3;
};

struct OpenedImage {
    std::shared_ptr<IByteSource> file;        // the container on disk
    std::shared_ptr<EncryptedSource> plaintext; // set when encrypted
    std::unique_ptr<IImageReader> reader;     // what IIO_Work reads from
    UdifSource* udif = nullptr;               // non-null when the (plain)text is UDIF
    bool encrypted = false;
    EncHeader enc;
    std::string passwordUsed;                 // UTF-8, for the session cache
    std::string kind;                         // "udif" | "encrypted-udif" | "encrypted-raw"
    std::string plaintextKind;                // for encrypted-raw: "GPT", "HFS+", ...
    std::vector<std::string> warnings;
};

OpenStatus OpenDmg(const wchar_t* path, const OpenOptions& opts, OpenedImage& out, std::string& message);

} // namespace dmg
