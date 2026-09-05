// dmg_decoder.h — per-chunk decompression for every UDIF chunk type.
//
//   zero / ignore -> memset      raw   -> memcpy
//   ADC           -> hand-rolled (Apple Data Compression, ~40 lines)
//   zlib          -> miniz tinfl  bzip2 -> libbz2
//   LZFSE         -> Apple lzfse  LZMA  -> xz-embedded (chunks are .xz streams)
//
// Every decoder is re-entrant: state lives on the stack or in per-call heap
// allocations, never in globals, so IIO_Work can run on many threads at once.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dmg {

// One-time process-level initialisation (CRC tables). Safe to call repeatedly.
void DecoderGlobalInit();

// Decodes `inLen` bytes of a chunk of `type` into exactly `outLen` bytes.
// Fails if the decoder produces a different length.
bool DecodeChunk(uint32_t type, const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, std::string& err);

// Exposed for the harness / tests.
bool AdcDecode(const uint8_t* in, size_t inLen, uint8_t* out, size_t outLen, size_t& produced);

// True when this build can decode `type` (all UDIF types in v1).
bool ChunkTypeSupported(uint32_t type);

} // namespace dmg
