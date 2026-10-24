// ============================================================================
// gen_randomx_vectors.cpp
//
// Standalone C++ vector generator for OwnChain M1-C2 RandomX golden vectors.
//
// Calls the upstream RandomX v1.2.3 C API directly (vendored under
// vendor/randomx/), without using the Rust wrapper.
//
// Build (GCC / Clang on Linux / macOS):
//   g++ -std=c++11 -O2 -I vendor/randomx/src \
//       tools/gen_randomx_vectors.cpp \
//       vendor/randomx/src/*.cpp vendor/randomx/src/*.c \
//       vendor/randomx/src/blake2/blake2b.c \
//       -o tools/gen_randomx_vectors -lpthread
//
// Build (MSVC on Windows x86_64):
//   call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
//   cl /nologo /std:c++14 /O2 /MD /I vendor\randomx\src /EHsc tools\gen_randomx_vectors.cpp \
//      /Fe:tools\gen_randomx_vectors.exe /link /LIBPATH:target\debug\build\ownchain-<hash>\out\lib randomx.lib advapi32.lib
//
// Usage:
//   ./gen_randomx_vectors > docs/test-vectors-m1c2-randomx.json
// ============================================================================

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

#include "randomx.h"

static const size_t HEADER_LEN = 170;
static const char* OWNCHAIN_ARGON_SALT = "OwnChain-PoW-v1";

static void hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned int v;
        sscanf(hex + 2 * i, "%02x", &v);
        out[i] = static_cast<uint8_t>(v);
    }
}

static void bytes_to_hex(const uint8_t* data, size_t len, char* out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = hex_chars[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = hex_chars[data[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static void build_header(uint8_t* header, uint64_t height, uint64_t nonce) {
    memset(header, 0, HEADER_LEN);
    header[0] = 0x01;  // version = 1
    for (int i = 0; i < 8; i++) {
        header[34 + i] = static_cast<uint8_t>((height >> (8 * i)) & 0xFF);
    }
    uint64_t timestamp = 1792454400ULL;
    for (int i = 0; i < 8; i++) {
        header[138 + i] = static_cast<uint8_t>((timestamp >> (8 * i)) & 0xFF);
    }
    header[146] = 0x01;  // difficulty = 1
    for (int i = 0; i < 8; i++) {
        header[162 + i] = static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF);
    }
}

static uint64_t key_height(uint64_t h) {
    if (h < 64) return 0;
    return 2048 * ((h - 64) / 2048);
}

int main() {
    uint8_t key[32];
    memset(key, 0, 32);
    key[0] = 0x42;
    key[31] = 0x01;

    printf("{\n");
    printf("  \"description\": \"OwnChain M1-C2 RandomX golden vectors\",\n");
    printf("  \"randomx_version\": \"v1.2.3\",\n");
    printf("  \"source_commit\": \"12f2c2ffe2108d6cf54c391fee33c8bc3646cdab\",\n");
    printf("  \"argon_salt\": \"OwnChain-PoW-v1\",\n");
    printf("  \"header_len\": 170,\n");
    printf("  \"key_hex\": \"");
    {
        char hex[65];
        bytes_to_hex(key, 32, hex);
        printf("%s\",\n", hex);
    }

    randomx_flags flags = randomx_get_flags();

    printf("  \"key_height_boundaries\": [\n");
    uint64_t boundary_heights[] = {63, 64, 2111, 2112, 4160};
    for (size_t i = 0; i < 5; i++) {
        uint64_t h = boundary_heights[i];
        printf("    {\"height\": %llu, \"key_height\": %llu}%s\n",
               (unsigned long long)h,
               (unsigned long long)key_height(h),
               i < 4 ? "," : "");
    }
    printf("  ],\n");

    printf("  \"hash_vectors\": [\n");
    for (size_t i = 0; i < 5; i++) {
        uint64_t height = boundary_heights[i];
        uint8_t header[HEADER_LEN];
        build_header(header, height, 0);

        uint8_t hash_light[32];
        uint8_t hash_fast[32];

        // --- Light mode ---
        randomx_cache* cache_light = randomx_alloc_cache(flags);
        randomx_init_cache(cache_light, key, 32);
        randomx_vm* vm_light = randomx_create_vm(flags, cache_light, nullptr);
        randomx_calculate_hash(vm_light, header, HEADER_LEN, hash_light);
        randomx_destroy_vm(vm_light);
        randomx_release_cache(cache_light);

        // --- Fast mode ---
        randomx_cache* cache_fast = randomx_alloc_cache(flags);
        randomx_init_cache(cache_fast, key, 32);
        randomx_dataset* dataset = randomx_alloc_dataset(flags | RANDOMX_FLAG_FULL_MEM);
        uint32_t item_count = (uint32_t)randomx_dataset_item_count();
        randomx_init_dataset(dataset, cache_fast, 0, item_count);
        randomx_vm* vm_fast = randomx_create_vm(flags | RANDOMX_FLAG_FULL_MEM, nullptr, dataset);
        randomx_calculate_hash(vm_fast, header, HEADER_LEN, hash_fast);
        randomx_destroy_vm(vm_fast);
        randomx_release_dataset(dataset);
        randomx_release_cache(cache_fast);

        char hex_light[65], hex_fast[65];
        bytes_to_hex(hash_light, 32, hex_light);
        bytes_to_hex(hash_fast, 32, hex_fast);

        printf("    {\n");
        printf("      \"height\": %llu,\n", (unsigned long long)height);
        printf("      \"key_height\": %llu,\n", (unsigned long long)key_height(height));
        printf("      \"nonce\": 0,\n");
        printf("      \"hash_light\": \"%s\",\n", hex_light);
        printf("      \"hash_fast\": \"%s\",\n", hex_fast);
        printf("      \"modes_agree\": %s\n", strcmp(hex_light, hex_fast) == 0 ? "true" : "false");
        printf("    }%s\n", i < 4 ? "," : "");
    }
    printf("  ],\n");

    printf("  \"reference_hash\": {\n");
    {
        uint8_t header[HEADER_LEN];
        build_header(header, 0, 0);
        uint8_t hash[32];
        randomx_cache* cache = randomx_alloc_cache(flags);
        randomx_init_cache(cache, key, 32);
        randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);
        randomx_calculate_hash(vm, header, HEADER_LEN, hash);
        randomx_destroy_vm(vm);
        randomx_release_cache(cache);
        char hex_hash[65];
        bytes_to_hex(hash, 32, hex_hash);
        printf("    \"height\": 0,\n");
        printf("    \"nonce\": 0,\n");
        printf("    \"hash_light\": \"%s\"\n", hex_hash);
    }
    printf("  }\n");
    printf("}\n");

    return 0;
}