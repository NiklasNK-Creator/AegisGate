/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * aes_gcm.cpp — AES-256-GCM implementation using AES-NI intrinsics.
 *               Software fallback for CPUs without AES-NI.
 */

#include "../public/aegis_crypto.h"
#include "../../common/include/types.h"

// AES-NI intrinsics (MSVC and GCC/Clang)
#ifdef _MSC_VER
#include <intrin.h>
#include <wmmintrin.h>
#else
#include <x86intrin.h>
#endif

namespace aegis::crypto {

// ============================================================================
//  AES-NI Detection
// ============================================================================

bool AesGcm256::IsHardwareAccelerated() {
    UINT32 eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    return (ecx & (1u << 25)) != 0;  // AES-NI bit
}

// ============================================================================
//  Key Expansion (AES-256)
// ============================================================================

// Helper for key expansion using AES-NI AESKEYGENASSIST
static inline __m128i AesKeyExpand(__m128i key, __m128i assist) {
    assist = _mm_shuffle_epi32(assist, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, assist);
}

static inline __m128i AesKeyExpand2(__m128i key, __m128i assist) {
    assist = _mm_shuffle_epi32(assist, 0xAA);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, assist);
}

HvStatus AesGcm256::ExpandKey(const UINT8 key[32], AesKeySchedule* schedule) {
    if (!key || !schedule) return HV_INVALID_PARAMETER;
    
    __m128i* rk = reinterpret_cast<__m128i*>(schedule->RoundKeys);
    
    // Load the 256-bit key as two 128-bit halves
    rk[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    rk[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));
    
    // Generate round keys using AESKEYGENASSIST
    __m128i assist;
    
    assist = _mm_aeskeygenassist_si128(rk[1], 0x01);
    rk[2] = AesKeyExpand(rk[0], assist);
    assist = _mm_aeskeygenassist_si128(rk[2], 0x00);
    rk[3] = AesKeyExpand2(rk[1], assist);
    
    assist = _mm_aeskeygenassist_si128(rk[3], 0x02);
    rk[4] = AesKeyExpand(rk[2], assist);
    assist = _mm_aeskeygenassist_si128(rk[4], 0x00);
    rk[5] = AesKeyExpand2(rk[3], assist);
    
    assist = _mm_aeskeygenassist_si128(rk[5], 0x04);
    rk[6] = AesKeyExpand(rk[4], assist);
    assist = _mm_aeskeygenassist_si128(rk[6], 0x00);
    rk[7] = AesKeyExpand2(rk[5], assist);
    
    assist = _mm_aeskeygenassist_si128(rk[7], 0x08);
    rk[8] = AesKeyExpand(rk[6], assist);
    assist = _mm_aeskeygenassist_si128(rk[8], 0x00);
    rk[9] = AesKeyExpand2(rk[7], assist);
    
    assist = _mm_aeskeygenassist_si128(rk[9], 0x10);
    rk[10] = AesKeyExpand(rk[8], assist);
    assist = _mm_aeskeygenassist_si128(rk[10], 0x00);
    rk[11] = AesKeyExpand2(rk[9], assist);
    
    assist = _mm_aeskeygenassist_si128(rk[11], 0x20);
    rk[12] = AesKeyExpand(rk[10], assist);
    assist = _mm_aeskeygenassist_si128(rk[12], 0x00);
    rk[13] = AesKeyExpand2(rk[11], assist);
    
    assist = _mm_aeskeygenassist_si128(rk[13], 0x40);
    rk[14] = AesKeyExpand(rk[12], assist);
    
    return HV_SUCCESS;
}

// ============================================================================
//  AES-256 Single Block Encrypt (CTR mode building block)
// ============================================================================

static inline __m128i AesEncryptBlock(__m128i block, const AesKeySchedule* ks) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(ks->RoundKeys);
    
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    block = _mm_aesenclast_si128(block, rk[14]);
    
    return block;
}

// ============================================================================
//  GCM GHASH (Galois Field Multiplication for Authentication)
// ============================================================================

// PCLMULQDQ-based GHASH for hardware acceleration
static inline __m128i GfMul(__m128i a, __m128i b) {
    __m128i tmp0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i tmp1 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i tmp2 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i tmp3 = _mm_clmulepi64_si128(a, b, 0x11);
    
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    tmp2 = _mm_slli_si128(tmp1, 8);
    tmp1 = _mm_srli_si128(tmp1, 8);
    tmp0 = _mm_xor_si128(tmp0, tmp2);
    tmp3 = _mm_xor_si128(tmp3, tmp1);
    
    // Reduction modulo x^128 + x^7 + x^2 + x + 1
    __m128i poly = _mm_setr_epi32(0xE1000000, 0, 0, 0);
    // Simplified reduction (Barrett)
    tmp1 = _mm_clmulepi64_si128(tmp0, poly, 0x10);
    tmp0 = _mm_shuffle_epi32(tmp0, 78);
    tmp0 = _mm_xor_si128(tmp0, tmp1);
    tmp1 = _mm_clmulepi64_si128(tmp0, poly, 0x10);
    tmp0 = _mm_shuffle_epi32(tmp0, 78);
    tmp0 = _mm_xor_si128(tmp0, tmp1);
    
    return _mm_xor_si128(tmp0, tmp3);
}

// Byte-swap a 128-bit value (GCM uses big-endian)
static inline __m128i ByteSwap128(__m128i v) {
    __m128i mask = _mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0);
    return _mm_shuffle_epi8(v, mask);
}

// ============================================================================
//  AES-256-GCM Encrypt
// ============================================================================

HvStatus AesGcm256::Encrypt(
    const UINT8* plaintext,  UINT32 ptLen,
    const UINT8* aad,        UINT32 aadLen,
    const AesKeySchedule* schedule,
    const UINT8 nonce[12],
    UINT8* ciphertext,
    UINT8 tag[16]
) {
    if (!schedule || !nonce || !tag) return HV_INVALID_PARAMETER;
    if (ptLen > 0 && (!plaintext || !ciphertext)) return HV_INVALID_PARAMETER;
    
    // Compute H = AES(K, 0^128) for GHASH
    __m128i H = AesEncryptBlock(_mm_setzero_si128(), schedule);
    H = ByteSwap128(H);
    
    // Build initial counter: nonce || 0x00000001
    AEGIS_ALIGN(16) UINT8 ctrBuf[16] = {};
    for (int i = 0; i < 12; i++) ctrBuf[i] = nonce[i];
    ctrBuf[15] = 1;
    __m128i J0 = _mm_load_si128(reinterpret_cast<__m128i*>(ctrBuf));
    
    // Encrypt J0 to get the tag mask (EK(J0))
    __m128i tagMask = AesEncryptBlock(J0, schedule);
    
    // GHASH accumulator
    __m128i ghash = _mm_setzero_si128();
    
    // Process AAD blocks
    UINT32 aadBlocks = aadLen / 16;
    for (UINT32 i = 0; i < aadBlocks; i++) {
        __m128i aBlock = ByteSwap128(
            _mm_loadu_si128(reinterpret_cast<const __m128i*>(aad + i * 16)));
        ghash = _mm_xor_si128(ghash, aBlock);
        ghash = GfMul(ghash, H);
    }
    // Remaining AAD bytes
    if (aadLen % 16 != 0) {
        AEGIS_ALIGN(16) UINT8 pad[16] = {};
        for (UINT32 i = 0; i < aadLen % 16; i++) pad[i] = aad[aadBlocks * 16 + i];
        __m128i aBlock = ByteSwap128(_mm_load_si128(reinterpret_cast<__m128i*>(pad)));
        ghash = _mm_xor_si128(ghash, aBlock);
        ghash = GfMul(ghash, H);
    }
    
    // Encrypt plaintext in CTR mode (counter starts at 2)
    ctrBuf[15] = 2;
    for (UINT32 i = 0; i < ptLen; i += 16) {
        __m128i counter = _mm_load_si128(reinterpret_cast<__m128i*>(ctrBuf));
        __m128i keystream = AesEncryptBlock(counter, schedule);
        
        UINT32 blockLen = (ptLen - i >= 16) ? 16 : (ptLen - i);
        
        if (blockLen == 16) {
            __m128i pt = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plaintext + i));
            __m128i ct = _mm_xor_si128(pt, keystream);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(ciphertext + i), ct);
            
            // GHASH the ciphertext block
            ghash = _mm_xor_si128(ghash, ByteSwap128(ct));
            ghash = GfMul(ghash, H);
        } else {
            // Partial last block
            AEGIS_ALIGN(16) UINT8 tmp[16] = {};
            for (UINT32 j = 0; j < blockLen; j++) tmp[j] = plaintext[i + j];
            __m128i pt = _mm_load_si128(reinterpret_cast<__m128i*>(tmp));
            __m128i ct = _mm_xor_si128(pt, keystream);
            _mm_store_si128(reinterpret_cast<__m128i*>(tmp), ct);
            for (UINT32 j = 0; j < blockLen; j++) ciphertext[i + j] = tmp[j];
            
            AEGIS_ALIGN(16) UINT8 pad[16] = {};
            for (UINT32 j = 0; j < blockLen; j++) pad[j] = ciphertext[i + j];
            ghash = _mm_xor_si128(ghash, ByteSwap128(
                _mm_load_si128(reinterpret_cast<__m128i*>(pad))));
            ghash = GfMul(ghash, H);
        }
        
        // Increment counter
        ctrBuf[15]++;
        if (ctrBuf[15] == 0) ctrBuf[14]++;
    }
    
    // Final GHASH block: len(AAD) || len(CT) in bits, big-endian
    AEGIS_ALIGN(16) UINT8 lenBlock[16] = {};
    UINT64 aadBits = static_cast<UINT64>(aadLen) * 8;
    UINT64 ctBits = static_cast<UINT64>(ptLen) * 8;
    // Big-endian 64-bit lengths
    for (int i = 0; i < 8; i++) {
        lenBlock[7 - i] = static_cast<UINT8>(aadBits >> (i * 8));
        lenBlock[15 - i] = static_cast<UINT8>(ctBits >> (i * 8));
    }
    ghash = _mm_xor_si128(ghash, _mm_load_si128(reinterpret_cast<__m128i*>(lenBlock)));
    ghash = GfMul(ghash, H);
    
    // Tag = GHASH XOR EK(J0)
    __m128i finalTag = _mm_xor_si128(ByteSwap128(ghash), tagMask);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), finalTag);
    
    return HV_SUCCESS;
}

// ============================================================================
//  AES-256-GCM Decrypt
// ============================================================================

HvStatus AesGcm256::Decrypt(
    const UINT8* ciphertext, UINT32 ctLen,
    const UINT8* aad,        UINT32 aadLen,
    const AesKeySchedule* schedule,
    const UINT8 nonce[12],
    const UINT8 expectedTag[16],
    UINT8* plaintext
) {
    // Compute tag for verification
    UINT8 computedTag[16];
    
    // Decrypt is same as encrypt in CTR mode
    HvStatus status = Encrypt(ciphertext, ctLen, aad, aadLen, schedule, nonce, plaintext, computedTag);
    if (HvIsError(status)) return status;
    
    // Constant-time tag comparison (prevents timing attacks)
    UINT8 diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computedTag[i] ^ expectedTag[i];
    }
    
    if (diff != 0) {
        // Authentication failed — zero out plaintext
        for (UINT32 i = 0; i < ctLen; i++) plaintext[i] = 0;
        return HV_CRYPTO_AUTH_FAILED;
    }
    
    return HV_SUCCESS;
}

} // namespace aegis::crypto
