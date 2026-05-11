/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * hardware_fingerprint.cpp — Unique hardware ID generation from CPU and board info.
 *                            Used as root of the cryptographic key hierarchy.
 */

#include "../public/aegis_crypto.h"

namespace aegis::crypto {

// ============================================================================
//  Simple SHA-256 (software, for fingerprint only — not performance critical)
//  Based on FIPS 180-4 specification
// ============================================================================

static const UINT32 SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline UINT32 RotR(UINT32 x, int n) { return (x >> n) | (x << (32 - n)); }
static inline UINT32 Ch(UINT32 x, UINT32 y, UINT32 z) { return (x & y) ^ (~x & z); }
static inline UINT32 Maj(UINT32 x, UINT32 y, UINT32 z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline UINT32 Sig0(UINT32 x) { return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22); }
static inline UINT32 Sig1(UINT32 x) { return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25); }
static inline UINT32 sig0(UINT32 x) { return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3); }
static inline UINT32 sig1(UINT32 x) { return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10); }

static void Sha256(const UINT8* data, UINT32 len, UINT8 hash[32]) {
    UINT32 h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Pad message: append 1 bit, zeros, then 64-bit length
    UINT32 paddedLen = ((len + 9 + 63) / 64) * 64;
    // Use stack buffer (max input for fingerprint is small)
    UINT8 padded[512] = {};
    for (UINT32 i = 0; i < len && i < 448; i++) padded[i] = data[i];
    padded[len] = 0x80;
    UINT64 bitLen = static_cast<UINT64>(len) * 8;
    for (int i = 0; i < 8; i++) {
        padded[paddedLen - 1 - i] = static_cast<UINT8>(bitLen >> (i * 8));
    }
    
    // Process 64-byte blocks
    for (UINT32 block = 0; block < paddedLen; block += 64) {
        UINT32 W[64];
        for (int i = 0; i < 16; i++) {
            W[i] = (static_cast<UINT32>(padded[block + i*4]) << 24) |
                   (static_cast<UINT32>(padded[block + i*4+1]) << 16) |
                   (static_cast<UINT32>(padded[block + i*4+2]) << 8) |
                   (static_cast<UINT32>(padded[block + i*4+3]));
        }
        for (int i = 16; i < 64; i++) {
            W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
        }
        
        UINT32 a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; i++) {
            UINT32 T1 = hh + Sig1(e) + Ch(e,f,g) + SHA256_K[i] + W[i];
            UINT32 T2 = Sig0(a) + Maj(a,b,c);
            hh=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    
    for (int i = 0; i < 8; i++) {
        hash[i*4]   = static_cast<UINT8>(h[i] >> 24);
        hash[i*4+1] = static_cast<UINT8>(h[i] >> 16);
        hash[i*4+2] = static_cast<UINT8>(h[i] >> 8);
        hash[i*4+3] = static_cast<UINT8>(h[i]);
    }
}

// ============================================================================
//  Hardware Fingerprint Generation
// ============================================================================

HvStatus HardwareFingerprint::Generate(UINT8 fingerprint[32]) {
    if (!fingerprint) return HV_INVALID_PARAMETER;
    
    // Collect hardware identifiers via CPUID
    UINT8 hwData[128] = {};
    UINT32 offset = 0;
    
    // CPUID Leaf 0: Vendor string
    UINT32 eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0), "c"(0));
    *reinterpret_cast<UINT32*>(hwData + offset) = ebx; offset += 4;
    *reinterpret_cast<UINT32*>(hwData + offset) = edx; offset += 4;
    *reinterpret_cast<UINT32*>(hwData + offset) = ecx; offset += 4;
    
    // CPUID Leaf 1: Family/Model/Stepping + Feature flags
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));
    *reinterpret_cast<UINT32*>(hwData + offset) = eax; offset += 4;  // Signature
    *reinterpret_cast<UINT32*>(hwData + offset) = ebx; offset += 4;  // Brand/APIC
    
    // CPUID Leaf 0x80000002-4: Processor brand string (48 bytes)
    for (UINT32 leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
        asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(leaf), "c"(0));
        *reinterpret_cast<UINT32*>(hwData + offset) = eax; offset += 4;
        *reinterpret_cast<UINT32*>(hwData + offset) = ebx; offset += 4;
        *reinterpret_cast<UINT32*>(hwData + offset) = ecx; offset += 4;
        *reinterpret_cast<UINT32*>(hwData + offset) = edx; offset += 4;
    }
    
    // Add a salt/version to prevent rainbow table attacks
    const char* salt = "AegisGate-HW-FP-v1";
    for (int i = 0; salt[i] && offset < 120; i++, offset++) {
        hwData[offset] = static_cast<UINT8>(salt[i]);
    }
    
    // SHA-256 hash of all collected data
    Sha256(hwData, offset, fingerprint);
    
    return HV_SUCCESS;
}

HvStatus HardwareFingerprint::DeriveMasterKey(
    const UINT8 fingerprint[32],
    const char* context, UINT32 contextLen,
    UINT8 masterKey[32]
) {
    if (!fingerprint || !context || !masterKey) return HV_INVALID_PARAMETER;
    
    // Simple HKDF-Extract: PRK = SHA-256(salt || fingerprint)
    UINT8 prk[32];
    UINT8 extractInput[96] = {};
    // Salt = "AegisGate-HKDF-v1"
    const char* salt = "AegisGate-HKDF-v1";
    UINT32 off = 0;
    for (int i = 0; salt[i] && off < 32; i++, off++)
        extractInput[off] = static_cast<UINT8>(salt[i]);
    for (int i = 0; i < 32; i++)
        extractInput[off + i] = fingerprint[i];
    Sha256(extractInput, off + 32, prk);
    
    // HKDF-Expand: OKM = SHA-256(PRK || context || 0x01)
    UINT8 expandInput[128] = {};
    off = 0;
    for (int i = 0; i < 32; i++) expandInput[off++] = prk[i];
    for (UINT32 i = 0; i < contextLen && off < 120; i++) expandInput[off++] = static_cast<UINT8>(context[i]);
    expandInput[off++] = 0x01;
    Sha256(expandInput, off, masterKey);
    
    return HV_SUCCESS;
}

// ============================================================================
//  Curve25519 stubs (TODO: full implementation)
// ============================================================================

HvStatus Curve25519::GeneratePrivateKey(UINT8 privateKey[32]) {
    // TODO: Use RDRAND for random key generation
    // For now, use TSC-based pseudo-random (NOT cryptographically secure)
    UINT32 lo, hi;
    for (int i = 0; i < 32; i += 8) {
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        UINT64 val = (static_cast<UINT64>(hi) << 32) | lo;
        for (int j = 0; j < 8 && (i+j) < 32; j++) {
            privateKey[i+j] = static_cast<UINT8>(val >> (j * 8));
        }
    }
    // Clamp per Curve25519 spec
    privateKey[0] &= 248;
    privateKey[31] &= 127;
    privateKey[31] |= 64;
    return HV_SUCCESS;
}

HvStatus Curve25519::DerivePublicKey(const UINT8[32], UINT8 publicKey[32]) {
    // TODO: Full Curve25519 scalar multiplication
    // Placeholder: copy private key (INSECURE — replace with real impl)
    for (int i = 0; i < 32; i++) publicKey[i] = 0;
    return HV_SUCCESS;
}

HvStatus Curve25519::ComputeSharedSecret(const UINT8[32], const UINT8[32], UINT8 shared[32]) {
    // TODO: Full ECDH computation
    for (int i = 0; i < 32; i++) shared[i] = 0;
    return HV_SUCCESS;
}

} // namespace aegis::crypto
