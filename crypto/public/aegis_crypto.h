/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * aegis_crypto.h — Cryptographic engine interface.
 *                  AES-256-GCM encryption with AES-NI hardware acceleration.
 *                  ECDH key exchange (Curve25519).
 *                  Hardware fingerprint generation.
 */

#pragma once

#include "../../common/include/types.h"
#include "../../common/include/aegis_status.h"
#include "../../common/include/aegis_config.h"

namespace aegis::crypto {

// ============================================================================
//  AES-256-GCM Engine
// ============================================================================

/// AES-256 expanded key schedule (15 round keys × 16 bytes = 240 bytes)
struct AesKeySchedule {
    AEGIS_ALIGN(16) UINT8 RoundKeys[15 * 16];
};

class AesGcm256 {
public:
    /// Check if CPU supports AES-NI
    static bool IsHardwareAccelerated();
    
    /// Expand a 256-bit key into the key schedule
    static HvStatus ExpandKey(const UINT8 key[32], AesKeySchedule* schedule);
    
    /**
     * Encrypt and authenticate data with AES-256-GCM.
     * 
     * @param plaintext   Input data to encrypt
     * @param ptLen       Length of plaintext in bytes
     * @param aad         Additional Authenticated Data (not encrypted, but authenticated)
     * @param aadLen      Length of AAD
     * @param schedule    Expanded key schedule
     * @param nonce       12-byte nonce (MUST be unique per message)
     * @param ciphertext  Output: encrypted data (same length as plaintext)
     * @param tag         Output: 16-byte authentication tag
     */
    static HvStatus Encrypt(
        const UINT8* plaintext,  UINT32 ptLen,
        const UINT8* aad,        UINT32 aadLen,
        const AesKeySchedule* schedule,
        const UINT8 nonce[12],
        UINT8* ciphertext,
        UINT8 tag[16]
    );
    
    /**
     * Decrypt and verify data with AES-256-GCM.
     * Returns HV_CRYPTO_AUTH_FAILED if tag verification fails.
     */
    static HvStatus Decrypt(
        const UINT8* ciphertext, UINT32 ctLen,
        const UINT8* aad,        UINT32 aadLen,
        const AesKeySchedule* schedule,
        const UINT8 nonce[12],
        const UINT8 tag[16],
        UINT8* plaintext
    );
};

// ============================================================================
//  Curve25519 ECDH Key Exchange
// ============================================================================

class Curve25519 {
public:
    /// Generate a random private key (32 bytes)
    static HvStatus GeneratePrivateKey(UINT8 privateKey[32]);
    
    /// Derive public key from private key
    static HvStatus DerivePublicKey(const UINT8 privateKey[32], UINT8 publicKey[32]);
    
    /// Compute shared secret from our private key and their public key
    static HvStatus ComputeSharedSecret(
        const UINT8 ourPrivateKey[32],
        const UINT8 theirPublicKey[32],
        UINT8 sharedSecret[32]
    );
};

// ============================================================================
//  Hardware Fingerprint
// ============================================================================

class HardwareFingerprint {
public:
    /**
     * Generate a SHA-256 hardware fingerprint from CPU ID, board serial, etc.
     * This fingerprint is used as the root of the key hierarchy.
     * Same hardware → same fingerprint → same master key.
     */
    static HvStatus Generate(UINT8 fingerprint[32]);
    
    /**
     * Derive a master key from hardware fingerprint using HKDF-SHA256.
     * @param fingerprint  32-byte hardware fingerprint
     * @param context      Context string (e.g., "AegisGate-MasterKey-v1")
     * @param contextLen   Length of context string
     * @param masterKey    Output: 32-byte derived master key
     */
    static HvStatus DeriveMasterKey(
        const UINT8 fingerprint[32],
        const char* context, UINT32 contextLen,
        UINT8 masterKey[32]
    );
};

// ============================================================================
//  Session Crypto Manager
// ============================================================================

struct SessionKeys {
    AesKeySchedule EncryptSchedule;   // Key for Agent → HV messages
    AesKeySchedule DecryptSchedule;   // Key for HV → Agent messages
    UINT8  SessionKey[32];            // Raw session key
    UINT64 NonceCounter;              // Auto-incrementing nonce counter
    UINT64 SequenceNumber;            // Anti-replay sequence
};

class SessionCrypto {
public:
    /// Initialize session crypto with a shared secret from ECDH
    static HvStatus InitSession(const UINT8 sharedSecret[32], SessionKeys* keys);
    
    /// Encrypt a message for sending to the Agent
    static HvStatus EncryptMessage(
        SessionKeys* keys,
        const UINT8* plaintext, UINT32 ptLen,
        UINT8* output,          // Header + ciphertext + tag
        UINT32* outputLen
    );
    
    /// Decrypt and verify a message from the Agent
    static HvStatus DecryptMessage(
        SessionKeys* keys,
        const UINT8* input, UINT32 inputLen,
        UINT8* plaintext,
        UINT32* ptLen
    );
};

} // namespace aegis::crypto
