// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef RSA_H
#define RSA_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

#define RSA_MOD_SIZE_BYTES        (512)
#define RSA_SIG_SIZE_BYTES        (RSA_MOD_SIZE_BYTES)

typedef struct rsa_keypair
{
    uint32_t modulus_size_bits;
    uint8_t  pub_exp[RSA_MOD_SIZE_BYTES];
    uint8_t  modulus[RSA_MOD_SIZE_BYTES];
} rsa_keypair_t;

typedef struct rsa_pubkey
{
    uint32_t modulus_size_bits;
    uint8_t  pub_exp[RSA_MOD_SIZE_BYTES];
    uint8_t  modulus[RSA_MOD_SIZE_BYTES];
} rsa_pubkey_t;

typedef struct rsa_sig
{
    uint8_t s[RSA_SIG_SIZE_BYTES];
} rsa_sig_t;


/**
 * Validate RSA public key
 *
 * - pubkey : RSA public key to validate.
 */
bool rsa_pubkey_is_valid(const rsa_pubkey_t *pubkey);

/**
 * RSA PSS Verify Digest Signature
 *
 * - modulus and exponent : little-endian
 * - sig                  : little-endian
 */
sev_status_t rsa_pss_verify(const uint8_t *hash, uint32_t hash_len,
                            const uint8_t *modulus, uint32_t modulus_len,
                            const uint8_t *exp, uint32_t exp_len,
                            const uint8_t *sig);

/**
 * RSA PSS Verify Message
 *
 * - modulus and exponent :  little-endian
 * - sig                  :  little-endian
 */
sev_status_t rsa_pss_verify_msg(const uint8_t *msg, uint32_t msg_len,
                                const uint8_t *modulus, uint32_t modulus_len,
                                const uint8_t *exp, uint32_t exp_len,
                                const uint8_t *sig, const uint32_t algo);

#endif /* RSA_H */
