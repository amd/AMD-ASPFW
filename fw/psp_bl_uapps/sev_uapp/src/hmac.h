// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "digest.h"
#include "sev_errors.h"

#define HMAC_SHA256_SIZE_BYTES          (DIGEST_SHA256_SIZE_BYTES)
#define HMAC_SHA256_BLOCK_SIZE_BYTES    64
#define HMAC_SHA256_KEY_SIZE_BYTES      64
#define HMAC_SHA512_SIZE_BYTES          (DIGEST_SHA512_SIZE_BYTES)
#define HMAC_SHA512_BLOCK_SIZE_BYTES    128
#define HMAC_SHA512_KEY_SIZE_BYTES      128

typedef struct hmac_sha256
{
    uint8_t hmac[HMAC_SHA256_SIZE_BYTES];
} hmac_sha256_t;

typedef struct hmac_sha256_ctx
{
    digest_sha_ctx_t    digest_ctx;
    uint8_t             key[HMAC_SHA256_KEY_SIZE_BYTES];
    uint32_t            key_len;
} hmac_sha256_ctx_t;

/**
 * Initializes the hmac-sha256 context.
 */
sev_status_t hmac_sha256_init(hmac_sha256_ctx_t *ctx, const void *key, size_t length);

/**
 * Updates the context with the given data.
 *
 *  data   : Input buffer.
 *  length : Input buffer length.
 */
sev_status_t hmac_sha256_update(hmac_sha256_ctx_t *ctx, const void *data, size_t length);

/**
 * Updates the context with the padding and outputs the digest.
 *
 * hmac : Output buffer.
 */
sev_status_t hmac_sha256_final(hmac_sha256_ctx_t *ctx, hmac_sha256_t *hmac);

/**
 * Calculates the HMAC of the 'msg' keyed with 'key'.
 *
 * msg     : Message to verify.             (in)
 * msg_len : Message length in bytes.       (in)
 * key     : Key used to calculate 'hmac'.  (in)
 * key_len : Length of the key in bytes.    (in)
 * hmac    : HMAC result.                   (out)
 */
sev_status_t hmac_sha256(const void *msg, size_t msg_len,
                         const void *key, size_t key_len,
                         hmac_sha256_t *hmac);

/**
 * Verifies that the input 'hmac' is the same as 'valid_hmac'. The comparison
 * is guaranteed to be constant-time regardless of input.
 *
 * hmac       : HMAC to verify.     (in)
 * valid_hmac : expected HMAC.      (in)
 */
sev_status_t hmac_sha256_verify(const hmac_sha256_t *hmac,
                                const hmac_sha256_t *valid_hmac);

/**
 * Verifies that the HMAC of the 'msg' keyed with 'key' is the same as 'hmac'.
 *
 * msg     : Message to verify.             (in)
 * msg_len : Message length in bytes.       (in)
 * key     : Key used to calculate 'hmac'.  (in)
 * key_len : Length of the key in bytes.    (in)
 * hmac    : HMAC to verify.                (in)
 */
sev_status_t hmac_sha256_verify_msg(const void *msg, size_t msg_len,
                                    const void *key, size_t key_len,
                                    const hmac_sha256_t *valid_hmac);

#endif /* HMAC_H */
