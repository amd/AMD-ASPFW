// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "common_utilities.h"
#include "hmac.h"
#include "secure_ops.h"

#define HMAC_IPAD_VALUE     (0x36)
#define HMAC_OPAD_VALUE     (0x5C)

/**
 * Initializes the digest context.
 */
sev_status_t hmac_sha256_init(hmac_sha256_ctx_t *ctx, const void *key, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t *k_ipad = NULL;        // inner padding - key XORd with ipad
    uint32_t i = 0;
    uint8_t pad_data[HMAC_SHA256_BLOCK_SIZE_BYTES + 32];

    if (!ctx || !key || length == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /*
     * For key sizes bigger than HMAC block size, the HMAC specification
     * requires the key to be hashed prior to using it with i-pad and o-pad.
     * We don't support this mode here.
     */
    if (length > HMAC_SHA256_KEY_SIZE_BYTES)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    k_ipad = (uint8_t *)ALIGN_TO_32_BYTES(pad_data);  /* Make it aligned cache line boundary */

    memset(k_ipad, 0, HMAC_SHA256_BLOCK_SIZE_BYTES);
    memcpy(k_ipad, key, length);
    for (i = 0; i < HMAC_SHA256_BLOCK_SIZE_BYTES; i++)
    {
        k_ipad[i] ^= HMAC_IPAD_VALUE;
    }

    status = digest_sha_init(&ctx->digest_ctx, SHA_TYPE_256);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx->digest_ctx, k_ipad,
                               HMAC_SHA256_BLOCK_SIZE_BYTES);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // save the context
    ctx->key_len = length;
    memcpy(ctx->key, key, length);

end:
    return status;
}

/**
 * Updates the context with the given data.
 *
 *  data  : data buffer
 *  length: can be any length, even 0.
 */
sev_status_t hmac_sha256_update(hmac_sha256_ctx_t *ctx, const void *data, size_t length)
{
    return digest_sha_update(&ctx->digest_ctx, data, length);
}

/**
 * Updates the context with the padding and outputs the digest.
 *
 * data  : input data buffer.
 * length: can be of any size, could be 0.
 * hmac  : doesn't have to be 16 byte aligned.
 */
sev_status_t hmac_sha256_final(hmac_sha256_ctx_t *ctx, hmac_sha256_t *hmac)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t *k_opad = NULL;     // outer padding - key XORd with opad
    uint32_t i = 0;
    uint8_t  pad_data[HMAC_SHA256_BLOCK_SIZE_BYTES + HMAC_SHA256_SIZE_BYTES + 32];
    uint32_t digest_len = 0;
    digest_sha_t *digest = NULL;

    if (!ctx || !hmac)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    k_opad = (uint8_t *)ALIGN_TO_32_BYTES(pad_data);  /* Make it aligned cache line boundary */

    memset(k_opad, 0, HMAC_SHA256_BLOCK_SIZE_BYTES);
    memcpy(k_opad, ctx->key, ctx->key_len);
    for (i = 0; i < HMAC_SHA256_BLOCK_SIZE_BYTES; i++)
    {
        k_opad[i] ^= HMAC_OPAD_VALUE;
    }

    /* Hash(ipad || Message) where "||" is concatenation
     * and Read the value of Hash(ipad || Message) from CCP. */
    digest_len = HMAC_SHA256_BLOCK_SIZE_BYTES;
    digest = (digest_sha_t *)&k_opad[HMAC_SHA256_BLOCK_SIZE_BYTES];
    status = digest_sha_final(&ctx->digest_ctx, digest, &digest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Hash(opad || Hash(ipad || Message)) where "||" is concatenation.
     * and read the final HMAC value from CCP. */
    status = digest_sha_init(&ctx->digest_ctx, SHA_TYPE_256);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx->digest_ctx, k_opad,
                               HMAC_SHA256_BLOCK_SIZE_BYTES +
                               HMAC_SHA256_SIZE_BYTES);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    digest_len = sizeof(*hmac);
    digest = (digest_sha_t *)hmac;
    status = digest_sha_final(&ctx->digest_ctx, digest, &digest_len);

end:
    return status;
}

sev_status_t hmac_sha256(const void *msg, size_t msg_len,
                         const void *key, size_t key_len,
                         hmac_sha256_t *hmac)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    hmac_sha256_ctx_t ctx;

    if (!msg || msg_len == 0 || !hmac || !key || key_len == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = hmac_sha256_init(&ctx, key, key_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, msg, msg_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_final(&ctx, hmac);

end:
    return status;
}

sev_status_t hmac_sha256_verify(const hmac_sha256_t *hmac,
                                const hmac_sha256_t *valid_hmac)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!hmac || !valid_hmac)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (secure_compare(valid_hmac, hmac, sizeof(hmac_sha256_t)) != 0)
        status = SEV_STATUS_BAD_MEASUREMENT;

end:
    return status;
}

sev_status_t hmac_sha256_verify_msg(const void *msg, size_t msg_len,
                                    const void *key, size_t key_len,
                                    const hmac_sha256_t *valid_hmac)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    hmac_sha256_t hmac;

    if (!msg || msg_len == 0 || !valid_hmac || !key || key_len == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&hmac, 0, sizeof(hmac));

    status = hmac_sha256(msg, msg_len, key, key_len, &hmac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (secure_compare(&hmac, valid_hmac, sizeof(hmac)) != 0)
        status = SEV_STATUS_BAD_MEASUREMENT;

end:
    return status;
}
