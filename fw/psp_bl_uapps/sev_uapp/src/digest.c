// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "digest.h"
#include "helper.h"
#include "sev_hal.h"

/**
 * Return the size of digest for intermediate digests
 */
static inline size_t INTERMEDIATE_DIGEST_SIZE(SHA_TYPE sha_type)
{
    if (sha_type == SHA_TYPE_256)
        return DIGEST_SHA256_SIZE_BYTES;
    else
        return DIGEST_STORAGE_BYTES;
}

/**
 * Return the size of digest for final digests
 */
static inline size_t FINAL_DIGEST_SIZE(SHA_TYPE sha_type)
{
    if (sha_type == SHA_TYPE_256)
        return DIGEST_SHA256_SIZE_BYTES;
    else
        return DIGEST_SHA384_SIZE_BYTES;
}

/**
 * Initializes the digest context.
 */
static sev_status_t sha_init(digest_sha_t *digest, SHA_TYPE sha_type)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_sha_t sha;

    if (!digest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sha_type != SHA_TYPE_256 && sha_type != SHA_TYPE_384)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&sha, 0, sizeof(sha));
    sha.data = NULL;
    sha.data_len = 0;
    sha.data_memtype = CCP_HAL_LOCAL;    /* Assume we are using SEV heap space for migration pipeline */
    sha.digest = digest->digest;
    sha.digest_len = INTERMEDIATE_DIGEST_SIZE(sha_type);
    sha.intermediate_digest = NULL;      /* Use default IV */
    sha.intermediate_msg_len = 0;
    sha.som = 1;    /* init */
    sha.eom = 0;
    status = sev_hal_sha(&sha, sha_type);

end:
    return status;
}

/**
 * Updates the context with the given data.
 *
 * 'data'  : must be 16 bytes aligned.
 * 'length': must be a multiple of 64 bytes ( restriction from ccp5.0 hardware! CCP-5.0-TRM page 36. )
 */
static sev_status_t sha_update(digest_sha_ctx_t *ctx, const uint8_t *data,
                               size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_sha_t sha;
    digest_sha_t digest;
    SHA_TYPE sha_type = SHA_TYPE_256;

    if (!ctx || !data || length == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Retrieve SHA type from the context */
    sha_type = ctx->sha_type;
    if (((sha_type == SHA_TYPE_256) && !IS_ALIGNED_TO_64_BYTES(length)) ||
        ((sha_type == SHA_TYPE_384) && !IS_ALIGNED_TO_128_BYTES(length)))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Update */
    memset(&sha, 0, sizeof(sha));
    sha.data = data;
    sha.data_len = length;
    sha.data_memtype = CCP_HAL_LOCAL;            /* Assume we are using SEV heap space for migration pipeline */
    sha.digest = digest.digest;
    sha.digest_len = INTERMEDIATE_DIGEST_SIZE(sha_type);
    sha.intermediate_digest = ctx->h.d.digest;     /* Re-establish context with intermediate digest!!! */
    sha.intermediate_msg_len = ctx->length;
    sha.som = 0;
    sha.eom = 0;
    status = sev_hal_sha(&sha, sha_type);
    if (status == SEV_STATUS_SUCCESS)
        memcpy(ctx->h.d.digest, digest.digest, INTERMEDIATE_DIGEST_SIZE(sha_type));

    ctx->length += length;
end:
    return status;
}

/**
 * Updates the context with the padding and outputs the digest.
 *
 * 'data'  : must be 16 bytes aligned.
 * 'length': can be of any size, could be 0.
 * 'digest': don't have to be 16 byte aligned.
 */
static sev_status_t sha_final(digest_sha_ctx_t *ctx, const uint8_t *data,
                              size_t length, digest_sha_t *digest,
                              size_t *digest_len)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t local_digest; // temp output in case digest is ctx->h
    sev_hal_sha_t sha;
    SHA_TYPE sha_type = SHA_TYPE_256;

    if (!ctx || !data || !digest /*|| !digest_len || !IS_ALIGNED_TO_16_BYTES(data)*/)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Retrieve SHA type */
    sha_type = ctx->sha_type;

    /* Final */
    memset(&sha, 0, sizeof(sha));
    sha.data = data;
    sha.data_len = length;
    sha.data_memtype = CCP_HAL_LOCAL;            /* Assume we are using SEV heap space for migration pipeline */
    sha.digest = local_digest.digest;
    sha.digest_len = FINAL_DIGEST_SIZE(sha_type);
    sha.intermediate_digest = ctx->h.d.digest;     /* Re-establish context with intermediate digest!!! */
    sha.intermediate_msg_len = ctx->length;
    sha.som = 0;
    sha.eom = 1;        /* final */
    status = sev_hal_sha(&sha, sha_type);
    if (status == SEV_STATUS_SUCCESS) {

        if (digest_len != NULL) *digest_len = FINAL_DIGEST_SIZE(sha_type);

        /* Copy the final digest to context */
        memcpy(ctx->h.d.digest, local_digest.digest, FINAL_DIGEST_SIZE(sha_type));
        memcpy(digest->digest, local_digest.digest, FINAL_DIGEST_SIZE(sha_type));
    }

    ctx->length += length;
end:
    return status;
}

/* External API interface exposed to SEV user app */

/**
 * Initializes the digest context.
 *
 * Caller must be responsible for donating context memory!
 *
 * Interweaving call is supported!
 *
 * For each digest_* call, low-level crypto resource is allocated
 * and release upon completion as one-shot business!
 */
sev_status_t digest_sha_init(digest_sha_ctx_t *ctx, SHA_TYPE sha_type)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!ctx || ((sha_type != SHA_TYPE_256 && sha_type != SHA_TYPE_384)))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(ctx, 0, sizeof(*ctx));

    ctx->sha_type = sha_type;

    /* Initialize with default IV */
    status = sha_init(&ctx->h.d, sha_type);
end:
    return status;
}

/**
 * Updates the context with the given data.
 *
 * 'data'  : data buffer to hash.
 * 'length': length of the input data.
 */
sev_status_t digest_sha_update(digest_sha_ctx_t *ctx, const void *data, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t block_size = 0;
    uint8_t *input = (uint8_t *)data;

    if (!ctx || !data)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Retrieve SHA type from context */
    block_size = (ctx->sha_type == SHA_TYPE_256) ?
        SHA256_BLOCK_SIZE_BYTES : SHA384_BLOCK_SIZE_BYTES;

    /* Append current update's data to any data left over from a prior update's
     * incomplete block. Do sha_update the block if it's complete now.
     */
    if (ctx->bytes_used > 0) {
        /* Fill unused part of the buffer */
        size_t len = block_size - ctx->bytes_used;
        if (len > length) {
            /* We do not end up with a full block. Just append */
            memcpy (&ctx->msg_block[ctx->bytes_used], input, length);
            ctx->bytes_used += length;
            goto end;
        }
        memcpy (&ctx->msg_block[ctx->bytes_used], input, len);
        input += len;
        length -= len;
        status = sha_update(ctx, &ctx->msg_block[0], block_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    ctx->bytes_used = length & (block_size - 1);  /* Calculate partial block size remains */
    length -= ctx->bytes_used;                    /* length now is multiple of block size, or 0. */

    /* Process any blocks we can. */
    if (length > 0)
    {
        status = sha_update(ctx, input, length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        input += length;
    }
    memcpy (&ctx->msg_block[0], input, ctx->bytes_used);

end:
    return status;
}

/**
 * Updates the context with the padding and calculates the final digest.
 *
 * digest    : output buffer for the final digest.
 * digest_len: length of the output buffer.
 */
sev_status_t digest_sha_final(digest_sha_ctx_t *ctx,
                              digest_sha_t *digest, size_t *digest_len)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!ctx || !digest || !digest_len)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Hash the final data with padding, and get back the final digest */
    status = sha_final(ctx, ctx->msg_block, ctx->bytes_used, digest, digest_len);
    ctx->bytes_used = 0;

end:
    return status;
}

/**
 * Calculate the complete SHA256/SHA384 digest of the input message.
 *
 * msg       : message buffer to hash.
 * msg_len   : length of the input message.
 * digest    : output buffer for the final digest.
 * digest_len: length of the output buffer.
 */
sev_status_t digest_sha(const void *msg, size_t msg_len,
                        digest_sha_t *digest, size_t *digest_len,
                        SHA_TYPE sha_type)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_ctx_t ctx;

    if (!msg || msg_len == 0 || !digest || !digest_len || *digest_len == 0 ||
        (sha_type != SHA_TYPE_256 && sha_type != SHA_TYPE_384))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = digest_sha_init(&ctx, sha_type);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, msg, msg_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_final(&ctx, digest, digest_len);

end:
    return status;
}
