// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "cipher.h"
#include "helper.h"
#include "secure_ops.h"
#include "sev_hal.h"

static bool mode_is_valid(cipher_aes_mode_t mode)
{
    bool result = false;

    switch (mode)
    {
        case AES_MODE_DECRYPT:
        case AES_MODE_ENCRYPT:
            result = true;
            break;
        default:
            result = false;
    }

    return result;
}

/**
 * Implements AES-CTR init.
 *
 * 'ctx': output, pointer to a pointer of context provided by crypto layer.
 */
sev_status_t cipher_aes_ctr_init(cipher_aes_ctr_ctx_t *ctx,
                                 const cipher_aes_iv_t *counter,
                                 const cipher_aes_key_t *key,
                                 const cipher_aes_mode_t mode)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!ctx || !counter || !key || !mode_is_valid(mode))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(ctx, 0, sizeof(*ctx));
    memcpy(&ctx->counter, counter, sizeof(ctx->counter));
    memcpy(&ctx->key, key, sizeof(ctx->key));
    ctx->mode = mode;

end:
    return status;
}

/**
 * Implements AES-CTR update.
 *
 * 'ctx': input/output of intermediate context IV
 * 'src_len': must be a multiple of 16 bytes (i.e. 128-bits) so there's no padding
 * 'src' and 'dest': the data must be 16 bytes aligned so there's no padding.
 *
 * support In Place operation (src==dest)!!!
 */
sev_status_t cipher_aes_ctr_update(cipher_aes_ctr_ctx_t *ctx,
                                   const uint8_t *src, uint32_t src_len,
                                   uint8_t *dest, uint32_t *dest_len)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_aes_t aes_params;
    sev_hal_aes_mode_t aes_mode = CCP_HAL_AES_MODE_DECRYPT;

    if (!ctx || !src || src_len == 0 || !dest || !dest_len || *dest_len == 0 ||
        src_len > *dest_len || !mode_is_valid(ctx->mode) ||
        !IS_ALIGNED_TO_16_BYTES(src_len))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    // Call HAL layer to get result
    aes_params.iv = ctx->counter.iv;
    aes_params.iv_length = sizeof(ctx->counter.iv);
    aes_params.key = (const uint8_t *)ctx->key.key;
    aes_params.key_length = sizeof(ctx->key.key);
    aes_params.key_memtype = CCP_HAL_LOCAL;
    aes_params.src = src;
    aes_params.src_length = src_len;
    aes_params.src_memtype = CCP_HAL_LOCAL;     /* Assume we are using SEV heap space for migration pipeline */
    aes_params.dest = (const uint8_t *)dest;
    aes_params.dest_length = *dest_len;
    aes_params.dest_memtype = CCP_HAL_LOCAL;    /* Assume we are using SEV heap space for migration pipeline */
    aes_params.aes_alg = CCP_HAL_AES_ALG_CTR;   /* AES CTR */

    if (ctx->mode == AES_MODE_DECRYPT)
        aes_mode = CCP_HAL_AES_MODE_DECRYPT;
    else
        aes_mode = CCP_HAL_AES_MODE_ENCRYPT;
    aes_params.aes_mode = aes_mode;

    /* Intermediate IV will be updated in this call */
    status = sev_hal_aes_generic(&aes_params);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    *dest_len = src_len;

end:
    return status;
}

/**
 * Implements AES-CTR final.
 *
 * 'ctx': input of final IV, note: this final IV cannot be used as context IV if src_len is not aligned to 16.
 * 'src_len': could be 0, or anything. Does not have to be multiple of 16 bytes.
 * 'src' and 'dest': must be 16 bytes aligned.
 *
 * support In Place operation (src==dest)!!!
 */
sev_status_t cipher_aes_ctr_final(cipher_aes_ctr_ctx_t *ctx,
                                  const uint8_t *src, uint32_t src_len,
                                  uint8_t *dest, uint32_t *dest_len)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t dest_size = 0, bytes_written = 0;

    if (!ctx || !src || !dest || !dest_len || !mode_is_valid(ctx->mode))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (src_len == 0)        /* Nothing to do */
        goto end;

    /* Since src_len != 0, now we can do more check against src and dest */
    dest_size = *dest_len;
    if (src_len > dest_size || dest_size == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (IS_ALIGNED_TO_16_BYTES(src_len))
    {
        /* Aligned to 16, directly call update. It may have worked, so still
         * inc counters, but pass back error */
        status = cipher_aes_ctr_update(ctx, src, src_len, dest, &dest_size);
        bytes_written += dest_size;
    }
    else
    {
        /* Not aligned to 16 */
        size_t len = src_len & (~0x0000000F);
        size_t len_leftover = src_len - len;
        uint8_t padding[CIPHER_AES_BLOCK_SIZE_BYTES];
        size_t padding_len = sizeof(padding);

        if (len != 0)
        {
            status = cipher_aes_ctr_update(ctx, src, len, dest, &dest_size);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            bytes_written += dest_size;
        }

        /* Pad to 16 bytes before processing */
        memset(padding, 0, sizeof(padding));
        memcpy(padding, src + len, len_leftover);

        /* In-place update for the padded 16 bytes */
        status = cipher_aes_ctr_update(ctx, padding, padding_len,
                                       padding, &padding_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Copy the data to dest buffer */
        memcpy(dest + bytes_written, padding, len_leftover);
        bytes_written += len_leftover;

        /* Attention! cache operation may be required if dest buffer is in DRAM */
    }

    *dest_len = bytes_written;

end:
    if (ctx)
    {
        /* Clean up */
        secure_memzero(ctx, sizeof(*ctx));
        ctx->mode = AES_MODE_INVALID;
    }

    return status;
}
