// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "secure_ops.h"
#include "sev_hal.h"
#include "sev_wrap.h"

/**
 *   Wrap the data
 *
 *   algorithm: secure data is encrypted and HMAC'd as following.
 *       IV is the initial AES counter,
 *       KE is the encryption key,
 *       KI is the integrity key,
 *       M is the plaintext data, then we'd produce C:
 *
 *          C = { IV, AES-CTR(M; KE, IV), HMAC(AES-CTR(M; KE, IV); KI) }
 *
 *   support In Place operation
 */
sev_status_t sev_secure_data_wrap(const cipher_aes_key_t *aes_key,
                                  uint8_t *hmac_key, size_t hmac_key_len,
                                  uint8_t *src, size_t src_len,
                                  uint8_t *dest, size_t *dest_len,
                                  hmac_sha256_t *hmac)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    cipher_aes_iv_t iv;
    cipher_aes_ctr_ctx_t aes_ctx;
    size_t len = 0;
    hmac_sha256_ctx_t sha_ctx;
    const uint32_t empty = 0xFFFFFFFF;

    if (!aes_key || !hmac_key || hmac_key_len == 0 || !src ||
        src_len == 0 || !dest || !dest_len || *dest_len == 0 ||
        *dest_len < src_len + HMAC_SHA256_SIZE_BYTES + sizeof(iv) || !hmac )
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Generate a new random iv that's not all F's, so it will pass the
       backwards-compatibility check in unwrap */
    do {
        status = sev_hal_trng((uint8_t *)&iv, sizeof(iv));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    } while (memcmp(&iv, &empty, sizeof(empty)) == 0);

    status = cipher_aes_ctr_init(&aes_ctx, &iv, aes_key, AES_MODE_ENCRYPT);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    len = src_len;
    status = cipher_aes_ctr_final(&aes_ctx, src, src_len, dest, &len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_init(&sha_ctx, hmac_key, hmac_key_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&sha_ctx, dest, len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&sha_ctx, &iv, sizeof(iv));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_final(&sha_ctx, hmac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Finally, copy the HMAC to dest buffer to make it a completed datablob as a whole */
    memcpy(dest+len, hmac, sizeof(*hmac));

    /* Finally finally, store the random IV */
    memcpy(dest+len+sizeof(*hmac), &iv, sizeof(iv));

end:
    return status;
}

/**
 *   Unwrap the data
 *
 *   support In Place operation
 */
sev_status_t sev_secure_data_unwrap(const cipher_aes_key_t *aes_key,
                                    uint8_t *hmac_key, size_t hmac_key_len,
                                    uint8_t *src, size_t src_len,
                                    uint8_t *dest, size_t *dest_len)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    cipher_aes_iv_t *iv = NULL;
    cipher_aes_ctr_ctx_t aes_ctx;
    hmac_sha256_t hmac;
    size_t len = src_len - sizeof(hmac) - sizeof(*iv);
    hmac_sha256_ctx_t sha_ctx;
    const uint32_t empty = 0xFFFFFFFF;

    if (!aes_key || !hmac_key || hmac_key_len == 0 || !src ||
        src_len == 0 || !dest || !dest_len || *dest_len == 0 ||
        *dest_len < src_len - HMAC_SHA256_SIZE_BYTES - sizeof(*iv))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    iv = (cipher_aes_iv_t *)(src + len + sizeof(hmac));

    status = hmac_sha256_init(&sha_ctx, hmac_key, hmac_key_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&sha_ctx, src, len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (memcmp(iv, &empty, sizeof(empty)) != 0)    /* New method, IV is used */
    {
        status = hmac_sha256_update(&sha_ctx, iv, sizeof(*iv));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else /* Backwards compatibility - old IV was all 0's */
    {
        memset(iv, 0, sizeof(cipher_aes_iv_t));
    }

    status = hmac_sha256_final(&sha_ctx, &hmac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (secure_compare(src + len, &hmac, sizeof(hmac)) != 0)
    {
        /* Failed validation */
        status = SEV_STATUS_SECURE_DATA_INVALID;
        goto end;
    }

    status = cipher_aes_ctr_init(&aes_ctx, iv, aes_key, AES_MODE_DECRYPT);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_aes_ctr_final(&aes_ctx, src, len, dest, dest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}
