// Copyright(C) 2017-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "common_utilities.h"
#include "hmac.h"
#include "kdf.h"
#include "nist_kdf.h"
#include "secure_ops.h"

/**
 * Number of bytes in the output of the PRF.
 */
#define NIST_KDF_H_BYTES (HMAC_SHA256_SIZE_BYTES)

/**
 * Number of bits in the output of the PRF.
 */
#define NIST_KDF_H    ((NIST_KDF_H_BYTES)*(BITS_PER_BYTE))

/**
 * Number of bits in the representation of the counter, i.
 */
#define NIST_KDF_R    (sizeof(uint32_t)*(BITS_PER_BYTE))

typedef struct nist_kdf_prf_params
{
    const uint8_t   *key;
    size_t          key_length;
    uint32_t        i;
    const uint8_t   *label;
    size_t          label_length;
    const uint8_t   *context;
    size_t          context_length;
    uint32_t        l;
} nist_kdf_prf_params_t;

static sev_status_t nist_kdf_prf(uint8_t *out, size_t out_length,
                                 const nist_kdf_prf_params_t *params)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    hmac_sha256_t hmac;
    hmac_sha256_ctx_t ctx;
    uint8_t null_byte = '\0';

    if (!out || out_length != NIST_KDF_H_BYTES || !params ||
        !params->key || !params->label)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = hmac_sha256_init(&ctx, params->key, params->key_length);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* The SVC call for SHA256 releases the LSB after each op, so there's no
     * resource leak here, even though we may not call hmac_sha256_final(). */

    status = hmac_sha256_update(&ctx, (uint8_t *)&params->i, sizeof(params->i));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = hmac_sha256_update(&ctx, params->label, params->label_length);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = hmac_sha256_update(&ctx, &null_byte, sizeof(null_byte));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    if (params->context && params->context_length != 0)
    {
        status = hmac_sha256_update(&ctx, params->context, params->context_length);
        if (status != SEV_STATUS_SUCCESS)
        {
            goto end;
        }
    }

    status = hmac_sha256_update(&ctx, (uint8_t *)&params->l, sizeof(params->l));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = hmac_sha256_final(&ctx, &hmac);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    memcpy(out, hmac.hmac, out_length);

end:
    secure_memzero(&hmac, sizeof(hmac));
    return status;
}

sev_status_t nist_kdf(uint8_t *key_out, size_t key_out_length,
                      const uint8_t *key_in, size_t key_in_length,
                      const uint8_t *label, size_t label_length,
                      const uint8_t *context, size_t context_length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t i = 0, offset = 0;

    /* Buffer to collect PRF output */
    uint8_t prf_out[NIST_KDF_H_BYTES];

    /* Length in bits of derived key */
    uint32_t l = key_out_length * BITS_PER_BYTE;

    /* Number of iterations to produce enough derived key bits */
    uint32_t n = ((l-1)/NIST_KDF_H) + 1;

    size_t bytes_left = key_out_length;

    if (!key_out)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    for (i = 1; i <= n; i++)
    {
        nist_kdf_prf_params_t params;

        params.key = key_in;
        params.key_length = key_in_length;
        params.label = label;
        params.label_length = label_length;
        params.context = context;
        params.context_length = context_length;
        params.i = i;
        params.l = l;

        /*
         * Ensure that all of the memory operations above have completed before
         * we continue.
         */
        ARMCC_DSB_ISB();

        /* Calculate a chunk of random data from the PRF */
        status = nist_kdf_prf(prf_out, NIST_KDF_H_BYTES, &params);
        if (status != SEV_STATUS_SUCCESS)
        {
            goto end;
        }

        /* Write out the key bytes */
        if (bytes_left <= NIST_KDF_H_BYTES)
        {
            memcpy(key_out + offset, prf_out, bytes_left);
        }
        else
        {
            memcpy(key_out + offset, prf_out, NIST_KDF_H_BYTES);
            offset += NIST_KDF_H_BYTES;
            bytes_left -= NIST_KDF_H_BYTES;
        }
    }

end:
    secure_memzero(prf_out, sizeof(prf_out));
    return status;
}

#if 1
sev_status_t kdf_derive( uint8_t *key_out, size_t key_out_length,
                         const uint8_t *key_in, size_t key_in_length,
                         const uint8_t *label, size_t label_length,
                         const uint8_t *context, size_t context_length)
{
    return nist_kdf(key_out, key_out_length, key_in, key_in_length, label,
                    label_length, context, context_length);
}
#endif
