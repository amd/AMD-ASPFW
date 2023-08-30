// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "ecdh.h"
#include "helper.h"
#include "secure_ops.h"
#include "sev_hal.h"

sev_status_t ecdh_keypair_generate(ecc_keypair_t *keypair)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t random[SEV_ECC_CURVE_SIZE_BYTES];    // P384, 48 bytes.

    if (!keypair)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    do
    {
        status = sev_hal_trng(random, sizeof(random));
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }

        status = ecc_keypair_generate_rdata(keypair, ECC_CURVE_NAME_SECP384R1, random, sizeof(random));
        if (status == ERR_INVALID_PARAMS)
        {
            // re-pick the random
            continue;
        }
        else
        {
            break;
        }

    } while (1);

end:
    secure_memzero(random, sizeof(random));
    return status;
}

sev_status_t ecdh_key_agreement(const ecc_keypair_t *lkeypair,
                                const ecc_pubkey_t *rpubkey,
                                uint8_t *secret, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_point_t result;

    if (!lkeypair || !rpubkey || !secret || length < ECC_CURVE_SECP384R1_SIZE_BYTES)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the pubkey (from x86) before using */
    /* Make sure the pubkey and keypair both specify the same curve */
    if (!ecc_pubkey_is_valid(rpubkey) || rpubkey->curve != lkeypair->curve)
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* Calculate h*d*Q, since h is always 1 for P384, we only need to calculate d*Q */
    status = ecc_point_scale(&result, &rpubkey->Q, &lkeypair->d, lkeypair->curve);
    if (status != SEV_STATUS_SUCCESS)
    {
        /* Checking if the result is infinity point has been done implicitly by CCP;
         * if the Point at Infinity is an output, an error-code will be returned. */
        goto end;
    }

    /* CCP output is big-endian, so we need to reverse the bytes */
    status = reverse_bytes(result.x.s, ECC_CURVE_SECP384R1_SIZE_BYTES);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memcpy(secret, result.x.s, ECC_CURVE_SECP384R1_SIZE_BYTES);

end:
    return status;
}
