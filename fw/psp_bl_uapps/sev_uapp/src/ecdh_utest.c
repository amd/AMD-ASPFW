// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "ecdh.h"
#include "ecdh_utest.h"
#include "sev_trace.h"

sev_status_t ecdh_utest(void)
{
    sev_status_t    status = SEV_STATUS_SUCCESS;

    ecc_keypair_t   lkeypair;
    ecc_keypair_t   rkeypair;
    uint8_t         lsecret[SEV_ECC_CURVE_SIZE_BYTES];
    uint8_t         rsecret[SEV_ECC_CURVE_SIZE_BYTES];

    status = ecdh_keypair_generate(&lkeypair);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecdh_keypair_generate(&rkeypair);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecdh_key_agreement(&lkeypair, (ecc_pubkey_t *)&rkeypair, lsecret, sizeof(lsecret));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecdh_key_agreement(&rkeypair, (ecc_pubkey_t *)&lkeypair, rsecret, sizeof(rsecret));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    // validate the result
    if (memcmp(lsecret, rsecret, sizeof(lsecret)) != 0)
    {
        status = ERR_UNKNOWN;
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("ecdh_utest failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("ecdh_utest succeed!\n");
    }

    return status;
}

