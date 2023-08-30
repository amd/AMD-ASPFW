// Copyright(C) 2017-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "digest.h"
#include "sev_cert.h"
#include "sev_cert_utest.h"
#include "sev_globals.h"
#include "sev_plat.h"

static sev_cert_t cert;
static sev_cert_keypair_t keys;
static sev_cert_pubkey_t pubkey;

static sev_status_t generate_keypair(uint32_t usage, uint32_t algo,
                                     sev_cert_keypair_t *keys)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_keypair_t kp;

    if (!keys /*|| !usage_is_valid(usage) || !algo_is_valid(algo)*/)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    kp.usage = usage;
    kp.algo = algo;

    switch (algo)
    {
    case SEV_CERT_ALGO_RSA_SHA256:
    case SEV_CERT_ALGO_RSA_SHA384:
        status = ERR_UNIMPLEMENTED;
        goto end;
    case SEV_CERT_ALGO_ECDSA_SHA256:
    case SEV_CERT_ALGO_ECDH_SHA256:
        status = ecdsa_keypair_generate(&kp.keypair.ecdsa);
        break;
    default:
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memcpy(keys, &kp, sizeof(*keys));

end:
    return status;
}

static sev_status_t sev_cert_ecdsa_utest(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = generate_keypair(SEV_CERT_USAGE_OCA, SEV_CERT_ALGO_ECDSA_SHA256, &keys);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_keypair_get_pubkey(&keys, &pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_create(&cert, &pubkey, &keys);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_validate(&cert, &pubkey);

end:
    return status;
}

static sev_status_t oca_utest(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_oca_generate(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_validate(&sev->sev.identity.persistent.oca_cert,
                               &sev->sev.identity.persistent.oca_cert.body.pubkey);

end:
    return status;
}

static sev_status_t pek_utest(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_pubkey_t *cek_pubkey = &pubkey;

    if (!sev || !sev_cert_has_pubkey(&sev->sev.identity.persistent.oca_cert))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_cek_derive(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_pek_generate(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_keypair_get_pubkey(&sev->sev.identity.cek, cek_pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_validate(&sev->sev.identity.persistent.pek_cert, cek_pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_validate(&sev->sev.identity.persistent.pek_cert,
                               &sev->sev.identity.persistent.oca_cert.body.pubkey);

end:
    return status;
}

static sev_status_t pdh_utest(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev || !sev_cert_has_pubkey(&sev->sev.identity.persistent.pek_cert))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_pdh_generate(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_validate(&sev->sev.identity.persistent.pdh_cert,
                               &sev->sev.identity.persistent.pek_cert.body.pubkey);

end:
    return status;
}

static sev_status_t oca_digest_utest(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    static digest_sha_ctx_t ctx;        /* Static to not waste stack space */
    static digest_sha_t last, current;  /* Static to not waste stack space */
    size_t length = 0, i = 0;
    sev_cert_body_t *body = NULL;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_oca_generate(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    body = &sev->sev.identity.persistent.oca_cert.body;
    memset(&current, 0, sizeof(current));

    for (i = 0; i < 100; i++)
    {
        memcpy(&last, &current, sizeof(last));

        status = digest_sha_init(&ctx, SHA_TYPE_256);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = digest_sha_update(&ctx, body, sizeof(*body));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = digest_sha_final(&ctx, &current, &length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        if (i > 0 && memcmp(&last, &current, sizeof(last)) != 0)
        {
            status = ERR_UNKNOWN;
            goto end;
        }
    }

end:
    return status;
}

sev_status_t sev_cert_utest(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = sev_cert_ecdsa_utest();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = oca_digest_utest(&gSev);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = oca_utest(&gSev);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = pek_utest(&gSev);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = pdh_utest(&gSev);

end:
    return status;
}
