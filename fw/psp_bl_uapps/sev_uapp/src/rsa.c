// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>

#include "rsa.h"
#include "sev_hal.h"

bool rsa_pubkey_is_valid(const rsa_pubkey_t *pubkey)
{
    bool is_valid = false;

    if (pubkey && pubkey->modulus_size_bits <= RSA_MOD_SIZE_BYTES*BITS_PER_BYTE)
        is_valid = true;

    return is_valid;
}

sev_status_t rsa_pss_verify(const uint8_t *hash, uint32_t hash_len,
                            const uint8_t *modulus, uint32_t modulus_len,
                            const uint8_t *exp, uint32_t exp_len,
                            const uint8_t *sig)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_rsapss_verify_t rsa_pss;

    if (!hash || !modulus || !exp || !sig || hash_len == 0 || modulus_len == 0 ||
        exp_len == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    rsa_pss.hash = (uint8_t *)hash;
    rsa_pss.hash_len = hash_len;
    rsa_pss.modulus = (uint8_t *)modulus;
    rsa_pss.modulus_len = modulus_len;
    rsa_pss.exponent = (uint8_t *)exp;
    rsa_pss.exp_len = exp_len;
    rsa_pss.sig = (uint8_t *)sig;
    status = sev_hal_rsapss_verify(&rsa_pss);
    if (status != SEV_STATUS_SUCCESS)
        status = SEV_STATUS_BAD_SIGNATURE;

end:
    return status;
}

sev_status_t rsa_pss_verify_msg(const uint8_t *msg, uint32_t msg_len,
                                const uint8_t *modulus, uint32_t modulus_len,
                                const uint8_t *exp, uint32_t exp_len,
                                const uint8_t *sig, const uint32_t algo)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t sha;
    SHA_TYPE sha_type = SHA_TYPE_256;
    size_t sha_len = sizeof(sha);

    if (!msg || !modulus || !exp || !sig)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (msg_len == 0 || modulus_len == 0 || exp_len == 0 ||
        modulus_len > RSA_MOD_SIZE_BYTES || exp_len > RSA_MOD_SIZE_BYTES ||
        modulus_len != exp_len)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (algo == SEV_CERT_ALGO_RSA_SHA256)
        sha_type = SHA_TYPE_256;
    else
        sha_type = SHA_TYPE_384;

    /* Calculate the digest of the input message */
    status = digest_sha(msg, msg_len, &sha, &sha_len, sha_type);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify the digest signature */
    status = rsa_pss_verify(sha.digest, sha_len, modulus, modulus_len, exp,
                            exp_len, sig);

end:
    return status;
}
