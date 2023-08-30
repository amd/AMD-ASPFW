// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "helper.h"
#include "sev_cert.h"
#include "sev_mcmd.h"

#define SEV_CERT_VERSION        (0x1)
#define SEV_CERT_MAX_SIGNATURES (2)

static bool algo_is_valid(uint32_t algo)
{
    /*
     * Since the algorithm enumerations are numerically contiguous,
     * we can simply check that the algo lies between the limit values.
     */
    return algo < SEV_CERT_ALGO_LIMIT && algo != SEV_CERT_ALGO_INVALID;
}

static bool usage_is_valid(uint32_t usage)
{
    bool is_valid = true;

    /*
     * Since the usage enumerations are not numerically contiguous,
     * we need to check each possible value.
     */
    switch (usage)
    {
    case SEV_CERT_USAGE_ARK:
    case SEV_CERT_USAGE_ASK:
    case SEV_CERT_USAGE_OCA:
    case SEV_CERT_USAGE_PEK:
    case SEV_CERT_USAGE_PDH:
    case SEV_CERT_USAGE_CEK:
        is_valid = true;
        break;
    default:
        is_valid = false;
    }

    return is_valid;
}

static bool key_has_usage(const sev_cert_pubkey_t *key, uint32_t usage)
{
    return key && (key->usage == usage);
}

static bool key_has_algo(const sev_cert_pubkey_t *key, uint32_t algo)
{
    return key && (key->algo == algo);
}

static bool pubkey_is_valid(const sev_cert_pubkey_t *pubkey)
{
    bool is_valid = false;

    if (!pubkey)
        goto end;

    is_valid = usage_is_valid(pubkey->usage);
    if (!is_valid)
        goto end;

    switch (pubkey->algo)
    {
    case SEV_CERT_ALGO_RSA_SHA256:
    case SEV_CERT_ALGO_RSA_SHA384:
        is_valid = rsa_pubkey_is_valid(&pubkey->key.rsa);
        break;
    case SEV_CERT_ALGO_ECDSA_SHA256:
    case SEV_CERT_ALGO_ECDH_SHA256:
    case SEV_CERT_ALGO_ECDSA_SHA384:
    case SEV_CERT_ALGO_ECDH_SHA384:
        is_valid = ecc_pubkey_is_valid(&pubkey->key.ecdsa);
        break;
    default:
        is_valid = false;
    }

end:
    return is_valid;
}

bool sev_cert_has_pubkey(const sev_cert_t *cert)
{
    return cert && cert->body.pubkey.usage != SEV_CERT_USAGE_INVALID;
}

sev_status_t sev_cert_keypair_get_pubkey(const sev_cert_keypair_t *keypair,
                                         sev_cert_pubkey_t *pubkey)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!keypair || !pubkey)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /*
     * To avoid exposing the private key here, copy each element of the key
     * individually and zero the rest.
     */
    memset(pubkey, 0, sizeof(*pubkey));
    pubkey->usage = keypair->usage;
    pubkey->algo = keypair->algo;

    switch (keypair->algo)
    {
    case SEV_CERT_ALGO_RSA_SHA256:
    case SEV_CERT_ALGO_RSA_SHA384:
        memcpy(&pubkey->key.rsa, &keypair->keypair.rsa, sizeof(pubkey->key.rsa));
        break;
    case SEV_CERT_ALGO_ECDSA_SHA256:
    case SEV_CERT_ALGO_ECDH_SHA256:
    case SEV_CERT_ALGO_ECDSA_SHA384:
    case SEV_CERT_ALGO_ECDH_SHA384:
        status = ecc_get_pubkey(&keypair->keypair.ecdsa, &pubkey->key.ecdsa);
        break;
    default:
        status = SEV_STATUS_UNSUPPORTED;
    }

end:
    return status;
}

sev_status_t sev_cert_get_pubkey(const sev_cert_t *cert, sev_cert_pubkey_t *pubkey)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert || !pubkey)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memcpy(pubkey, &cert->body.pubkey, sizeof(*pubkey));

end:
    return status;
}

sev_status_t sev_cert_get_sig1(const sev_cert_t *cert, sev_cert_sig_t *sig)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert || !sig)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memcpy(sig, &cert->sig1, sizeof(*sig));

end:
    return status;
}

sev_status_t sev_cert_get_sig2(const sev_cert_t *cert, sev_cert_sig_t *sig)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert || !sig)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memcpy(sig, &cert->sig2, sizeof(*sig));

end:
    return status;
}

sev_status_t sev_cert_set_pubkey(sev_cert_t *cert, const sev_cert_pubkey_t *pubkey)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert || !pubkey || !algo_is_valid(pubkey->algo) || !usage_is_valid(pubkey->usage))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memcpy(&cert->body.pubkey, pubkey, sizeof(cert->body.pubkey));

end:
    return status;
}

sev_status_t sev_cert_set_sig(sev_cert_t *cert, const sev_cert_sig_t *sig)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert || !sig)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* If the usage is invalid, then the signature is unused. */
    if (cert->sig1.usage == SEV_CERT_USAGE_INVALID)
        memcpy(&cert->sig1, sig, sizeof(cert->sig1));
    else if (cert->sig2.usage == SEV_CERT_USAGE_INVALID)
        memcpy(&cert->sig2, sig, sizeof(cert->sig2));
    else
        status = SEV_STATUS_INVALID_CERTIFICATE;

end:
    return status;
}

sev_status_t sev_cert_sign(sev_cert_t *cert, const sev_cert_keypair_t *key)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_sig_t sig;

    if (!cert || !key || !usage_is_valid(key->usage))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&sig, 0, sizeof(sig));
    sig.usage = key->usage;
    sig.algo = key->algo;

    switch (key->algo)
    {
    case SEV_CERT_ALGO_RSA_SHA256:
    case SEV_CERT_ALGO_RSA_SHA384:
        status = ERR_UNIMPLEMENTED;
        goto end;
    case SEV_CERT_ALGO_ECDH_SHA256:
    case SEV_CERT_ALGO_ECDH_SHA384:
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    case SEV_CERT_ALGO_ECDSA_SHA256:
    case SEV_CERT_ALGO_ECDSA_SHA384:
        status = ecdsa_sign_msg(&sig.sig.ecdsa, &key->keypair.ecdsa,
                                (uint8_t *)&cert->body, sizeof(cert->body), key->algo);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        break;
    default:
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_cert_set_sig(cert, &sig);

end:
    return status;
}

sev_status_t sev_cert_init(sev_cert_t *cert)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(cert, 0, sizeof(*cert));
    cert->body.version = SEV_CERT_VERSION;
    cert->body.api_major = SEV_API_MAJOR;
    cert->body.api_minor = SEV_API_MINOR;
    cert->body.pubkey.algo = SEV_CERT_ALGO_INVALID;
    cert->body.pubkey.usage = SEV_CERT_USAGE_INVALID;

    cert->sig1.algo = SEV_CERT_ALGO_INVALID;
    cert->sig1.usage = SEV_CERT_USAGE_INVALID;

    cert->sig2.algo = SEV_CERT_ALGO_INVALID;
    cert->sig2.usage = SEV_CERT_USAGE_INVALID;

end:
    return status;
}

sev_status_t sev_cert_create(sev_cert_t *cert, const sev_cert_pubkey_t *pubkey,
                             const sev_cert_keypair_t *signing_key)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* We allow the signing_key to be NULL to support creation of unsigned certs */
    if (!cert || !pubkey)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_cert_init(cert);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_fail;

    status = sev_cert_set_pubkey(cert, pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_fail;

    if (signing_key)
    {
        status = sev_cert_sign(cert, signing_key);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_fail;
    }

end:
    return status;
exit_fail:
    memset(cert, 0, sizeof(sev_cert_t));
    return status;
}

static sev_status_t sev_cert_validate_body(const sev_cert_body_t *body)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!body)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (body->version != SEV_CERT_VERSION || !pubkey_is_valid(&body->pubkey))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
    }

end:
    return status;
}

static sev_status_t sev_cert_validate_sig(const sev_cert_t *cert,
                                          const sev_cert_pubkey_t *signing_key)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    const sev_cert_sig_t *sigs[SEV_CERT_MAX_SIGNATURES] = {NULL};
    const rsa_pubkey_t *rsa_pubkey = NULL;
    const ecc_pubkey_t *ecc_pubkey = NULL;
    size_t i = 0;

    if (!cert || !signing_key)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (!pubkey_is_valid(signing_key))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    sigs[0] = &cert->sig1;
    sigs[1] = &cert->sig2;
    rsa_pubkey = &signing_key->key.rsa;
    ecc_pubkey = &signing_key->key.ecdsa;

    /*
     * This is the default status code if none of the signature algorithms
     * match the given signing key.
     */
    status = SEV_STATUS_INVALID_CERTIFICATE;

    for (i = 0; i < SEV_CERT_MAX_SIGNATURES; i++)
    {
        uint8_t big_endian[RSA_SIG_SIZE_BYTES] = {0};

        /* Check if sig is malformed */
        if ((sigs[i]->algo == SEV_CERT_ALGO_INVALID && sigs[i]->usage != SEV_CERT_USAGE_INVALID) ||
            (sigs[i]->algo != SEV_CERT_ALGO_INVALID && sigs[i]->usage == SEV_CERT_USAGE_INVALID))
        {
            /* signature is invalid. immediately break */
            status = SEV_STATUS_BAD_SIGNATURE;
            goto end;
        }

        if (sigs[i]->algo != signing_key->algo || sigs[i]->usage != signing_key->usage)
        {
            /* The key didn't produce this signature. Try the next one. */
            continue;
        }

        switch (signing_key->algo)
        {
        case SEV_CERT_ALGO_RSA_SHA256:
        case SEV_CERT_ALGO_RSA_SHA384:
            /*
             * The underlying RSA-PSS validation routine assumes that the
             * signature bytes have big-endian encoding, so swap the bytes.
             */
            memcpy(big_endian, sigs[i]->sig.rsa.s, rsa_pubkey->modulus_size_bits/BITS_PER_BYTE);
            status = reverse_bytes(big_endian, rsa_pubkey->modulus_size_bits/BITS_PER_BYTE);
            if (status != SEV_STATUS_SUCCESS)
                break;

            status = rsa_pss_verify_msg((uint8_t *)&cert->body, sizeof(cert->body),
                                        rsa_pubkey->modulus, rsa_pubkey->modulus_size_bits/BITS_PER_BYTE,
                                        rsa_pubkey->pub_exp, rsa_pubkey->modulus_size_bits/BITS_PER_BYTE,
                                        big_endian, signing_key->algo);
            break;
        case SEV_CERT_ALGO_ECDSA_SHA256:
        case SEV_CERT_ALGO_ECDSA_SHA384:
            status = ecdsa_verify_msg(&sigs[i]->sig.ecdsa, ecc_pubkey,
                                      (uint8_t *)&cert->body, sizeof(cert->body), signing_key->algo);
            break;
        default:
            /* Bad/unsupported signing key algorithm */
            status = SEV_STATUS_UNSUPPORTED;
            break;
        }

        if (status == SEV_STATUS_BAD_SIGNATURE)
            continue;   /* Try next signature block. Could have same also/usage but different parent */
        else if (status == SEV_STATUS_SUCCESS)
            continue;   /* Make sure both sigs are valid/invalid (make sure other sig isn't malformed) */
        else
            break;      /* Return whatever error you have */
    }

end:
    return status;
}

/**
 * The following procedure validates an SEV certificate chain:
 * 1.    PDH certificate
 * a.    Verify that the API_MAJOR field is equal to this API major version
 * b.    Verify that the API_MINOR field is greater than or equal to this API major version
 * c.    Verify that the VERSION field is supported by this API version
 * d.    Verify that the PUBKEY_USAGE field is equal to the PDH key usage encoding
 * e.    Verify that SIG1_USAGE field is equal to the PEK key usage encoding
 * f.    Verify that SIG1_ALGO field is equal to the PUBKEY_ALGO field of the PEK certificate
 * g.    Verify that the SIG1 field is a valid signature by the PEK certificate's public key
 *
 * 2.    PEK certificate
 * a.    Verify that the API_MAJOR field is equal to this API major version
 * b.    Verify that the API_MINOR field is greater than or equal to this API major version
 * c.    Verify that the VERSION field is supported by this API version
 * d.    Verify that the PUBKEY_USAGE field is equal to the PEK key usage encoding
 * e.    Verify that SIG1_USAGE field is equal to the CEK key usage encoding
 * f.    Verify that SIG1_ALGO field is equal to the PUBKEY_ALGO field of the CEK certificate
 * g.    Verify that the SIG1 field is a valid signature by the CEK certificate's public key
 * h.    Verify that SIG2_USAGE field is equal to the OCA key usage encoding
 * i.    Verify that SIG2_ALGO field is equal to the PUBKEY_ALGO field of the OCA certificate
 * j.    Verify that the SIG2 field is a valid signature by the OCA certificate's public key
 *
 * 3.    OCA certificate
 * a.    Verify that the API_MAJOR field is equal to this API major version
 * b.    Verify that the API_MINOR field is greater than or equal to this API major version
 * c.    Verify that the VERSION field is supported by this API version
 * d.    Verify that the PUBKEY_USAGE field is equal to the OCA key usage encoding
 * e.    Verify that SIG1_USAGE field is equal to the OCA key usage encoding
 * f.    Verify that SIG1_ALGO field is equal to the PUBKEY_ALGO field
 * g.    Verify that the SIG1 field is a valid self signature
 *
 * 4.    CEK certificate
 * a.    Verify that the API_MAJOR field is equal to this API major version
 * b.    Verify that the API_MINOR field is greater than or equal to this API major version
 * c.    Verify that the VERSION field is supported by this API version
 * d.    Verify that the PUBKEY_USAGE field is equal to the CEK key usage encoding
 * e.    Verify that SIG1_USAGE field is equal to the ASK key usage encoding
 * f.    Verify that SIG1_ALGO field is equal to the PUBKEY_ALGO field of the ASK certificate
 * g.    Verify that the SIG1 field is a valid signature by the ASK certificate's public key
 *
 * 5.    ASK certificate - see Section 11.3
 * 6.    ARK certificate - see Section 11.3
 */
sev_status_t sev_cert_validate(const sev_cert_t *cert,
                               const sev_cert_pubkey_t *signing_key)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    const sev_cert_pubkey_t *pubkey = NULL;

    if (!cert || !signing_key)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (!pubkey_is_valid(signing_key))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* Validate the signature before we do any other checking */
    status = sev_cert_validate_sig(cert, signing_key);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the certificate body */
    status = sev_cert_validate_body(&cert->body);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    pubkey = &cert->body.pubkey;

    /*
     * Although the signature was valid, ensure that the certificate was signed
     * with the proper key.
     */
    switch (pubkey->usage)
    {
    case SEV_CERT_USAGE_PDH:
        /* The PDH certificate must be signed by the PEK */
        if (!key_has_usage(signing_key, SEV_CERT_USAGE_PEK))
        {
            status = SEV_STATUS_INVALID_CERTIFICATE;
        }
        break;
    case SEV_CERT_USAGE_PEK:
        /* The PEK certificate must be signed by the OCA or the CEK */
        if (!key_has_usage(signing_key, SEV_CERT_USAGE_OCA) &&
            !key_has_usage(signing_key, SEV_CERT_USAGE_CEK))
        {
                status = SEV_STATUS_INVALID_CERTIFICATE;
        }
        break;
    case SEV_CERT_USAGE_OCA:
        /* The OCA certificate must be self-signed */
        if (!key_has_usage(signing_key, SEV_CERT_USAGE_OCA))
        {
            status = SEV_STATUS_INVALID_CERTIFICATE;
        }
        break;
    case SEV_CERT_USAGE_CEK:
        /* The CEK must be signed by the ASK */
        if (!key_has_usage(signing_key, SEV_CERT_USAGE_ASK))
        {
            status = SEV_STATUS_INVALID_CERTIFICATE;
        }
        break;
    default:
        status = SEV_STATUS_INVALID_CERTIFICATE;
    }

end:
    return status;
}

sev_status_t sev_cert_sanity_check(const sev_cert_t *cert, uint32_t expected_usage,
                                   uint32_t expected_algo)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!cert)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check the body metadata */
    status = sev_cert_validate_body(&cert->body);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (!key_has_usage(&cert->body.pubkey, expected_usage) ||
        !key_has_algo(&cert->body.pubkey, expected_algo))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
    }

end:
    return status;
}
