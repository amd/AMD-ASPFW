// Copyright(C) 2017-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "amd_cert.h"
#include "digest.h"
#include "helper.h"
#include "secure_ops.h"
#include "sev_hal.h"

#define AMD_CERT_KEY_BYTES_4K    ((AMD_CERT_KEY_BITS_4K)/(BITS_PER_BYTE))

/* Genoa ID - From ark_genoa.cert */
static const uint8_t amd_root_key_id[AMD_CERT_ID_SIZE_BYTES] = {
        0x9F, 0x9D, 0x4A, 0x8F, 0xE7, 0x61, 0x45, 0x65,
        0x99, 0xF6, 0x94, 0x6C, 0x4C, 0x01, 0x0F, 0x3A
};

/* size is max cert size in bytes */
sev_status_t amd_cert_init(amd_cert_t *cert, const uint8_t *buffer, size_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    amd_cert_t tmp;

    if (!cert || !buffer)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&tmp, 0, sizeof(tmp));

    /* Copy the fixed body data from the temporary buffer */
    memcpy(&tmp.fixed, buffer, sizeof(tmp.fixed));

    tmp.pubkey.modulus_size = tmp.fixed.modulus_size_bits/BITS_PER_BYTE;
    tmp.pubkey.pubexp_size = tmp.fixed.pubexp_size_bits/BITS_PER_BYTE;

    /* Make sure pubexp_size and modulus_size are within constraints */
    if (tmp.pubkey.modulus_size >= size || tmp.pubkey.pubexp_size >= size)
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* Initialize the remainder of the certificate */
    tmp.pubkey.pubexp = buffer + sizeof(tmp.fixed);
    tmp.pubkey.modulus = tmp.pubkey.pubexp + tmp.pubkey.pubexp_size;
    tmp.signature = tmp.pubkey.modulus + tmp.pubkey.modulus_size;

    if (tmp.signature + tmp.pubkey.modulus_size > buffer + size)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memcpy(cert, &tmp, sizeof(*cert));

end:
    return status;
}

bool key_size_is_valid(size_t size)
{
    return (size == AMD_CERT_KEY_BITS_2K) || (size == AMD_CERT_KEY_BITS_4K);
}

static sev_status_t amd_cert_validate_sig(const amd_cert_t *cert,
                                          const amd_cert_pubkey_t *pubkey)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_ctx_t ctx;
    digest_sha_t msg_digest;
    size_t digest_len = 0;
    uint8_t signature[AMD_CERT_KEY_BYTES_4K] = {0};

    if (!cert || !pubkey)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the key sizes before using them */
    if (!key_size_is_valid(cert->fixed.modulus_size_bits) ||
        !key_size_is_valid(cert->fixed.pubexp_size_bits))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    memset(&ctx, 0, sizeof(ctx));
    memset(&msg_digest, 0, sizeof(msg_digest));

    /*
     * Calculate the digest of the certificate body. This includes the
     * fixed body data, the public exponent, and the modulus.
     */
    status = digest_sha_init(&ctx, SHA_TYPE_384);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, &cert->fixed, sizeof(cert->fixed));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, cert->pubkey.pubexp,
                               cert->pubkey.pubexp_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, cert->pubkey.modulus,
                               cert->pubkey.modulus_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_final(&ctx, &msg_digest, &digest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Swap the bytes of the signature */
    memcpy(signature, cert->signature, pubkey->modulus_size);

    status = reverse_bytes(signature, pubkey->modulus_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify the signature */
    status = rsa_pss_verify(msg_digest.digest, digest_len,
                            pubkey->modulus, pubkey->modulus_size,
                            pubkey->pubexp, pubkey->pubexp_size,
                            signature);

end:
    return status;
}

static sev_status_t amd_cert_validate_common(const amd_cert_fixed_t *fixed)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!fixed)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (fixed->version != AMD_CERT_VERSION ||
        !key_size_is_valid(fixed->modulus_size_bits) ||
        !key_size_is_valid(fixed->pubexp_size_bits))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
    }

end:
    return status;
}

static bool usage_is_valid(uint32_t usage)
{
    return (usage == SEV_CERT_USAGE_ARK) || (usage == SEV_CERT_USAGE_ASK);
}

static sev_status_t amd_cert_validate(const amd_cert_t *cert,
                                      const amd_cert_t *parent,
                                      uint32_t expected_usage)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    const uint8_t *key_id = NULL;

    if (!cert || !usage_is_valid(expected_usage))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the signature before using any certificate fields */
    if (parent)
    {
        status = amd_cert_validate_sig(cert, &parent->pubkey);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Validate the fixed data */
    status = amd_cert_validate_common(&cert->fixed);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* If there is no parent, then the certificate must be self-certified */
    key_id = parent ? parent->fixed.key_id : cert->fixed.key_id;

    if (cert->fixed.key_usage != expected_usage ||
        memcmp(cert->fixed.certifying_id, key_id,
               sizeof(cert->fixed.certifying_id)) != 0)
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
    }

end:
    return status;
}

static sev_status_t amd_cert_public_key_hash(const amd_cert_t *cert,
                                             digest_sha_t *hash)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t tmp_hash;
    size_t hash_size = DIGEST_SHA256_SIZE_BYTES; // sizeof(tmp_hash);
    digest_sha_ctx_t ctx;

    if (!cert || !hash)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&tmp_hash, 0, sizeof(tmp_hash));

    /* Calculate the hash of the public key */
    status = digest_sha_init(&ctx, SHA_TYPE_384);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, &cert->fixed, sizeof(cert->fixed));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, cert->pubkey.pubexp,
                               cert->pubkey.pubexp_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_update(&ctx, cert->pubkey.modulus,
                               cert->pubkey.modulus_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_final(&ctx, &tmp_hash, &hash_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the hash to the output */
    memcpy(hash->digest, tmp_hash.digest, DIGEST_SHA384_SIZE_BYTES);

end:
    return status;
}

sev_status_t amd_cert_validate_ark(const amd_cert_t *ark)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t hash, fused_hash;

    if (!ark)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&hash, 0, sizeof(hash));
    memset(&fused_hash, 0, sizeof(fused_hash));

    /* Validate the certificate. Check for self-signed ARK */
    status = amd_cert_validate(ark, ark, SEV_CERT_USAGE_ARK);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Include the following code in public builds, but disable for internal
     * (WIP) builds until the test suite can be updated.
     */
    if (memcmp(ark->fixed.key_id, amd_root_key_id, sizeof(ark->fixed.key_id)) != 0)
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* Calculate the hash of the ARK public key */
    status = amd_cert_public_key_hash(ark, &hash);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Retrieve the fused hash value of the ARK public key */
    status = sev_hal_get_root_key_hash(&fused_hash);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* The hashes should match */
    if (secure_compare(hash.digest, fused_hash.digest, sizeof(hash)) != 0)
        status = SEV_STATUS_INVALID_CERTIFICATE;

end:
    secure_memzero(&fused_hash, sizeof(fused_hash));
    return status;
}

sev_status_t amd_cert_validate_ask(const amd_cert_t *ask, const amd_cert_t *ark)
{
    return amd_cert_validate(ask, ark, SEV_CERT_USAGE_ASK);
}

size_t amd_cert_get_size(const amd_cert_t *cert)
{
    size_t size = 0;

    if (cert)
    {
        size = sizeof(cert->fixed) + 2*cert->pubkey.modulus_size +
               cert->pubkey.pubexp_size;
    }
    return size;
}

sev_status_t amd_cert_export_pubkey(const amd_cert_t *cert,
                                    sev_cert_pubkey_t *pubkey)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t cert_size = 0;

    if (!cert || !pubkey)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    cert_size = amd_cert_get_size(cert);

    /* Ensure that the two memory areas don't overlap */
    if ((size_t)cert <= (size_t)pubkey + sizeof(*pubkey) &&
        (size_t)pubkey <= (size_t)cert + cert_size)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(pubkey, 0, sizeof(*pubkey));
    pubkey->algo = SEV_CERT_ALGO_RSA_SHA384;
    pubkey->usage = cert->fixed.key_usage;
    pubkey->key.rsa.modulus_size_bits = cert->fixed.modulus_size_bits;
    memcpy(pubkey->key.rsa.modulus, cert->pubkey.modulus, cert->pubkey.modulus_size);
    memcpy(pubkey->key.rsa.pub_exp, cert->pubkey.pubexp, cert->pubkey.pubexp_size);

end:
    return status;
}

/**
 * There are only 4 possible combinations of ASK and ARK combined length.
 * Each can be either 2K or 4K.
 */
bool amd_cert_chain_length_is_valid(size_t length)
{
#define SIZE_2K_KEY (AMD_CERT_KEY_BITS_2K/BITS_PER_BYTE)
#define SIZE_4K_KEY (AMD_CERT_KEY_BITS_4K/BITS_PER_BYTE)

#define SIZE_2KASK_2KARK (2*sizeof(amd_cert_fixed_t)+2*SIZE_2K_KEY+4*SIZE_2K_KEY)
#define SIZE_2KASK_4KARK (2*sizeof(amd_cert_fixed_t)+2*SIZE_2K_KEY+4*SIZE_4K_KEY)
#define SIZE_4KASK_2KARK (2*sizeof(amd_cert_fixed_t)+2*SIZE_4K_KEY+4*SIZE_2K_KEY)
#define SIZE_4KASK_4KARK (2*sizeof(amd_cert_fixed_t)+2*SIZE_4K_KEY+4*SIZE_4K_KEY)

    if (length == SIZE_2KASK_2KARK || length == SIZE_2KASK_4KARK ||
        length == SIZE_4KASK_2KARK || length == SIZE_4KASK_4KARK)
        return true;

    return false;
}
