// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "ecdsa.h"
#include "secure_ops.h"
#include "sev_hal.h"

sev_status_t ecdsa_keypair_generate(ecc_keypair_t *keypair)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t random[SEV_ECC_CURVE_SIZE_BYTES];       // P384, 48 bytes.

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
            /* Re-pick the random */
            continue;
        }
        else
        {
            break;
        }

    } while (1);

    secure_memzero(random, sizeof(random));
    return status;
}

sev_status_t ecdsa_export_pubkey(ecc_pubkey_t *pubkey, const ecc_keypair_t *keypair)
{
    return ecc_get_pubkey(keypair, pubkey);
}

/**
 * Source: https://www.iad.gov/iad/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
 *
 * ECDSA SIGNATURE GENERATION:
 *
 * INPUT: Domain parameters D = (p,a,b,G,n,h), private key d, message m.
 * OUTPUT: Signature (r,s).
 * 1. Select k randomly from [1,n-1].
 * 2. Compute kP = X(x, y) and convert X_x to an integer x.
 * 3. Compute r = x mod n. If r = 0 then re-select random number.
 * 4. Compute e = Hash(m).
 * 5. Compute s = k^-1(e+dr) mod n. If s = 0 then re-select random number.
 * 6. Return(r,s).
 */
sev_status_t ecdsa_sign_rdata(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                              const uint8_t *digest, size_t length,
                              const uint8_t *rdata, size_t rlength)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t k, r, e;
    ecc_point_t X;
    const ecc_curve_t *curve = keypair ? ecc_get_curve(keypair->curve) : NULL;

    if (!sig || !keypair || !digest || length == 0 || !rdata || rlength == 0 ||
        !curve)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Clear the minimum amount necessary to perform validation checks */
    memset(&k, 0, sizeof(k));

    if (1)
    {
        memcpy(&k, rdata, rlength);

        /* Check that rdata is less than the curve.n */
        if (ecc_scalar_is_greater(&k, &curve->n))
        {
            status = ERR_INVALID_PARAMS;
            goto end;
        }

        if (ecc_scalar_is_zero(&k))
        {
            status = ERR_INVALID_PARAMS;
            goto end;
        }
    }
    else /* Recommended by Section A.2.1 of the NSA doc but still seemed to introduce bias */
    {
        ecc_scalar_t c;
        ecc_scalar_t modulus;
        ecc_scalar_t one;

        memset(&c, 0, sizeof(c));
        memset(&modulus, 0, sizeof(modulus));
        memset(&one, 0, sizeof(one));
        one.s[0] = 1;
        memcpy(&c.s, rdata, rlength);    /* Is this little endian? */

        /* Calculate k = c mod(n-1) + 1 */
        status = ecc_scalar_minus(&modulus, &curve->n, &one);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = ecc_scalar_reduce(&k, &c, &modulus);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /*
         * Since we just reduced the data mod(n-1), doing the addition mod(n)
         * guarantees that we can add one without wrapping.
         */
        status = ecc_scalar_add(&k, &k, &one, &curve->n);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Clear the rest of the data and output buffer */
    memset(sig, 0, sizeof(*sig));
    memset(&r, 0, sizeof(r));
    memset(&e, 0, sizeof(e));
    memset(&X, 0, sizeof(X));
    memset(sig, 0, sizeof(*sig));

    /* Compute k*G = (x, y) and compute r=x mod n, and r != 0.
     * otherwise, re-pick the random */
    status = ecc_point_scale(&X, &curve->G, &k, curve->name);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecc_scalar_mod(&r, &X.x, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    if (ecc_scalar_is_zero(&r))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Copy r to signature output */
    memcpy(&sig->r, &r, sizeof(r));

    /* Compute k^-1 mod n */
    status = ecc_scalar_inv(&k, &k, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* Compute s = k^-1(e+dr) mod n.
     * if s = 0, re-pick the random */
    status = ecc_scalar_mul(&r, &keypair->d, &r, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecc_scalar_init(&e, digest, length);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = ecc_scalar_add(&e, &e, &r, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecc_scalar_mul(&sig->s, &k, &e, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    if (ecc_scalar_is_zero(&sig->s))
    {
        status = ERR_INVALID_PARAMS;
    }

end:
    return status;
}

sev_status_t ecdsa_sign(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                        const uint8_t *digest, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t random[SEV_ECC_CURVE_SIZE_BYTES];    /* P384, 48 bytes */

    if (!sig || !keypair || !digest || length == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    do
    {
        status = sev_hal_trng(random, sizeof(random));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = ecdsa_sign_rdata(sig, keypair, digest, length,
                                 (const uint8_t *)&random, sizeof(random));
    } while (status == ERR_INVALID_PARAMS);    // re-pick the random

end:
    secure_memzero(random, sizeof(random));
    return status;
}

/**
 * Source: http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf
 *
 * ECDSA SIGNATURE VERIFICATION:
 *
 * INPUT: Domain parameters D = (p,a,b,G,n,h), public key Q, message m, signature (r, s),
 * OUTPUT: Success or Fail.
 * 1. Verify that r and s are integers in the interval [1, n-1]
 * 2. Compute e = Hash(m).
 * 3. Compute w = s^-1 mod n.
 * 4. Compute u1 = ew mod n, and u2 = rw mod n.
 * 5. Compute X(x, y) = u1G + u2Q.
 * 6. If X = Infinity point, then reject the signature. Otherwise, convert X_x to an interger x,
 *    and compute v = x mod n.
 * 7. Accept the signature if and only if v = r.
 */
sev_status_t ecdsa_verify(const ecdsa_sig_t *sig, const ecc_pubkey_t *pubkey,
                          const uint8_t *digest, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t e, w, u1, u2;
    ecc_point_t X;
    const ecc_curve_t *curve = pubkey ? ecc_get_curve(pubkey->curve) : NULL;

    if (!sig || !pubkey || !digest || length == 0 || !curve)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&e, 0, sizeof(e));
    memset(&w, 0, sizeof(w));
    memset(&u1, 0, sizeof(u1));
    memset(&u2, 0, sizeof(u2));
    memset(&X, 0, sizeof(X));

    /* Verify that r and s are integers in the interval [1, n-1] */
    if (ecc_scalar_is_zero(&sig->r))
    {
        status = SEV_STATUS_BAD_SIGNATURE;
        goto end;
    }

    if (!ecc_scalar_is_greater(&curve->n, &sig->r))
    {
        status = SEV_STATUS_BAD_SIGNATURE;
        goto end;
    }

    if (ecc_scalar_is_zero(&sig->s))
    {
        status = SEV_STATUS_BAD_SIGNATURE;
        goto end;
    }

    if (!ecc_scalar_is_greater(&curve->n, &sig->s))
    {
        status = SEV_STATUS_BAD_SIGNATURE;
        goto end;
    }

    status = ecc_scalar_init(&e, digest, length);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Compute w = s^-1 mod n */
    status = ecc_scalar_inv(&w, &sig->s, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* Compute u1 = ew mod n, and u2 = rw mod n */
    status = ecc_scalar_mul(&u1, &e, &w, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecc_scalar_mul(&u2, &sig->r, &w, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* Compute X(x, y) = u1G + u2Q */
    status = ecc_point_linear(&X, &curve->G, &u1, &pubkey->Q, &u2, curve->name);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* If X = Infinity point, a error will be thrown from CCP, then reject the signature.
     * Otherwise, convert X_x to an integer x, and compute v = x mod n. */
    memset(&e, 0, sizeof(e));   /* Use e as placeholder */
    status = ecc_scalar_mod(&e, &X.x, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    if (secure_compare(&sig->r, &e, sizeof(e)) != 0)
    {
        status = SEV_STATUS_BAD_SIGNATURE;
    }

end:
    return status;
}

static sev_status_t sign_verify_msg(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                                    const uint8_t *msg, size_t length, bool sign,
                                    const uint32_t algo)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t sha;
    SHA_TYPE sha_type = SHA_TYPE_256;
    size_t sha_len = sizeof(sha);
    ecc_pubkey_t pubkey;

    if (!sig || !keypair || !msg || keypair->curve == ECC_CURVE_NAME_INVALID)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* This function only supports ECDSA algorithms */
    if (algo != SEV_CERT_ALGO_ECDSA_SHA256 && algo != SEV_CERT_ALGO_ECDSA_SHA384)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (length == 0)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (algo == SEV_CERT_ALGO_ECDSA_SHA256)
        sha_type = SHA_TYPE_256;
    else
        sha_type = SHA_TYPE_384;

    /* Calculate the digest of the input message */
    status = digest_sha(msg, length, &sha, &sha_len, sha_type);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memset(&pubkey, 0, sizeof(pubkey));
    status = ecc_get_pubkey(keypair, &pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Sign/verify using the digest as input */
    status = sign ? ecdsa_sign(sig, keypair, sha.digest, sha_len)
                  : ecdsa_verify(sig, &pubkey, sha.digest, sha_len);

end:
    return status;
}

sev_status_t ecdsa_sign_msg(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                            const uint8_t *msg, size_t length, const uint32_t algo)
{
    return sign_verify_msg(sig, keypair, msg, length, true, algo);
}

sev_status_t ecdsa_verify_msg(const ecdsa_sig_t *sig, const ecc_pubkey_t *pubkey,
                              const uint8_t *msg, size_t length, const uint32_t algo)
{
    return sign_verify_msg((ecdsa_sig_t *)sig, (const ecc_keypair_t *)pubkey,
                           msg, length, false, algo);
}
