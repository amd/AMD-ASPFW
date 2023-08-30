// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecc.h"
#include "ecdsa.h"
#include "ecdsa_utest.h"
#include "sev_hal.h"
#include "sev_trace.h"

#define ECDSA_TEST_STRESS_COUNT     1000

/*
    Reference:
        NIST FIPS-186-4:   http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

    Test Vector Source:

    https://www.iad.gov/iad/library/ia-guidance/ia-solutions-for-classified/algorithm-guidance/suite-b-implementers-guide-to-fips-186-3-ecdsa.cfm
    Suite B Implementer's Guide to FIPS 186-3 (ECDSA), section: D.2 Example ECDSA Signature for P-384

    More test vectors can be found at:
    Source: http://csrc.nist.gov/groups/STM/cavp/digital-signatures.html
           http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip

    The private key d:
    d = c838b852 53ef8dc7 394fa580 8a518398 1c7deef5 a69ba8f4
    f2117ffe a39cfcd9 0e95f6cb c854abac ab701d50 c1f3cf24

    The public key Q = dG = (xQ, yQ):
    xQ = 1fbac8ee bd0cbf35 640b39ef e0808dd7 74debff2 0a2a329e
    91713baf 7d7f3c3e 81546d88 3730bee7 e48678f8 57b02ca0

    yQ = eb213103 bd68ce34 3365a8a4 c3d4555f a385f533 0203bdd7
    6ffad1f3 affb9575 1c132007 e1b24035 3cb0a4cf 1693bdf9

    k = dc6b4403 6989a196 e39d1cda c000812f 4bdd8b2d b41bb33a
    f5137258 5ebd1db6 3f0ce827 5aa1fd45 e2d2a735 f8749359

    Message M='This is only a test message. It is 48 bytes long'. H = Hash(M):

    H = b9210c9d 7e20897a b8659726 6a9d5077 e8db1b06 f7220ed6
    ee75bd8b 45db3789 1f8ba555 03040041 59f4453d c5b3f5a1

    r = a0c27ec8 93092dea 1e1bd2cc fed3cf94 5c8134ed 0c9f8131
    1a0f4a05 942db8db ed8dd59f 267471d5 462aa14f e72de856

    s = 20ab3f45 b74f10b6 e11f96a2 c8eb694d 206b9dda 86d3c7e3
    31c26b22 c987b753 77265776 67adadf1 68ebbe80 3794a402

    The signature on the message M is the pair (r, s).
*/
static ecc_keypair_t test_keypair =
{
 .curve = ECC_CURVE_NAME_SECP384R1,

 .Q ={{{0xa0, 0x2c, 0xb0, 0x57, 0xf8, 0x78, 0x86, 0xe4, 0xe7, 0xbe, 0x30, 0x37, 0x88, 0x6d, 0x54, 0x81,
        0x3e, 0x3c, 0x7f, 0x7d, 0xaf, 0x3b, 0x71, 0x91, 0x9e, 0x32, 0x2a, 0x0a, 0xf2, 0xbf, 0xde, 0x74,
        0xd7, 0x8d, 0x80, 0xe0, 0xef, 0x39, 0x0b, 0x64, 0x35, 0xbf, 0x0c, 0xbd, 0xee, 0xc8, 0xba, 0x1f,}},

      {{0xf9, 0xbd, 0x93, 0x16, 0xcf, 0xa4, 0xb0, 0x3c, 0x35, 0x40, 0xb2, 0xe1, 0x07, 0x20, 0x13, 0x1c,
        0x75, 0x95, 0xfb, 0xaf, 0xf3, 0xd1, 0xfa, 0x6f, 0xd7, 0xbd, 0x03, 0x02, 0x33, 0xf5, 0x85, 0xa3,
        0x5f, 0x55, 0xd4, 0xc3, 0xa4, 0xa8, 0x65, 0x33, 0x34, 0xce, 0x68, 0xbd, 0x03, 0x31, 0x21, 0xeb,}}},

 .d ={{ 0x24, 0xCF, 0xF3, 0xC1, 0x50, 0x1D, 0x70, 0xAB, 0xAC, 0xAB, 0x54, 0xC8, 0xCB, 0xF6, 0x95, 0x0E,
        0xD9, 0xFC, 0x9C, 0xA3, 0xFE, 0x7F, 0x11, 0xF2, 0xF4, 0xA8, 0x9B, 0xA6, 0xF5, 0xEE, 0x7D, 0x1C,
        0x98, 0x83, 0x51, 0x8A, 0x80, 0xA5, 0x4F, 0x39, 0xC7, 0x8D, 0xEF, 0x53, 0x52, 0xB8, 0x38, 0xC8, }},
};

static uint8_t test_digest[48] =
{
        0xb9, 0x21, 0x0c, 0x9d, 0x7e, 0x20, 0x89, 0x7a, 0xb8, 0x65, 0x97, 0x26, 0x6a, 0x9d, 0x50, 0x77,
        0xe8, 0xdb, 0x1b, 0x06, 0xf7, 0x22, 0x0e, 0xd6, 0xee, 0x75, 0xbd, 0x8b, 0x45, 0xdb, 0x37, 0x89,
        0x1f, 0x8b, 0xa5, 0x55, 0x03, 0x04, 0x00, 0x41, 0x59, 0xf4, 0x45, 0x3d, 0xc5, 0xb3, 0xf5, 0xa1,
};

static ecdsa_sig_t test_sig =
{
 .r ={{ 0x56, 0xE8, 0x2D, 0xE7, 0x4F, 0xA1, 0x2A, 0x46, 0xD5, 0x71, 0x74, 0x26, 0x9F, 0xD5, 0x8D, 0xED,
        0xDB, 0xB8, 0x2D, 0x94, 0x05, 0x4A, 0x0F, 0x1A, 0x31, 0x81, 0x9F, 0x0C, 0xED, 0x34, 0x81, 0x5C,
        0x94, 0xCF, 0xD3, 0xFE, 0xCC, 0xD2, 0x1B, 0x1E, 0xEA, 0x2D, 0x09, 0x93, 0xC8, 0x7E, 0xC2, 0xA0, }},

 .s ={{ 0x02, 0xA4, 0x94, 0x37, 0x80, 0xBE, 0xEB, 0x68, 0xF1, 0xAD, 0xAD, 0x67, 0x76, 0x57, 0x26, 0x77,
        0x53, 0xB7, 0x87, 0xC9, 0x22, 0x6B, 0xC2, 0x31, 0xE3, 0xC7, 0xD3, 0x86, 0xDA, 0x9D, 0x6B, 0x20,
        0x4D, 0x69, 0xEB, 0xC8, 0xA2, 0x96, 0x1F, 0xE1, 0xB6, 0x10, 0x4F, 0xB7, 0x45, 0x3F, 0xAB, 0x20, }},
};

static uint8_t test_random[48] =
{
        0x59, 0x93, 0x74, 0xF8, 0x35, 0xA7, 0xD2, 0xE2, 0x45, 0xFD, 0xA1, 0x5A, 0x27, 0xE8, 0x0C, 0x3F,
        0xB6, 0x1D, 0xBD, 0x5E, 0x58, 0x72, 0x13, 0xF5, 0x3A, 0xB3, 0x1B, 0xB4, 0x2D, 0x8B, 0xDD, 0x4B,
        0x2F, 0x81, 0x00, 0xC0, 0xDA, 0x1C, 0x9D, 0xE3, 0x96, 0xA1, 0x89, 0x69, 0x03, 0x44, 0x6B, 0xDC,
};

sev_status_t ecdsa_utest(void)
{
    sev_status_t    status = SEV_STATUS_SUCCESS;
    ecdsa_sig_t     sig;
    ecc_keypair_t   keypair;
    ecc_pubkey_t    *test_pubkey;
    uint32_t        loop;

    test_pubkey = (ecc_pubkey_t *)&test_keypair;

    /* Negative test for zero-buffer signature */
    memset(&sig, 0, sizeof(sig));
    status = ecdsa_verify(&sig, test_pubkey, test_digest, sizeof(test_digest));
    if (status == SEV_STATUS_SUCCESS)
    {
        status = ERR_INVAL;
        goto end;
    }

    /* Negative test for random signature, test for a good amount of times */
    for (loop = 0; loop < ECDSA_TEST_STRESS_COUNT; loop++ )
    {
        status = sev_hal_trng((uint8_t *)&sig.r, SEV_ECC_CURVE_SIZE_BYTES);
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }

        status = sev_hal_trng((uint8_t *)&sig.s, SEV_ECC_CURVE_SIZE_BYTES);
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }

        status = ecdsa_verify(&sig, test_pubkey, test_digest, sizeof(test_digest));
        if (status == SEV_STATUS_SUCCESS)
        {
            status = ERR_INVAL;
            break;
        }
    }
    if (status != SEV_STATUS_BAD_SIGNATURE)
    {
        goto end;
    }

    /* Positive test against test vector */
    status = ecdsa_verify(&test_sig, test_pubkey, test_digest, sizeof(test_digest));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    status = ecdsa_sign_rdata(&sig, &test_keypair, test_digest, sizeof(test_digest), test_random, sizeof(test_random));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    if (memcmp(&sig, &test_sig, sizeof(test_sig)) != 0)
    {
        status = SEV_STATUS_BAD_SIGNATURE;
        goto end;
    }

    /* Finally, generate a keypair at run time, and test against itself. test for a good amount of times */
    for (loop = 0; loop < ECDSA_TEST_STRESS_COUNT; loop++ )
    {
        status = ecdsa_keypair_generate(&keypair);
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }

        test_pubkey = (ecc_pubkey_t *)&keypair;
        status = ecdsa_sign(&sig, &keypair, test_digest, sizeof(test_digest));
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }

        status = ecdsa_verify(&sig, test_pubkey, test_digest, sizeof(test_digest));
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }
    }
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("ecdsa_utest failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("ecdsa_utest succeed!\n");
    }

    return status;
}
