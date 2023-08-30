// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "ccp_direct_cipher.h"
#include "cipher.h"
#include "cipher_utest.h"
#include "common_utilities.h"
#include "sev_trace.h"

#define AESBUFFERLEN        64
#define MAX_KEY_SIZE        16      // 64 bytes key size
#define MAX_IV_SIZE         16      // 16 bytes

// AES Modes
typedef enum CCP_AES_MODE_E
{
    CCP_AES_MODE_ECB   = 0,
    CCP_AES_MODE_CBC   = 1,
    CCP_AES_MODE_OFB   = 2,
    CCP_AES_MODE_CFB   = 3,
    CCP_AES_MODE_CTR   = 4,
    CCP_AES_MODE_CMAC  = 5,
    CCP_AES_MODE_GHASH = 6,
    CCP_AES_MODE_GCTR  = 7,
    CCP_AES_MODE_IAPM_NIST  = 8,
    CCP_AES_MODE_IAPM_IPSEC = 9,
    CCP_AES_MODE_UMC   = 10
} CCP_AES_MODE;

typedef struct AESVECTOR_T
{
    uint8_t         In[AESBUFFERLEN];
    uint8_t         Out[AESBUFFERLEN];
    uint8_t         Key[MAX_KEY_SIZE];
    uint8_t         IV[MAX_IV_SIZE];
    uint32_t        OutSize;
    CCP_AES_MODE    mode;
    uint32_t        Params;
    uint32_t        KeySize;
    uint32_t        InSize;
    const char      Description[256];
} AESVECTOR;

__align(16) const static AESVECTOR AESVector =
{
        /* AES-CTR 128 mode */
        {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
         },
         {
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
            0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
            0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
            0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
            0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
            0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
            0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
            0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
         },
         {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
         },
         {
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
         },
         64,
         CCP_AES_MODE_CTR,
         3,
         16,
         64,
         "AES CTR with 128 bits key and input size 64 bytes"
};


sev_status_t cipher_utest_encrypt(void)
{
    sev_status_t                status = SEV_STATUS_SUCCESS;
    cipher_aes_ctr_ctx_t        ctx;
    cipher_aes_iv_t             counter;
    cipher_aes_mode_t           mode = AES_MODE_INVALID;
    cipher_aes_key_t            key;
    uint8_t                     output[AESBUFFERLEN + 32];
    uint32_t                    dest_len = 0;
    uint32_t                    i;
    uint8_t                    *output_aligned;

    memcpy(&counter, AESVector.IV, sizeof(counter));
    memcpy(&key, AESVector.Key, sizeof(key));
    mode = AES_MODE_ENCRYPT;

    status = cipher_aes_ctr_init(&ctx, &counter, &key, mode);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memset(output, 0, sizeof(output));
    output_aligned = (uint8_t *)(ALIGN_TO_16_BYTES(output));
    dest_len = AESBUFFERLEN;
    status = cipher_aes_ctr_final(&ctx, (uint8_t *)AESVector.In, AESVector.InSize,
                                  output_aligned, &dest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    for (i = 0; i < AESVector.OutSize; i++)
    {
        if (output_aligned[i] != AESVector.Out[i])
        {
            status = ERR_UNKNOWN;
            break;
        }
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("cipher_utest_encrypt failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("cipher_utest_encrypt succeed!\n");
    }
    return status;
}

/**
 * Same as cipher_utest_encrypt() but uses InSize-1 so there is 1 bit of padding
 */
sev_status_t cipher_utest_encrypt_padded(void)
{
    sev_status_t                status = SEV_STATUS_SUCCESS;
    cipher_aes_ctr_ctx_t        ctx;
    cipher_aes_iv_t             counter;
    cipher_aes_mode_t           mode = AES_MODE_INVALID;
    cipher_aes_key_t            key;
    uint8_t                     output[AESBUFFERLEN + 32];
    uint32_t                    dest_len = 0;
    uint32_t                    i;
    uint8_t                    *output_aligned;

    memcpy(&counter, AESVector.IV, sizeof(counter));
    memcpy(&key, AESVector.Key, sizeof(key));
    mode = AES_MODE_ENCRYPT;

    status = cipher_aes_ctr_init(&ctx, &counter, &key, mode);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memset(output, 0, sizeof(output));
    output_aligned = (uint8_t *)(ALIGN_TO_16_BYTES(output));
    dest_len = AESBUFFERLEN;
    status = cipher_aes_ctr_final(&ctx, (uint8_t *)AESVector.In, AESVector.InSize-1,
                                  output_aligned, &dest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    for (i = 0; i < dest_len; i++)
    {
        if (output_aligned[i] != AESVector.Out[i])
        {
            status = ERR_UNKNOWN;
            break;
        }
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("cipher_utest_encrypt failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("cipher_utest_encrypt succeed!\n");
    }
    return status;
}

sev_status_t cipher_utest_decrypt(void)
{
    sev_status_t                status = SEV_STATUS_SUCCESS;
    cipher_aes_ctr_ctx_t        ctx;
    cipher_aes_iv_t             counter;
    cipher_aes_mode_t           mode = AES_MODE_INVALID;
    cipher_aes_key_t            key;
    uint8_t                     output[AESBUFFERLEN + 32];
    uint32_t                    dest_len = 0;
    uint32_t                    i;
    uint8_t                    *output_aligned;

    memcpy(&counter, AESVector.IV, sizeof(counter));
    memcpy(&key, AESVector.Key, sizeof(key));
    mode = AES_MODE_DECRYPT;

    status = cipher_aes_ctr_init(&ctx, &counter, &key, mode);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memset(output, 0, sizeof(output));
    output_aligned = (uint8_t *)(ALIGN_TO_16_BYTES(output));
    dest_len = AESBUFFERLEN;
    status = cipher_aes_ctr_final(&ctx, (uint8_t *)AESVector.Out, AESVector.OutSize,
                                  output_aligned, &dest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    for (i = 0; i < AESVector.InSize; i++)
    {
        if (output_aligned[i] != AESVector.In[i])
        {
            status = ERR_UNKNOWN;
            break;
        }
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("cipher_utest_decrypt failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("cipher_utest_decrypt succeed!\n");
    }
    return status;
}

/**
 * AES256GCM test vectors matching SEV page swap
 */
static const uint8_t kat_aes256gcm_key1[] =
{
    0x37,0x89,0x18,0x5b,0x3e,0x6a,0x19,0x71,0xbe,0x0e,0x8b,0xb8,0x64,0x97,0x35,0x10,
    0x1b,0xfc,0xe1,0x1a,0xf6,0xe3,0x0d,0x49,0xe5,0x6c,0x63,0xfb,0x26,0x40,0x9f,0x20
};
static const uint8_t kat_aes256gcm_iv1[] =
{
    0xf4,0x78,0x89,0x26,0x0a,0x25,0x82,0x77
};

static const uint8_t kat_aes256gcm_aad1[] = {'d'};
static const uint8_t kat_aes256gcm_aad2[] = {'v'};
static const uint8_t kat_aes256gcm_aad3[] = {'m'};

__align(32) static const uint8_t kat_aes256gcm_pt1[] =
{
    0xc6,0x99,0x2d,0x2c,0x4c,0x96,0x72,0xb5,0xdd,0x94,0xdd,0x5f,0x5f,0xd7,0x85,0xc0,
    0x85,0xcb,0x85,0xf5,0x4b,0x6a,0x26,0xb2,0x0e,0xec,0xda,0xd4,0xab,0x53,0x6c,0xca
};
__align(32) static const uint8_t kat_aes256gcm_ct1[] =
{
    0xC2,0xEC,0xF1,0x6C,0x9D,0xBA,0x49,0xD4,0xE8,0x95,0x70,0xCD,0x22,0x38,0xB0,0xE1,
    0x87,0xEB,0x7E,0x2E,0xF4,0x67,0x29,0xA1,0xA8,0x65,0x26,0xCE,0xC3,0xE9,0xFC,0x9F
};
__align(16) static const uint8_t kat_aes256gcm_tag1[] =
{
    0xE1,0x7C,0x67,0xD4,0x36,0xBF,0xCE,0x8A,0x66,0x3E,0x2A,0xBD,0xE2,0xD0,0xE6,0xF9
};
__align(16) static const uint8_t kat_aes256gcm_tag2[] =
{
    0x18,0xE9,0x77,0x27,0x56,0xE8,0x95,0xE2,0x1F,0xC6,0xF5,0x14,0x6F,0xB9,0xD5,0x02
};
__align(16) static const uint8_t kat_aes256gcm_tag3[] =
{
    0x7C,0xB6,0xEF,0xAD,0x86,0x94,0x63,0x3E,0x5A,0xC2,0x45,0x69,0x24,0x64,0x7F,0x04
};

sev_status_t cipher_utest_aes256gcm_crypt(const uint8_t *pKey,
                                          const uint8_t *pAAD, size_t AADSize,
                                          const uint8_t *pMsg, size_t MsgSize)
{
    sev_status_t status;
    uint8_t IV[16], T[16];
    uint8_t buff[(AESBUFFERLEN*2) + 16];
    uint8_t *pAlignedCT = (uint8_t *)(ALIGN_TO_16_BYTES(buff));
    uint8_t *pAlignedPT = pAlignedCT + AESBUFFERLEN;

    // generate random data for testing
    memset(&IV, 0xA5, sizeof(IV));

    status = aes256gcm_authenticated_encrypt(pKey, 32,
                                             pAAD, AADSize,
                                             pMsg, MsgSize,
                                             pAlignedCT,        // out - ciphertext
                                             IV, 16, T);
    if (status == SEV_STATUS_SUCCESS)
    {
        status = aes256gcm_authenticated_decrypt(pKey, 32,
                                                 pAAD, AADSize,
                                                 pAlignedCT, MsgSize,
                                                 pAlignedPT,         // out - plaintext
                                                 IV, 16, T);
        if (status == SEV_STATUS_SUCCESS && memcmp(pMsg, pAlignedPT, MsgSize) != 0)
            status = ERR_SECURE_DATA_VALIDATION;
    }
    return status;
}

sev_status_t cipher_utest(void)
{
    sev_status_t status;

    status = cipher_utest_encrypt();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_utest_encrypt_padded();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_utest_decrypt();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * AES-GCM based on CCP Direct API
     */
    status = cipher_utest_aes256gcm_kat(
            kat_aes256gcm_key1,
            kat_aes256gcm_iv1, sizeof(kat_aes256gcm_iv1),
            kat_aes256gcm_aad1, sizeof(kat_aes256gcm_aad1),
            kat_aes256gcm_pt1, sizeof(kat_aes256gcm_pt1),
            kat_aes256gcm_ct1,
            kat_aes256gcm_tag1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_utest_aes256gcm_kat(
            kat_aes256gcm_key1,
            kat_aes256gcm_iv1, sizeof(kat_aes256gcm_iv1),
            kat_aes256gcm_aad2, sizeof(kat_aes256gcm_aad2),
            kat_aes256gcm_pt1, sizeof(kat_aes256gcm_pt1),
            kat_aes256gcm_ct1,
            kat_aes256gcm_tag2);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_utest_aes256gcm_kat(
            kat_aes256gcm_key1,
            kat_aes256gcm_iv1, sizeof(kat_aes256gcm_iv1),
            kat_aes256gcm_aad3, sizeof(kat_aes256gcm_aad3),
            kat_aes256gcm_pt1, sizeof(kat_aes256gcm_pt1),
            kat_aes256gcm_ct1,
            kat_aes256gcm_tag3);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_utest_aes256gcm_crypt(
            kat_aes256gcm_key1,
            kat_aes256gcm_aad1, sizeof(kat_aes256gcm_aad1),
            kat_aes256gcm_pt1, sizeof(kat_aes256gcm_pt1));

end:
    return status;
}
