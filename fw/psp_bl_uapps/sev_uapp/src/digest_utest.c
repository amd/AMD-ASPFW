// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "ccp_direct_cipher.h"
#include "digest.h"
#include "digest_utest.h"
#include "sev_trace.h"

#define SHABUFFERLEN 1024
#define HASHLEN      64

typedef struct SHAVECTOR_T
{
    unsigned char aucMessage[SHABUFFERLEN];
    unsigned char aucHash[HASHLEN];
    unsigned int  uiMessageLen;
    unsigned int  uiHashLen;
} SHAVECTOR;

static SHAVECTOR SHAVector[] =
{
   {
      // Zero length input SHA256 vector
      "",
      {
         0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
         0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
         0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
         0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
      },
      0,
      32,
   },

   {
      /* 256 32 bytes message */
      {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      },
      {
         0x47, 0x73, 0xd1, 0x2e, 0x23, 0x71, 0xbb, 0x93,
         0x5b, 0x9a, 0x0f, 0x54, 0x39, 0xb4, 0xa1, 0xc3,
         0xad, 0x3f, 0x24, 0x14, 0xb8, 0x69, 0x80, 0xf8,
         0x41, 0x8d, 0x1c, 0xfa, 0xbd, 0xfa, 0xdf, 0xef
      },
      32,
      32,
   },

   {
      /* 256 64 bytes message */
      {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      },
      {
         0x18, 0x54, 0x6d, 0x1e, 0x49, 0x8d, 0xd4, 0xba,
         0x54, 0x49, 0x82, 0xe3, 0xbb, 0xd0, 0x96, 0x90,
         0x4d, 0xd7, 0x80, 0xa5, 0xd7, 0xa4, 0x83, 0xb1,
         0xbf, 0xc9, 0x21, 0x60, 0x60, 0x07, 0x2d, 0xef
      },
      64,
      32,
   },

   {
      /* 256 256 bytes message */
      {
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
      },
      {
         0x1c, 0x6a, 0x44, 0x8d, 0x8d, 0x49, 0x25, 0x54,
         0xe8, 0x49, 0xf0, 0x96, 0x33, 0xda, 0x5b, 0x2e,
         0x62, 0x3e, 0x44, 0x04, 0x99, 0x09, 0xc3, 0x6a,
         0x61, 0xdc, 0xbc, 0xdf, 0xbf, 0x05, 0x60, 0xbe
      },
      256,
      32,
   },

   {
      "abcd",
      {
         0x88, 0xd4, 0x26, 0x6f, 0xd4, 0xe6, 0x33, 0x8d,
         0x13, 0xb8, 0x45, 0xfc, 0xf2, 0x89, 0x57, 0x9d,
         0x20, 0x9c, 0x89, 0x78, 0x23, 0xb9, 0x21, 0x7d,
         0xa3, 0xe1, 0x61, 0x93, 0x6f, 0x03, 0x15, 0x89
      },
      4,
      32,
   },

   {
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      {
         0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
         0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
         0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
         0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
      },
      56,
      32,
   },
};

/**
 * Test vectors from RFC4231
 *
 * Test case 7
 *   Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 *                  aaaaaa                            (131 bytes)
 *   Data =         54686973206973206120746573742075  ("This is a test u")
 *                  73696e672061206c6172676572207468  ("sing a larger th")
 *                  616e20626c6f636b2d73697a65206b65  ("an block-size ke")
 *                  7920616e642061206c61726765722074  ("y and a larger t")
 *                  68616e20626c6f636b2d73697a652064  ("han block-size d")
 *                  6174612e20546865206b6579206e6565  ("ata. The key nee")
 *                  647320746f2062652068617368656420  ("ds to be hashed ")
 *                  6265666f7265206265696e6720757365  ("before being use")
 *                  642062792074686520484d414320616c  ("d by the HMAC al")
 *                  676f726974686d2e                  ("gorithm.")
 *
 *   HMAC-SHA-224 = 3a854166ac5d9f023f54d517d0b39dbd
 *                  946770db9c2b95c9f6f565d1
 *   HMAC-SHA-256 = 9b09ffa71b942fcb27635fbcd5b0e944
 *                  bfdc63644f0713938a7f51535c3a35e2
 *   HMAC-SHA-384 = 6617178e941f020d351e2f254e8fd32c
 *                  602420feb0b8fb9adccebb82461e99c5
 *                  a678cc31e799176d3860e6110c46523e
 *   HMAC-SHA-512 = e37b6a775dc87dbaa4dfa9f96e5e3ffd
 *                  debd71f8867289865df5a32d20cdc944
 *                  b6022cac3c4982b10d5eeb55c3e4de15
 *                  134676fb6de0446065c97440fa8c6a58
 */
__align(32) static const uint8_t kat_case7_data[] =
{
    0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x61,0x20,0x74,0x65,0x73,0x74,0x20,0x75,
    0x73,0x69,0x6e,0x67,0x20,0x61,0x20,0x6c,0x61,0x72,0x67,0x65,0x72,0x20,0x74,0x68,
    0x61,0x6e,0x20,0x62,0x6c,0x6f,0x63,0x6b,0x2d,0x73,0x69,0x7a,0x65,0x20,0x6b,0x65,
    0x79,0x20,0x61,0x6e,0x64,0x20,0x61,0x20,0x6c,0x61,0x72,0x67,0x65,0x72,0x20,0x74,
    0x68,0x61,0x6e,0x20,0x62,0x6c,0x6f,0x63,0x6b,0x2d,0x73,0x69,0x7a,0x65,0x20,0x64,
    0x61,0x74,0x61,0x2e,0x20,0x54,0x68,0x65,0x20,0x6b,0x65,0x79,0x20,0x6e,0x65,0x65,
    0x64,0x73,0x20,0x74,0x6f,0x20,0x62,0x65,0x20,0x68,0x61,0x73,0x68,0x65,0x64,0x20,
    0x62,0x65,0x66,0x6f,0x72,0x65,0x20,0x62,0x65,0x69,0x6e,0x67,0x20,0x75,0x73,0x65,
    0x64,0x20,0x62,0x79,0x20,0x74,0x68,0x65,0x20,0x48,0x4d,0x41,0x43,0x20,0x61,0x6c,
    0x67,0x6f,0x72,0x69,0x74,0x68,0x6d,0x2e
};

__align(32) static const uint8_t kat_case7_sha256[] = // sha256(kat_case7_data)
{
    0xa5,0xef,0x36,0x9e,0x36,0xe2,0x73,0x4f,0xad,0x02,0x85,0x11,0x43,0xd9,0x83,0x2b,
    0xd1,0xb3,0xf9,0x06,0x19,0x84,0xb7,0x5a,0x6f,0x37,0x36,0x32,0x74,0xe5,0x2d,0x86
};

__align(32) static const uint8_t kat_abcd[] = // "abcd"
{
    0x61,0x62,0x63,0x64
};

__align(32) static const uint8_t kat_abcd_sha256[] = // SHA256("abcd")
{
    0x88,0xd4,0x26,0x6f,0xd4,0xe6,0x33,0x8d,0x13,0xb8,0x45,0xfc,0xf2,0x89,0x57,0x9d,
    0x20,0x9c,0x89,0x78,0x23,0xb9,0x21,0x7d,0xa3,0xe1,0x61,0x93,0x6f,0x03,0x15,0x89
};

__align(32) static const uint8_t kat_nul_sha256[] = // sha256("")
{
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};

sev_status_t digest_utest_sha256_v1_impl(const uint8_t *msg,  size_t msg_size,
                                         const uint8_t *hash, int    multipart)
{
    sev_status_t     status;
    digest_sha_ctx_t ctx;
    digest_sha_t     digest;
    size_t           digest_size = sizeof(digest);

    memset(&ctx, 0, sizeof(ctx));
    memset(&digest, 0, sizeof(digest));

    status = digest_sha_init(&ctx, SHA_TYPE_256);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    while (multipart && msg_size > 64)
    {
        status = digest_sha_update(&ctx, msg, 64);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        msg += 64;
        msg_size -= 64;
    }

    status = digest_sha_update(&ctx, msg, msg_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_sha_final(&ctx, &digest, &digest_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // verify digest
    if (memcmp(hash, digest.digest, 32) != 0)
    {
        status = ERR_SECURE_DATA_VALIDATION;
    }

end:
    return status;
}

#define GUEST_MIN_ALIGN         (16)
digest_sha_ctx_t        ctx1 __attribute__((aligned (GUEST_MIN_ALIGN)));
digest_sha_ctx_t        ctx2 __attribute__((aligned (GUEST_MIN_ALIGN)));

sev_status_t digest_utest(void)
{
    sev_status_t     status = SEV_STATUS_SUCCESS;
    digest_sha_ctx_t ctx;
    digest_sha_t     digest;
    size_t           digest_size;
    size_t           i, j;

    for (i = 0; i < sizeof(SHAVector)/sizeof(SHAVector[0]); i++)
    {
        memset(&ctx, 0, sizeof(ctx));
        memset(&digest, 0, sizeof(digest));
        digest_size = sizeof(digest);

        status = digest_sha_init(&ctx, SHA_TYPE_256);
        if (status != SEV_STATUS_SUCCESS)
            break;

        status = digest_sha_update(&ctx, SHAVector[i].aucMessage,
                                   SHAVector[i].uiMessageLen);
        if (status != SEV_STATUS_SUCCESS)
            break;

        status = digest_sha_final(&ctx, &digest, &digest_size);
        if (status != SEV_STATUS_SUCCESS)
            break;

        for (j = 0; j < digest_size; j++)
        {
            if (SHAVector[i].aucHash[j] != digest.digest[j])
            {
                status = ERR_UNKNOWN;
                goto end;
            }
        }
    }
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // using v1 implementation
    status = digest_utest_sha256_v1_impl("", 0, kat_nul_sha256, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_utest_sha256_v1_impl(kat_abcd, sizeof(kat_abcd), kat_abcd_sha256, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_utest_sha256_v1_impl(kat_case7_data, sizeof(kat_case7_data), kat_case7_sha256, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_utest_sha256_v1_impl(kat_case7_data, sizeof(kat_case7_data), kat_case7_sha256, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_utest_sha256_kat(kat_abcd, sizeof(kat_abcd), kat_abcd_sha256, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = digest_utest_sha256_kat(kat_case7_data, sizeof(kat_case7_data), kat_case7_sha256, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

#ifdef GENOA_BRINGUP
    status = digest_utest_sha256_kat(kat_case7_data, sizeof(kat_case7_data), kat_case7_sha256, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // PLAT-102559: Mix contexts between Guests and don't SHA_FINAL
    do {
        memset(&ctx1, 0, sizeof(ctx1));
        memset(&ctx2, 0, sizeof(ctx2));

        // LaunchStart Guest 1 (Context 1)
        status = digest_sha_init(&ctx1, SHA_TYPE_256);
        if (status != SEV_STATUS_SUCCESS)
            break;

        // LaunchStart Guest 2 (Context 2)
        status = digest_sha_init(&ctx2, SHA_TYPE_256);
        if (status != SEV_STATUS_SUCCESS)
            break;

        // LaunchUpdate Guest 1 (Context 1)
        status = digest_sha_update(&ctx1, SHAVector[3].aucMessage, 64);
        if (status != SEV_STATUS_SUCCESS)
            break;

        // LaunchUpdate Guest 2 (Context 2)
        // 32B passes, 64B fails
        status = digest_sha_update(&ctx2, SHAVector[3].aucMessage, 64);
        if (status != SEV_STATUS_SUCCESS)
            break;
    } while (0);
#endif

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("digest_utest failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("digest_utest succeed!\n");
    }

    return status;
}
