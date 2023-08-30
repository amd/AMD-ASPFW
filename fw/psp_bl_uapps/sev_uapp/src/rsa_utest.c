// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rsa.h"
#include "rsa_utest.h"
#include "sev_globals.h"
#include "sev_trace.h"

#define RSA_PSS_BUFFER_LEN          256
#define RSA_PSS_EXP_LEN             4

typedef struct _RSAPSSVECTOR
{
    unsigned char   Modulus[RSA_PSS_BUFFER_LEN];
    unsigned char   Exp[RSA_PSS_EXP_LEN];
    unsigned char   Signature[RSA_PSS_BUFFER_LEN];
    unsigned char   Hash[32];
    unsigned int    ModulusLen;
    unsigned int    ExpLen;
    unsigned int    SignatureLen;
    unsigned int    HashLen;
} RSAPSSVECTOR;

static RSAPSSVECTOR RSAPSSVector[] =
   {
      /* RSA-PSS */
      {
         {
                0x11, 0x44, 0xd1, 0xd0, 0x91, 0xa8, 0x83, 0x67, 0x78, 0x1e, 0xd0, 0xec, 0x69, 0x1c, 0xd5, 0x6a,
                0x7f, 0x3b, 0x04, 0x7c, 0x4a, 0x78, 0xc4, 0x21, 0x11, 0x93, 0x55, 0x30, 0xc5, 0x17, 0xc0, 0x97,
                0xcf, 0x5d, 0xc7, 0x0e, 0x25, 0xcb, 0x9d, 0x87, 0x8e, 0x80, 0x2d, 0xae, 0xee, 0x0a, 0xa1, 0xfd,
                0xd7, 0xc8, 0x9c, 0x82, 0x0b, 0xcd, 0x16, 0x4d, 0x95, 0x76, 0x17, 0x33, 0x6d, 0x54, 0x0b, 0x3c,
                0x8e, 0x4a, 0xd1, 0xbe, 0xcc, 0xa8, 0xdc, 0x57, 0x69, 0xc6, 0xe9, 0x32, 0x13, 0x07, 0x5b, 0xf0,
                0x46, 0x6d, 0x73, 0xb7, 0x3c, 0xcf, 0x05, 0x61, 0x1b, 0x25, 0x89, 0x30, 0x65, 0xc0, 0x25, 0x84,
                0x04, 0xc7, 0x5d, 0xa2, 0xed, 0x5f, 0x9e, 0x8f, 0xd5, 0x8a, 0x72, 0x7e, 0x66, 0x53, 0xfd, 0x03,
                0xde, 0xea, 0x17, 0x68, 0xff, 0xec, 0x52, 0x95, 0x35, 0x29, 0xa6, 0xc9, 0xba, 0x15, 0x3d, 0x4b,
                0xfa, 0x6f, 0xa9, 0x71, 0xc4, 0x15, 0xa6, 0xc3, 0xe2, 0xaf, 0xfe, 0x40, 0xb1, 0x2c, 0xd6, 0xb4,
                0xb3, 0x38, 0x9d, 0x55, 0xab, 0xa2, 0xde, 0xcc, 0x4d, 0x62, 0xc7, 0xed, 0x97, 0x05, 0x26, 0x77,
                0x33, 0x6c, 0x60, 0x1d, 0x35, 0xba, 0xd0, 0x3f, 0x1c, 0x8e, 0x1e, 0xe4, 0xd1, 0x43, 0x5b, 0x90,
                0xea, 0x43, 0x41, 0x17, 0x32, 0x92, 0x21, 0x59, 0x8c, 0x16, 0xe8, 0x4b, 0x5a, 0x89, 0xfd, 0x8c,
                0xfd, 0xb8, 0xd3, 0x17, 0x41, 0x40, 0x43, 0x40, 0x0a, 0xcb, 0x0d, 0x40, 0x31, 0x2a, 0x34, 0xd7,
                0x1f, 0xcc, 0x1d, 0x67, 0x52, 0xec, 0xfe, 0xdb, 0xce, 0x6e, 0x11, 0x1a, 0x60, 0x90, 0x38, 0xdb,
                0x54, 0xd8, 0x16, 0xb1, 0xb2, 0xfe, 0x86, 0x12, 0xa3, 0xba, 0x87, 0x68, 0x9d, 0x24, 0xd6, 0x3f,
                0xe3, 0xf8, 0x35, 0x51, 0xf4, 0x81, 0x84, 0xb1, 0x30, 0x46, 0xe0, 0xde, 0x55, 0x81, 0x54, 0xc7,
         },
         {
                0x01, 0x00, 0x01, 0x00,
         },
         {
                0x38, 0x3c, 0x11, 0x5f, 0xe3, 0x79, 0x72, 0x17, 0xed, 0xed, 0x2d, 0xdf, 0x33, 0x0b, 0x3e, 0xc6,
                0x55, 0xa4, 0xee, 0x00, 0x29, 0x7a, 0x08, 0x20, 0xe8, 0xaa, 0xe5, 0xc3, 0x0d, 0x46, 0x29, 0x64,
                0x42, 0x23, 0x9c, 0x02, 0x38, 0xc9, 0x51, 0x04, 0xe4, 0xa0, 0xcb, 0x82, 0x24, 0x48, 0xca, 0xa8,
                0x12, 0x76, 0x00, 0x5d, 0xce, 0xff, 0xe4, 0x69, 0x1f, 0xca, 0xcf, 0x99, 0x69, 0xa5, 0x7e, 0xb3,
                0x40, 0x4a, 0x38, 0xbf, 0x29, 0x05, 0x71, 0xb4, 0xeb, 0x29, 0xf1, 0x42, 0xb7, 0xf4, 0xe0, 0xeb,
                0xf0, 0xd0, 0x07, 0xf3, 0x77, 0xb6, 0x79, 0xde, 0x71, 0xfa, 0xff, 0x9e, 0x2a, 0xb8, 0x7c, 0x37,
                0xd7, 0xa4, 0x1a, 0x6a, 0x5b, 0xcd, 0x4b, 0x2c, 0x30, 0xf7, 0x88, 0xac, 0xc1, 0x9f, 0xd5, 0xf3,
                0x7e, 0xda, 0x17, 0x0c, 0x11, 0x64, 0xe2, 0x78, 0x93, 0x1d, 0xd8, 0xe8, 0x19, 0x0d, 0xad, 0x3f,
                0x02, 0xd9, 0x79, 0x1c, 0xc1, 0xb4, 0x5c, 0xa0, 0x8d, 0xd9, 0xb5, 0x1b, 0xda, 0x12, 0x3f, 0xb2,
                0x09, 0x73, 0x3f, 0x0b, 0x16, 0xc9, 0x2c, 0x78, 0xf7, 0x18, 0x64, 0x44, 0xd5, 0x19, 0x9a, 0xfe,
                0x41, 0xca, 0x27, 0xb3, 0x65, 0x58, 0x23, 0xc7, 0x6a, 0x2a, 0x7e, 0xa0, 0x21, 0x62, 0x90, 0x5e,
                0x58, 0xad, 0xd9, 0x00, 0xc8, 0x23, 0xfb, 0x1f, 0x5c, 0x11, 0x7e, 0x53, 0x44, 0x19, 0x62, 0xe2,
                0x25, 0x2d, 0xe5, 0x97, 0x15, 0x11, 0xe7, 0x29, 0xb4, 0xa2, 0xe1, 0xd3, 0xe6, 0x90, 0x34, 0x36,
                0x7f, 0xce, 0x05, 0x71, 0x32, 0x07, 0x4d, 0x3a, 0x96, 0xc1, 0x45, 0x2c, 0x8d, 0xbc, 0x38, 0x02,
                0x36, 0x9d, 0x7d, 0xd7, 0x42, 0xc7, 0x16, 0x37, 0xb7, 0x4c, 0xd2, 0x2d, 0xbe, 0x89, 0x31, 0xca,
                0x46, 0x55, 0xc0, 0x05, 0x74, 0x36, 0x4f, 0xca, 0x2f, 0x51, 0x7b, 0xc7, 0x3d, 0xe9, 0x3a, 0x6a,
         },
         {
                0x9e, 0x6e, 0x79, 0x4b, 0x7c, 0xe1, 0xfc, 0x83, 0x33, 0x8b, 0x21, 0xfe, 0x87, 0xff, 0xd7, 0x84,
                0x6f, 0x14, 0xd9, 0xec, 0xa2, 0x0b, 0xb7, 0xaf, 0x2e, 0xac, 0x54, 0x26, 0x4e, 0x2b, 0x1d, 0xaf,
         },
         256,
         4,
         256,
         32,
      },
};


sev_status_t rsa_utest(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t index = 0;

    for (index = 0; index < ARRAY_LENGTH(RSAPSSVector); index++)
    {
        status = rsa_pss_verify(RSAPSSVector[index].Hash,
                                RSAPSSVector[index].HashLen,
                                RSAPSSVector[index].Modulus,
                                RSAPSSVector[index].ModulusLen,
                                RSAPSSVector[index].Exp,
                                RSAPSSVector[index].ExpLen,
                                RSAPSSVector[index].Signature);
        if (status != SEV_STATUS_SUCCESS)
        {
            break;
        }
    }

    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("rsa_utest failed...\n");
        SEV_TRACE_EX(status, index, 0, 0);
    }
    else
    {
        SEV_TRACE("rsa_utest succeed!\n");
    }

    return status;
}
