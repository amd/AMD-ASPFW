//-----------------------------------------------------------------------------
// Copyright 2021 Advanced Micro Devices, Inc. All rights reserved.
//
// This document contains proprietary, confidential information that
// may be used, copied and/or disclosed only as authorized by a
// valid licensing agreement with ATI Technologies Inc. This copyright
// notice must be retained on all authorized copies.
//
// This code is provided "as is".  AMD Inc. makes, and
// the end user receives, no warranties or conditions, express,
// implied, statutory or otherwise, and ATI Technologies Inc.
// specifically disclaims any implied warranties of merchantability,
// non-infringement, or fitness for a particular purpose.
//
//-----------------------------------------------------------------------------

#ifndef SW_HASH_H_
#define SW_HASH_H_

#include "commontypes.h"
#include "sev_status.h"

// Used for SHA-1 and SHA-256
typedef struct SW_SHA_CONTEXT
{
      uint32_t          State[8];       // hash state
      uint8_t           Msg[64];        // currently processed block of the message
      uint32_t          Mlen;           // Length of the current block
      uint64_t          MsgLen;         // total length of the message

} SW_SHA_CONTEXT;

#if 0
// Used for SHA-384 and SHA-512
typedef struct SW_SHA2_CONTEXT
{
      uint64_t          State[8];       // hash state
      uint8_t           Msg[128];       // currently processed block of the message
      uint32_t          Mlen;           // Length of the current block
      uint64_t          MsgLen;         // total length of the message

} SW_SHA2_CONTEXT;

// Function prototypes
//
uint32_t SW_SHA1_Init( SW_SHA_CONTEXT* pOp );

uint32_t SW_SHA1_Process(   SW_SHA_CONTEXT*     pOp,
                            const uint8_t*      pMsg,
                            uint32_t            MsgLen );

uint32_t SW_SHA1_Final( SW_SHA_CONTEXT*     pOp,
                        uint8_t*            pHash,
                        uint32_t            HashLen );

uint32_t SW_SHA224_Init( SW_SHA_CONTEXT* pOp );

uint32_t SW_SHA224_Process( SW_SHA_CONTEXT*     pOp,
                            const uint8_t*      pMsg,
                            uint32_t            MsgLen );

uint32_t SW_SHA224_Final(   SW_SHA_CONTEXT*     pOp,
                            uint8_t*            pHash,
                            uint32_t            HashLen );
#endif

sev_status_t SW_SHA256_Init( SW_SHA_CONTEXT* pOp );

sev_status_t SW_SHA256_Process( SW_SHA_CONTEXT*     pOp,
                            const uint8_t*      pMsg,
                            uint32_t            MsgLen );

sev_status_t SW_SHA256_Final(   SW_SHA_CONTEXT*     pOp,
                            uint8_t*            pHash,
                            uint32_t            HashLen );

#if 0
uint32_t SW_SHA384_Init( SW_SHA2_CONTEXT* pOp );

uint32_t SW_SHA384_Process( SW_SHA2_CONTEXT*    pOp,
                            const uint8_t*      pMsg,
                            uint32_t            MsgLen );

uint32_t SW_SHA384_Final(   SW_SHA2_CONTEXT*    pOp,
                            uint8_t*            pHash,
                            uint32_t            HashLen );

uint32_t SW_SHA512_Init( SW_SHA2_CONTEXT* pOp );

uint32_t SW_SHA512_Process( SW_SHA2_CONTEXT*    pOp,
                            const uint8_t*      pMsg,
                            uint32_t            MsgLen );

uint32_t SW_SHA512_Final(   SW_SHA2_CONTEXT*    pOp,
                            uint8_t*            pHash,
                            uint32_t            HashLen );

#endif

#endif // SW_HASH_H_
