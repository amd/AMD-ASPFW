//-----------------------------------------------------------------------------
// Copyright 2016 Advanced Micro Devices, Inc. All rights reserved.
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

#include "sw_hash.h"

static inline unsigned long ByteSwapUlong( unsigned long Param )
{
    return ( ( Param >> 24 ) |
           ( (Param >> 8  ) & 0x0000FF00 ) |
           ( (Param << 8  ) & 0x00FF0000 ) |
           ( (Param << 24 ) & 0xFF000000 ) );
}

static inline uint32_t Read_dword_be( uint8_t const* V )
{
   uint32_t Ret = 0;

   Ret |= (uint32_t) V[3];
   Ret |= ((uint32_t) V[2]) << 8;
   Ret |= ((uint32_t) V[1]) << 16;
   Ret |= ((uint32_t) V[0]) << 24;

   return Ret;
}

#define GETDWORD( x )               ByteSwapUlong( *(uint32_t*) &((x)[0]) )
#define GETDWORD_MISALIGNED( x )    Read_dword_be( (uint8_t const*) &((x)[0]) )

#define STOREDWORD( x, y )          *(uint32_t*)(x) = ByteSwapUlong( y );

#define GETUINT64( x )              (uint64_t)( (uint64_t)ByteSwapUlong(*(uint32_t*)&((x)[4])) +\
                                                (uint64_t)( (uint64_t)ByteSwapUlong(*(uint32_t*)&((x)[0])) << 32 ))
#define GETUINT64_MISALIGNED( x )   (uint64_t)( (uint64_t)Read_dword_be( (uint8_t const*)&((x)[4])) +\
                                                (uint64_t)( (uint64_t)Read_dword_be( (uint8_t const*)&((x)[0])) << 32 ))

#define STOREUINT64( x, y )         *(uint64_t*)(x) = ( (uint64_t)ByteSwapUlong( (uint32_t)((uint64_t)(y) >> 32) ) +\
                                                    ((uint64_t)ByteSwapUlong( (uint32_t)(y) ) << 32) );

#define TEE_SUCCESS 0

typedef uint8_t     BYTE;
typedef uint32_t    DWORD;
typedef uint64_t    UINT64;

#define ROR(x,b)                (((x) >> (b)) | ((x) << (32 - (b))))
#define ROL(x,b)                (((x) << (b)) | ((x) >> (32 - (b))))

#define ROR64( value, shift )   (UINT64)(((UINT64)(value) >> shift) | ((UINT64)(value) << (64 - shift)))
#define ROL64( value, shift )   (UINT64)(((UINT64)(value) << shift) | ((UINT64)(value) >> (64 - shift)))

#define SHA256_HASH_SIZE                    32
#define SHA384_HASH_SIZE                    48

#if 0
/////////////////////////////////////////////////////////////////////////////////////////////////
//
//        SHA-1 implementation.
//

/*-----------------------------------------------------------------------------
    SHA-1 compression function
*/
void SHA1_Compress( DWORD State[5], const BYTE Msg[64] )
{
    DWORD   a = State[0];
    DWORD   b = State[1];
    DWORD   c = State[2];
    DWORD   d = State[3];
    DWORD   e = State[4];
    DWORD   t;
    DWORD   W[80];
    DWORD   i;


    // break chunk into sixteen 32-bit big-endian words w[i], 0 = i = 15
    if( ((uint32_t)&Msg[0] & 0x03) != 0 )   // Msg is not 4-byte aligned
    {
        for( i = 0; i < 16; i++ )
        {
            W[i] = GETDWORD_MISALIGNED( Msg );
            Msg += 4;
        }
    }
    else    // Msg is 4-byte aligned
    {
        for( i = 0; i < 16; i++ )
        {
            W[i] = GETDWORD( Msg );
            Msg += 4;
        }
    }

    // Extend the sixteen 32-bit words into eighty 32-bit words
    for( i = 16; i < 80; i++ )
        W[i] = ROL( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );

    for( i = 0; i < 20; i++ )
    {
        t = ROL( a, 5 ) + ( d ^ ( b & (c ^ d) ) ) + e + 0x5A827999 + W[i];
        e = d;    d = c;    c = ROL( b, 30 );    b = a;    a = t;
    }

    for( i = 20; i < 40; i++ )
    {
        t = ROL( a, 5 ) + ( b ^ c  ^ d ) + e + 0x6ED9EBA1 + W[i];
        e = d;    d = c;    c = ROL( b, 30 );    b = a;    a = t;
    }

    for( i = 40; i < 60; i++ )
    {
        t = ROL( a, 5 ) + ( (b & c) | ( d & (b | c) ) ) + e + 0x8F1BBCDC + W[i];
        e = d;    d = c;    c = ROL( b, 30 );    b = a;    a = t;
    }

    for( i = 60; i < 80; i++ )
    {
        t = ROL( a, 5 ) + ( b ^ c  ^ d ) + e + 0xCA62C1D6 + W[i];
        e = d;    d = c;    c = ROL( b, 30 );    b = a;    a = t;
    }

    State[0] += a;
    State[1] += b;
    State[2] += c;
    State[3] += d;
    State[4] += e;
}


/*-----------------------------------------------------------------------------

    Initialization of SHA-1 operation.

    Parameters:
        pOp     -    operation context

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA1_Init( SW_SHA_CONTEXT* pOp )
{
    uint32_t    status = TEE_SUCCESS;


    // Make sure that context contains all zeroes
    //
    memset( pOp, 0, sizeof(*pOp) );

    pOp->State[0]       = 0x67452301;
    pOp->State[1]       = 0xEFCDAB89;
    pOp->State[2]       = 0x98BADCFE;
    pOp->State[3]       = 0x10325476;
    pOp->State[4]       = 0xC3D2E1F0;

    return status;
}


/*-----------------------------------------------------------------------------

    SHA1 hash operation.

    Parameters:
        pOp         -   operation context
        pData       -   data to be hashed
        DataLen     -   data length

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA1_Process(   SW_SHA_CONTEXT*     pOp,
                            const BYTE*         pMsg,
                            DWORD               MsgLen )
{
    uint32_t    status = TEE_SUCCESS;
    DWORD       Mlen;
    DWORD       BytesToCopy;


    Mlen = pOp->Mlen;

    pOp->MsgLen += MsgLen;        // summarize the total number of bytes processed.

    while( MsgLen > 0 )
    {
        // If remaining message length is less than BlockSize bytes or internal buffer
        // is not empty, then copy message to the internal buffer. Then, if the
        // buffer is full, compress it.
        //
        if( ( MsgLen < 64 ) || ( Mlen != 0 ) )
        {
            if( Mlen + MsgLen >= 64 )
                BytesToCopy = 64 - Mlen;
            else
                BytesToCopy = MsgLen;

            memcpy( &pOp->Msg[Mlen], pMsg, BytesToCopy );

            MsgLen -= BytesToCopy;
            Mlen += BytesToCopy;
            pMsg += BytesToCopy;

            if( Mlen == 64 )
            {
                SHA1_Compress( pOp->State, pOp->Msg );

                Mlen = 0;
            }
        }
        else
        {
            // Internal buffer is empty and remaining msg length is bigger then
            // or equal to 64 bytes. Then just compress 64 bytes of the message.
            //
            SHA1_Compress( pOp->State, pMsg );

            MsgLen -= 64;
            pMsg += 64;
        }
    }

    pOp->Mlen = Mlen;

    return status;
}


/*-----------------------------------------------------------------------------

    Finalize SHA1 hash operation and send hash value to the caller function.

    Parameters:
        pOp         -   operation context
        pHash       -   ptr to receive hash value
        HashLen     -   buffer length

    Return value:
        TEE_SUCCESS or error code

    Notes:  if HashLen is smaller than KC_SHA1_HASH_LEN, function will return
            error code TEE_ERROR_SHORT_BUFFER.
*/
uint32_t SW_SHA1_Final( SW_SHA_CONTEXT*     pOp,
                        BYTE*               pHash,
                        DWORD               HashLen )
{
    uint32_t    status = TEE_SUCCESS;
    DWORD       Mlen;
    BYTE*       pM;


    if( HashLen < SHA1_HASH_SIZE )
        return TEE_ERROR_SHORT_BUFFER;

    Mlen = pOp->Mlen;
    pM = &pOp->Msg[0];

    pOp->Msg[Mlen++] = 0x80;    // append bit '1' to the message

    // We will have to add the length of the message before padding
    // ( 8 bytes of pOp->MsgLen ) to the end of the message, and keep padded
    // message length multiple of 64. Therefore, if current internal buffer
    // doesn't have space for pOp->MsgLen, we have to padd it with zeroes,
    // compress and add another 64 bytes ( 56 zeroes + pOp->MsgLen )
    //
    if( Mlen > 56 )
    {
        while( Mlen < 64 )
            pM[Mlen++] = 0;

        SHA1_Compress( pOp->State, pOp->Msg );

        Mlen = 0;
    }

    //
    // Pad the rest of the buffer with zeroes, add pOp->MsgLen ( in bits ) and compress.
    //

    while( Mlen < 56 )
        pM[Mlen++] = 0;

    pOp->MsgLen = pOp->MsgLen << 3;        // length in bits

    STOREUINT64( &pM[Mlen], pOp->MsgLen );

    SHA1_Compress( pOp->State, pOp->Msg );

    // Copy SHA-1 state to the output
    //
    STOREDWORD( &pHash[0],  pOp->State[0] )
    STOREDWORD( &pHash[4],  pOp->State[1] )
    STOREDWORD( &pHash[8],  pOp->State[2] )
    STOREDWORD( &pHash[12], pOp->State[3] )
    STOREDWORD( &pHash[16], pOp->State[4] )

    return status;
}


/*-----------------------------------------------------------------------------

    Performs SHA-1 hash operation on given data. This function just wraps three
    other functions to provide simple one-call interface.

    Parameters:
        pData       -   data to be hashed
        DataLen     -   data length
        pHash       -   ptr to receive hash value
        HashLen     -   hash buffer length

    Return value:
        TEE_SUCCESS, or errorcode
*/
uint32_t SW_SHA1_Hash(  const BYTE*     pData,
                        DWORD           DataLen,
                        BYTE*           pHash,
                        DWORD           HashLen )
{
    uint32_t            status = TEE_SUCCESS;
    SW_SHA_CONTEXT      Op;


    do
    {
        if( TEE_SUCCESS != ( status = SW_SHA1_Init( &Op ) ) )
            break;

        if( TEE_SUCCESS != ( status = SW_SHA1_Process( &Op, pData, DataLen ) ) )
            break;

        if( TEE_SUCCESS != ( status = SW_SHA1_Final( &Op, pHash, HashLen ) ) )
            break;

    } while( 0 );

    return status;
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////
//
//        SHA-256 implementation.
//

static const DWORD    K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


/*-----------------------------------------------------------------------------
    SHA-256 compression function
*/
void SHA256_Compress( DWORD State[8], const BYTE Msg[64] )
{
    DWORD    a = State[0];
    DWORD    b = State[1];
    DWORD    c = State[2];
    DWORD    d = State[3];
    DWORD    e = State[4];
    DWORD    f = State[5];
    DWORD    g = State[6];
    DWORD    h = State[7];
    DWORD    s0;
    DWORD    s1;
    DWORD    maj;
    DWORD    ch;
    DWORD    t1;
    DWORD    t2;
    DWORD    W[64];
    DWORD    i;


    // break chunk into sixteen 32-bit big-endian words w[i], 0 = i = 15
    if( ((uint32_t)&Msg[0] & 0x03) != 0 )   // Msg is not 4-byte aligned
    {
        for( i = 0; i < 16; i++ )
        {
            W[i] = GETDWORD_MISALIGNED( Msg );
            Msg += 4;
        }
    }
    else    // Msg is 4-byte aligned
    {
        for( i = 0; i < 16; i++ )
        {
            W[i] = GETDWORD( Msg );
            Msg += 4;
        }
    }

    // Extend the sixteen 32-bit words into sixty-four 32-bit words:
    for( i = 16; i < 64; i++ )
    {
        s0 = ROR( W[i-15], 7 ) ^ ROR( W[i-15], 18 ) ^ ( W[i-15] >> 3 );
        s1 = ROR( W[i-2], 17 ) ^ ROR( W[i-2], 19 ) ^ ( W[i-2] >> 10 );
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    // Main loop
    for( i = 0; i < 64; i++ )
    {
        s0 = ROR( a, 2 ) ^ ROR( a, 13 ) ^ ROR( a, 22 );
        maj = ( (a | b) & c ) | (a & b);
        t2 = s0 + maj;
        s1 = ROR( e, 6 ) ^ ROR( e, 11 ) ^ ROR( e, 25 );
        ch = g ^ ( e & (f ^ g) );
        t1 = h + s1 + ch + K[i] + W[i];
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    State[0] += a;
    State[1] += b;
    State[2] += c;
    State[3] += d;
    State[4] += e;
    State[5] += f;
    State[6] += g;
    State[7] += h;
}

/*-----------------------------------------------------------------------------

    Initialization of SHA-256 operation.

    Parameters:
        pOp            -    operation context

    Return value:
        sev_status_t or error code
*/
sev_status_t SW_SHA256_Init( SW_SHA_CONTEXT* pOp )
{
    sev_status_t status = SEV_STATUS_SUCCESS;


    // Make sure that context contains all zeroes
    //
    memset( pOp, 0, sizeof(*pOp) );

    pOp->State[0]   = 0x6a09e667;
    pOp->State[1]   = 0xbb67ae85;
    pOp->State[2]   = 0x3c6ef372;
    pOp->State[3]   = 0xa54ff53a;
    pOp->State[4]   = 0x510e527f;
    pOp->State[5]   = 0x9b05688c;
    pOp->State[6]   = 0x1f83d9ab;
    pOp->State[7]   = 0x5be0cd19;

    return status;
}


/*-----------------------------------------------------------------------------

    SHA256 hash operation.

    Parameters:
        pOp         -    operation context
        pData       -    data to be hashed
        DataLen     -    data length

    Return value:
        sev_status_t or error code
*/
sev_status_t SW_SHA256_Process( SW_SHA_CONTEXT*     pOp,
                            const BYTE*         pMsg,
                            DWORD               MsgLen )
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    DWORD       Mlen;
    DWORD       BytesToCopy;
    DWORD       BlockSize = 64;


    Mlen = pOp->Mlen;

    pOp->MsgLen += MsgLen;      // summarize the total number of bytes processed.

    while( MsgLen > 0 )
    {
        // If remaining message length is less than BlockSize bytes or internal buffer
        // is not empty, then copy message to the internal buffer. Then, if the
        // buffer is full, compress it.
        //
        if( ( MsgLen < BlockSize ) || ( Mlen != 0 ) )
        {
            if( Mlen + MsgLen >= BlockSize )
                BytesToCopy = BlockSize - Mlen;
            else
                BytesToCopy = MsgLen;

            memcpy( &pOp->Msg[Mlen], pMsg, BytesToCopy );

            MsgLen -= BytesToCopy;
            Mlen += BytesToCopy;
            pMsg += BytesToCopy;

            if( Mlen == BlockSize )
            {
                SHA256_Compress( pOp->State, pOp->Msg );

                Mlen = 0;
            }
        }
        else
        {
            // Internal buffer is empty and remaining msg length is bigger then
            // or equal to BlockSize bytes. Then just compress BlockSize bytes
            // of the message.
            //
            SHA256_Compress( pOp->State, pMsg );

            MsgLen -= BlockSize;
            pMsg += BlockSize;
        }
    }

    pOp->Mlen = Mlen;

    return status;
}


/*-----------------------------------------------------------------------------

    Finalize SHA256 hash operation and send hash value to the caller function.

    Parameters:
        pOp         -    operation context
        pHash       -    ptr to receive hash value
        HashLen     -    buffer length

    Return value:
        sev_status_t, or errorcode

    Notes:  if HashLen is smaller than hash length of the selected SHA-256 hash,
            function will return error code TEE_ERROR_SHORT_BUFFER.
*/
sev_status_t SW_SHA256_Final(   SW_SHA_CONTEXT*     pOp,
                            BYTE*               pHash,
                            DWORD               HashLen )
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    DWORD       Mlen;
    BYTE*       pM;


    if( HashLen < SHA256_HASH_SIZE )
        return SEV_STATUS_INVALID_LENGTH;

    Mlen = pOp->Mlen;
    pM = &pOp->Msg[0];

    pOp->Msg[Mlen++] = 0x80;    // append bit '1' to the message

    // We will have to add the length of the message before padding
    // ( 8 bytes of pOp->MsgLen ) to the end of the message, and keep padded
    // message length multiple of 64. Therefore, if current internal buffer
    // doesn't have space for pOp->MsgLen, we have to padd it with zeroes,
    // compress and add another 64 bytes ( 56 zeroes + pOp->MsgLen )
    //
    if( Mlen > 56 )
    {
        while( Mlen < 64 )
            pM[Mlen++] = 0;

        SHA256_Compress( pOp->State, pOp->Msg );

        Mlen = 0;
    }

    //
    // Pad the rest of the buffer with zeroes, add pOp->MsgLen ( in bits ) and compress.
    //

    while( Mlen < 56 )
        pM[Mlen++] = 0;

    pOp->MsgLen = pOp->MsgLen << 3;        // length in bits

    STOREUINT64( &pM[Mlen], pOp->MsgLen );

    SHA256_Compress( pOp->State, pOp->Msg );

    // Copy SHA-256 state to the output
    //
    STOREDWORD( &pHash[0],  pOp->State[0] )
    STOREDWORD( &pHash[4],  pOp->State[1] )
    STOREDWORD( &pHash[8],  pOp->State[2] )
    STOREDWORD( &pHash[12], pOp->State[3] )
    STOREDWORD( &pHash[16], pOp->State[4] )
    STOREDWORD( &pHash[20], pOp->State[5] )
    STOREDWORD( &pHash[24], pOp->State[6] )
    STOREDWORD( &pHash[28], pOp->State[7] )

    return status;
}

/*-----------------------------------------------------------------------------

    Performs SHA-256 hash operation on given data. This function just wraps three
    other functions to provide simple one-call interface.

    Parameters:
        pData       -    data to be hashed
        DataLen     -    data length
        pHash       -    ptr to receive hash value
        HashLen     -    hash buffer length

    Return value:
        TEE_SUCCESS, or errorcode
*/
sev_status_t SW_SHA256_Hash(    const BYTE*     pData,
                            DWORD           DataLen,
                            BYTE*           pHash,
                            DWORD           HashLen )
{
    sev_status_t        status = SEV_STATUS_SUCCESS;
    SW_SHA_CONTEXT      Op;


    do
    {
        if( SEV_STATUS_SUCCESS != ( status = SW_SHA256_Init( &Op ) ) )
            break;

        if( SEV_STATUS_SUCCESS != ( status = SW_SHA256_Process( &Op, pData, DataLen ) ) )
            break;

        if( SEV_STATUS_SUCCESS != ( status = SW_SHA256_Final( &Op, pHash, HashLen ) ) )
            break;

    } while( 0 );

    return status;
}

#if 0
/*-----------------------------------------------------------------------------

    Initialization of SHA-224 operation.

    Parameters:
        pOp            -    operation context

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA224_Init( SW_SHA_CONTEXT* pOp )
{
    int        status = TEE_SUCCESS;


    // Make sure that context contains all zeroes
    //
    memset( pOp, 0, sizeof(*pOp) );

    pOp->State[0]   = 0xc1059ed8;
    pOp->State[1]   = 0x367cd507;
    pOp->State[2]   = 0x3070dd17;
    pOp->State[3]   = 0xf70e5939;
    pOp->State[4]   = 0xffc00b31;
    pOp->State[5]   = 0x68581511;
    pOp->State[6]   = 0x64f98fa7;
    pOp->State[7]   = 0xbefa4fa4;

    return status;
}

/*-----------------------------------------------------------------------------

    SHA224 hash operation.

    Parameters:
        pOp         -    operation context
        pData       -    data to be hashed
        DataLen     -    data length

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA224_Process( SW_SHA_CONTEXT*     pOp,
                            const BYTE*         pMsg,
                            DWORD               MsgLen )
{
    return SW_SHA256_Process( pOp,
                              pMsg,
                              MsgLen );
}

/*-----------------------------------------------------------------------------

    Finalize SHA224 hash operation and send hash value to the caller function.

    Parameters:
        pOp         -    operation context
        pHash       -    ptr to receive hash value
        HashLen     -    buffer length

    Return value:
        TEE_SUCCESS, or errorcode

    Notes:  if HashLen is smaller than hash length of the selected SHA-224 hash,
            function will return error code TEE_ERROR_SHORT_BUFFER.
*/
uint32_t SW_SHA224_Final(   SW_SHA_CONTEXT*     pOp,
                            BYTE*               pHash,
                            DWORD               HashLen )
{
    int         status = TEE_SUCCESS;
    DWORD       Mlen;
    BYTE*       pM;


    if( HashLen < SHA224_HASH_SIZE )
        return TEE_ERROR_SHORT_BUFFER;

    Mlen = pOp->Mlen;
    pM = &pOp->Msg[0];

    pOp->Msg[Mlen++] = 0x80;    // append bit '1' to the message

    // We will have to add the length of the message before padding
    // ( 8 bytes of pOp->MsgLen ) to the end of the message, and keep padded
    // message length multiple of 64. Therefore, if current internal buffer
    // doesn't have space for pOp->MsgLen, we have to padd it with zeroes,
    // compress and add another 64 bytes ( 56 zeroes + pOp->MsgLen )
    //
    if( Mlen > 56 )
    {
        while( Mlen < 64 )
            pM[Mlen++] = 0;

        SHA256_Compress( pOp->State, pOp->Msg );

        Mlen = 0;
    }

    //
    // Pad the rest of the buffer with zeroes, add pOp->MsgLen ( in bits ) and compress.
    //

    while( Mlen < 56 )
        pM[Mlen++] = 0;

    pOp->MsgLen = pOp->MsgLen << 3;        // length in bits

    STOREUINT64( &pM[Mlen], pOp->MsgLen );

    SHA256_Compress( pOp->State, pOp->Msg );

    // Copy SHA-256 state to the output
    // For SHA-224, only the first 7 DWORDs of SHA-256 hash are used
    //
    STOREDWORD( &pHash[0],  pOp->State[0] )
    STOREDWORD( &pHash[4],  pOp->State[1] )
    STOREDWORD( &pHash[8],  pOp->State[2] )
    STOREDWORD( &pHash[12], pOp->State[3] )
    STOREDWORD( &pHash[16], pOp->State[4] )
    STOREDWORD( &pHash[20], pOp->State[5] )
    STOREDWORD( &pHash[24], pOp->State[6] )

    return status;
}

/*-----------------------------------------------------------------------------

    Performs SHA-224 hash operation on given data. This function just wraps three
    other functions to provide simple one-call interface.

    Parameters:
        pData       -    data to be hashed
        DataLen     -    data length
        pHash       -    ptr to receive hash value
        HashLen     -    hash buffer length

    Return value:
        TEE_SUCCESS, or errorcode
*/
uint32_t SW_SHA224_Hash(    const BYTE*     pData,
                            DWORD           DataLen,
                            BYTE*           pHash,
                            DWORD           HashLen )
{
    uint32_t            status = TEE_SUCCESS;
    SW_SHA_CONTEXT      Op;


    do
    {
        if( TEE_SUCCESS != ( status = SW_SHA224_Init( &Op ) ) )
            break;

        if( TEE_SUCCESS != ( status = SW_SHA224_Process( &Op, pData, DataLen ) ) )
            break;

        if( TEE_SUCCESS != ( status = SW_SHA224_Final( &Op, pHash, HashLen ) ) )
            break;

    } while( 0 );

    return status;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//
//        SHA-512 implementation.
//

static const UINT64    K_512[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/*-----------------------------------------------------------------------------
    SHA-512 compression function
*/
void SHA512_Compress( UINT64 State[8], const BYTE Msg[64] )
{
    UINT64    a = State[0];
    UINT64    b = State[1];
    UINT64    c = State[2];
    UINT64    d = State[3];
    UINT64    e = State[4];
    UINT64    f = State[5];
    UINT64    g = State[6];
    UINT64    h = State[7];
    UINT64    s0;
    UINT64    s1;
    UINT64    maj;
    UINT64    ch;
    UINT64    t1;
    UINT64    t2;
    UINT64    W[80];
    DWORD    i;


    // break chunk into sixteen 64-bit big-endian words w[i], 0 = i = 15
    if( ((uint32_t)&Msg[0] & 0x03) != 0 )   // Msg is not 4-byte aligned
    {
        for( i = 0; i < 16; i++ )
        {
            W[i] = GETUINT64_MISALIGNED( Msg );
            Msg += 8;
        }
    }
    else    // Msg is 4-byte aligned
    {
        for( i = 0; i < 16; i++ )
        {
            W[i] = GETUINT64( Msg );
            Msg += 8;
        }
    }

    // Extend the sixteen 64-bit words into sixty-four 64-bit words:
    for( i = 16; i < 80; i++ )
    {
        s0 = ROR64( W[i-15], 1 ) ^ ROR64( W[i-15], 8 ) ^ ( W[i-15] >> 7 );
        s1 = ROR64( W[i-2], 19 ) ^ ROR64( W[i-2], 61 ) ^ ( W[i-2] >> 6 );
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    // Main loop
    for( i = 0; i < 80; i++ )
    {
        s0 = ROR64( a, 28 ) ^ ROR64( a, 34 ) ^ ROR64( a, 39 );
        maj = ( (a | b) & c ) | (a & b);
        t2 = s0 + maj;
        s1 = ROR64( e, 14 ) ^ ROR64( e, 18 ) ^ ROR64( e, 41 );
        ch = g ^ ( e & (f ^ g) );
        t1 = h + s1 + ch + K_512[i] + W[i];
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    State[0] += a;
    State[1] += b;
    State[2] += c;
    State[3] += d;
    State[4] += e;
    State[5] += f;
    State[6] += g;
    State[7] += h;
}

/*-----------------------------------------------------------------------------

    Initialization of SHA-512 operation.

    Parameters:
        pOp     -   operation context

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA512_Init( SW_SHA2_CONTEXT* pOp )
{
    uint32_t    status = TEE_SUCCESS;


    // Make sure that context contains all zeroes
    //
    memset( pOp, 0, sizeof(*pOp) );

    pOp->State[0]   = 0x6a09e667f3bcc908;
    pOp->State[1]   = 0xbb67ae8584caa73b;
    pOp->State[2]   = 0x3c6ef372fe94f82b;
    pOp->State[3]   = 0xa54ff53a5f1d36f1;
    pOp->State[4]   = 0x510e527fade682d1;
    pOp->State[5]   = 0x9b05688c2b3e6c1f;
    pOp->State[6]   = 0x1f83d9abfb41bd6b;
    pOp->State[7]   = 0x5be0cd19137e2179;

    return status;
}

/*-----------------------------------------------------------------------------

    SHA-512 hash operation.

    Parameters:
        pOp         -   operation context
        pData       -   data to be hashed
        DataLen     -   data length

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA512_Process( SW_SHA2_CONTEXT*    pOp,
                            const BYTE*         pMsg,
                            DWORD               MsgLen )
{
    uint32_t    status = TEE_SUCCESS;
    DWORD       Mlen;
    DWORD       BytesToCopy;


    Mlen = pOp->Mlen;

    pOp->MsgLen += MsgLen;        // summarize the total number of bytes processed.

    while( MsgLen > 0 )
    {
        // If remaining message length is less than 128 bytes or internal buffer
        // is not empty, then copy message to the internal buffer. Then, if the
        // buffer is full, compress it.
        //
        if( ( MsgLen < 128 ) || ( Mlen != 0 ) )
        {
            if( Mlen + MsgLen >= 128 )
                BytesToCopy = 128 - Mlen;
            else
                BytesToCopy = MsgLen;

            memcpy( &pOp->Msg[Mlen], pMsg, BytesToCopy );

            MsgLen -= BytesToCopy;
            Mlen += BytesToCopy;
            pMsg += BytesToCopy;

            if( Mlen == 128 )
            {
                SHA512_Compress( pOp->State, pOp->Msg );

                Mlen = 0;
            }
        }
        else
        {
            // Internal buffer is empty and remaining msg length is bigger then
            // or equal to 128 bytes. Then just compress 128 bytes of the message.
            //
            SHA512_Compress( pOp->State, pMsg );

            MsgLen -= 128;
            pMsg += 128;
        }
    }

    pOp->Mlen = Mlen;

    return status;
}

/*-----------------------------------------------------------------------------

    Finalize SHA-512 hash operation and send hash value to the caller function.

    Parameters:
        pOp         -   operation context
        pHash       -   ptr to receive hash value
        HashLen     -   buffer length

    Return value:
        TEE_SUCCESS, or errorcode

    Notes:    if HashLen is smaller than hash length of the selected SHA-512 hash,
            function will return error code TEE_ERROR_SHORT_BUFFER.
*/
uint32_t SW_SHA512_Final(   SW_SHA2_CONTEXT*    pOp,
                            BYTE*               pHash,
                            DWORD               HashLen )
{
    uint32_t    status = TEE_SUCCESS;
    DWORD       Mlen;
    BYTE*       pM;


    if( HashLen < SHA512_HASH_SIZE )
        return TEE_ERROR_SHORT_BUFFER;

    Mlen = pOp->Mlen;
    pM = &pOp->Msg[0];

    pOp->Msg[Mlen++] = 0x80;    // append bit '1' to the message

    // We will have to add the length of the message before padding
    // ( 8 bytes of pOp->MsgLen ) to the end of the message, and keep padded
    // message length multiple of 128. Therefore, if current internal buffer
    // doesn't have space for pOp->MsgLen, we have to padd it with zeroes,
    // compress and add another 128 bytes ( 120 zeroes + pOp->MsgLen )
    //
    if( Mlen > 112 )
    {
        while( Mlen < 128 )
            pM[Mlen++] = 0;

        SHA512_Compress( pOp->State, pOp->Msg );

        Mlen = 0;
    }

    //
    // Pad the rest of the buffer with zeroes, add pOp->MsgLen ( in bits ) and compress.
    //

    while( Mlen < 120 )
        pM[Mlen++] = 0;

    pOp->MsgLen = pOp->MsgLen << 3;        // length in bits

    STOREUINT64( &pM[Mlen], pOp->MsgLen );

    SHA512_Compress( pOp->State, pOp->Msg );

    // Copy SHA-512 state to the output
    //
    STOREUINT64( &pHash[0],     pOp->State[0] )
    STOREUINT64( &pHash[8],     pOp->State[1] )
    STOREUINT64( &pHash[16],    pOp->State[2] )
    STOREUINT64( &pHash[24],    pOp->State[3] )
    STOREUINT64( &pHash[32],    pOp->State[4] )
    STOREUINT64( &pHash[40],    pOp->State[5] )
    STOREUINT64( &pHash[48],    pOp->State[6] )
    STOREUINT64( &pHash[56],    pOp->State[7] )

    return status;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//
//        SHA-384 implementation.
//
// Same as SHA-512, just different init values and shorter hash value
//

/*-----------------------------------------------------------------------------

    Initialization of SHA-384 operation.

    Parameters:
        pOp     -   operation context

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA384_Init( SW_SHA2_CONTEXT* pOp )
{
    uint32_t    status = TEE_SUCCESS;


    // Make sure that context contains all zeroes
    //
    memset( pOp, 0, sizeof(*pOp) );

    pOp->State[0]   = 0xcbbb9d5dc1059ed8;
    pOp->State[1]   = 0x629a292a367cd507;
    pOp->State[2]   = 0x9159015a3070dd17;
    pOp->State[3]   = 0x152fecd8f70e5939;
    pOp->State[4]   = 0x67332667ffc00b31;
    pOp->State[5]   = 0x8eb44a8768581511;
    pOp->State[6]   = 0xdb0c2e0d64f98fa7;
    pOp->State[7]   = 0x47b5481dbefa4fa4;

    return status;
}


/*-----------------------------------------------------------------------------

    SHA-384 hash operation.

    Parameters:
        pOp         -   operation context
        pData       -   data to be hashed
        DataLen     -   data length

    Return value:
        TEE_SUCCESS or error code
*/
uint32_t SW_SHA384_Process( SW_SHA2_CONTEXT*    pOp,
                            const uint8_t*      pMsg,
                            uint32_t            MsgLen )
{
    return SW_SHA512_Process( pOp, pMsg, MsgLen );
}


/*-----------------------------------------------------------------------------

    Finalize SHA-384 hash operation and send hash value to the caller function.

    Parameters:
        pOp         -   operation context
        pHash       -   ptr to receive hash value
        HashLen     -   buffer length

    Return value:
        TEE_SUCCESS, or errorcode

    Notes:    if HashLen is smaller than hash length of the selected SHA-512 hash,
            function will return error code TEE_ERROR_SHORT_BUFFER.
*/
uint32_t SW_SHA384_Final(   SW_SHA2_CONTEXT*    pOp,
                            uint8_t*            pHash,
                            uint32_t            HashLen )
{
    uint32_t    status = TEE_SUCCESS;
    DWORD       Mlen;
    BYTE*       pM;


    if( HashLen < SHA384_HASH_SIZE )
        return SEV_STATUS_INVALID_LENGTH;

    Mlen = pOp->Mlen;
    pM = &pOp->Msg[0];

    pOp->Msg[Mlen++] = 0x80;    // append bit '1' to the message

    // We will have to add the length of the message before padding
    // ( 8 bytes of pOp->MsgLen ) to the end of the message, and keep padded
    // message length multiple of 128. Therefore, if current internal buffer
    // doesn't have space for pOp->MsgLen, we have to padd it with zeroes,
    // compress and add another 128 bytes ( 120 zeroes + pOp->MsgLen )
    //
    if( Mlen > 112 )
    {
        while( Mlen < 128 )
            pM[Mlen++] = 0;

        SHA512_Compress( pOp->State, pOp->Msg );

        Mlen = 0;
    }

    //
    // Pad the rest of the buffer with zeroes, add pOp->MsgLen ( in bits ) and compress.
    //

    while( Mlen < 120 )
        pM[Mlen++] = 0;

    pOp->MsgLen = pOp->MsgLen << 3;        // length in bits

    STOREUINT64( &pM[Mlen], pOp->MsgLen );

    SHA512_Compress( pOp->State, pOp->Msg );

    // Copy SHA-384 state to the output
    //
    STOREUINT64( &pHash[0],     pOp->State[0] )
    STOREUINT64( &pHash[8],     pOp->State[1] )
    STOREUINT64( &pHash[16],    pOp->State[2] )
    STOREUINT64( &pHash[24],    pOp->State[3] )
    STOREUINT64( &pHash[32],    pOp->State[4] )
    STOREUINT64( &pHash[40],    pOp->State[5] )

    return status;
}

#endif
