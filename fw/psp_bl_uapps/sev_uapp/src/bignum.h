// Copyright(C) 2012-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef BIGNUM_H
#define BIGNUM_H

#include <stddef.h>
#include <stdint.h>

#include "common_utilities.h"

/**
 * Error codes
 */
#define KC_OK                           0x00000000  // Result OK
#define KC_SUCCESS                      0x00000000  // Result SUCCESS
#define KCERR_GENERIC_ERROR             0x00008001  // Generic Error
#define KCERR_BUFFER_OVERFLOW           0x00008002  // Not enough space for output
#define KCERR_INVALID_PARAMETER         0x00008003
#define KCERR_INCORRECT_DATA_LEN        0x00008004
#define KCERR_NULL_PTR                  0x00008005
#define KCERR_FUNCTION_NOT_SUPPORTED    0x00008006

#define KCERR_INVALID_SESSION           0x00008007
#define KCERR_INVALID_OPERATION         0x00008008
#define KCERR_INVALID_ROUNDS            0x00008009  // Invalid number of rounds
#define KCERR_INVALID_OPERATION_TYPE    0x0000800A
#define KCERR_FAIL_TESTVECTOR           0x0000800B  // Algorithm failed test vectors
#define KCERR_DATA_CORRUPTED            0x0000800C  // Corrupted data buffer

#define KCERR_BN_TOO_SMALL              0x0000800D  // BigNumber too small for result value
#define KCERR_BAD_BIGNUMBER             0x0000800E  // Illegal BigNumber passed (probably NULL)
#define KCERR_SCRATCH_TOO_SMALL         0x0000800F  // Scratch area not big enough
#define KCERR_PK_INVALID_SIZE           0x00008010  // Invalid size input for PK parameters
#define KCERR_RSA_DECRYPTION_ERROR      0x00008011  // RSA decryption error
#define KCERR_PK_INVALID_TYPE           0x00008012  // Invalid type of PK key

#define KCERR_NOT_IMPLEMENTED           0x00008013  // Internal - Code not implemented
#define KCERR_INTERNAL_ERROR            0x00008014  // Internal error
#define KCERR_SIGNATURE_INCORRECT       0x00008015  // incorrect signature
#define KCERR_BN_NO_INVERSE             0x00008016  // no inverse
#define KCERR_BN_INVALID_SIZE           0x00008017  // invalid size of the operand
#define KCERR_INCORRECT_UNIT_SIZE       0x00008018  // incorrect XTS unit size
#define KCERR_DATA_LENGTH               0x00008019  // incorrect data length

#define BN_BITS         28

/**
 * The data size is set for 1024 bit big numbers where
 * the result of multiplication is 2048 bit.
 * 64 bytes + 16 bytes, where the 16 bytes is used for optimization.
 * The implementation is size-optimized for debug-unlock.
 */
#define MAX_BN_ELEMENTS    80

// Big number structure
typedef struct _KC_BIGNUM
{
    uint32_t   Used;                   // how many elements used
    uint32_t   Sign;                   // 1 means negative value
    uint32_t   Obfuscated;             // whether bignum is obfuscated or not
    uint32_t   Data[MAX_BN_ELEMENTS];  // 28-bit elements of big number
} KC_BIGNUM;

typedef struct _KC_BN_SCRATCH
{
    KC_BIGNUM       Barrett_u;          // u value for Barrett modular reduction
    KC_BIGNUM       BarrettTemp[3];     // temporary numbers for BNBarrettReduce function
    KC_BIGNUM       Temp[6];            // temporary numbers for BNDiv() function
} KC_BN_SCRATCH;

// Set bignum to integer value (integer must not be bigger than 0x0FFFFFFF).
#define BN_SET_INT( Bn, Integer )   \
{                                   \
    Bn.Used         = 1;            \
    Bn.Sign         = 0;            \
    Bn.Obfuscated   = 0;            \
    Bn.Data[0]      = Integer;      \
                                    \
}

enum
{
    BN_BIGGER  = 1,
    BN_SMALLER = 2,
    BN_EQUAL   = 3
};

// Functions provided

uint32_t BNLoad( KC_BIGNUM *pBn, const uint8_t *pData, uint32_t DataLen );
uint32_t BNStore( KC_BIGNUM *pBn, uint8_t *pData, uint32_t DataLen );

void BNCopy( KC_BIGNUM *pDest, KC_BIGNUM *pSrc );
void BNShiftDigR( KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift );
uint32_t BNShiftDigL( KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift );
uint32_t BNShiftBitsL( KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift );
void BNShiftBitsR( KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift );
uint32_t BNCompare( KC_BIGNUM *x, KC_BIGNUM *y );
uint32_t BNSecureCompare( KC_BIGNUM *x, KC_BIGNUM *y );
uint32_t BNMultiply( KC_BIGNUM *x, KC_BIGNUM *y, KC_BIGNUM *z, uint32_t Digits );
uint32_t BNMultiplyHighDigs( KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y, uint32_t Digits );
uint32_t BNAdd( KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y );
uint32_t BNSubtract( KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y );
void BNMod_2Pwr( KC_BIGNUM *z, KC_BIGNUM *x, uint32_t Exp );
uint32_t BNBitCount( KC_BIGNUM *pBn );
uint32_t BNDiv( KC_BN_SCRATCH *pScratch,  KC_BIGNUM *z, KC_BIGNUM *a, KC_BIGNUM *b, KC_BIGNUM *r );
uint32_t BNSet2Pwr( KC_BIGNUM *pBn, uint32_t Pwr );
uint32_t BNBarrettSetup( KC_BN_SCRATCH *pScratch, KC_BIGNUM *m );
uint32_t BNBarrettReduce( KC_BN_SCRATCH *pScratch, KC_BIGNUM *r, KC_BIGNUM *x, KC_BIGNUM *m );

#endif /* BIGNUM_H */
