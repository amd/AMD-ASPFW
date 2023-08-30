//-----------------------------------------------------------------------------
// Copyright(C) 2012-2020 Advanced Micro Devices, Inc. All rights reserved.
//
// ISC License
//
// Copyright (c) 2013-2020
// Frank Denis <j at pureftpd dot org>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "bignum.h"

#define BN_MASK            (( 1 << BN_BITS ) - 1 )

#define BNTRIM(pBn)                                             \
{                                                               \
    while ((pBn->Used != 0) && (pBn->Data[pBn->Used-1] == 0))   \
        pBn->Used--;                                            \
}

#define BN_ZERO(pBn)        \
{                           \
    pBn->Used = 0;          \
    pBn->Sign = 0;          \
                            \
}

#define BN_EVEN(pBn)      ((pBn->Data[0] & 0x01) == 0)

/**
 *  Load octet string into big number structure.
 *
 *  Parameters:
 *      pBn     - bignumber to be loaded
 *      pData   - input buffer ( octet string )
 *      DataLen - input buffer length
 *
 *  Assume input is little-endian.
 *  Assume BN_BITS is 28.
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNLoad(KC_BIGNUM *pBn, const uint8_t *pData, uint32_t DataLen)
{
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t Data = 0;
    uint32_t Temp = 0;
    uint32_t BnLen = (DataLen / 7) * 2;    // consider 28 bits per element

    /* Input data length must be multiple of 4 */
    if (DataLen & 0x03)
        return KCERR_DATA_LENGTH;

    /* Check if data is not bigger than max BigNum size */
    if ((BnLen + 2) > arraysize(pBn->Data))
        return KCERR_DATA_LENGTH;

    BN_ZERO(pBn);

    memset(&pBn->Data, 0, sizeof(pBn->Data));

    while (1)
    {
        Data = *(uint32_t *)pData;
        pBn->Data[i] = (( Data << (j * 4)) + Temp ) & BN_MASK;
        Temp = Data >> (BN_BITS - j * 4);
        i++;

        /* Every 7 uint32_ts will expand to 8 uint32_ts */
        if (++j == 8)
        {
            j = 0;
            Temp = 0;
        }
        else
        {
            pData += 4;
            DataLen -= 4;

            if (DataLen == 0)
            {
                if (Temp != 0)
                {
                    pBn->Data[i] = Temp & BN_MASK;
                    i++;
                }

                pBn->Used = i;
                break;
            }
        }
    }

    BNTRIM(pBn);

    return KC_OK;
}

/**
 *  Store big number to octet string. Opposite of BNLoad().
 *
 *  Parameters:
 *      pBn     - bignumber to be converted to octet string
 *      pData   - output buffer
 *      DataLen - input buffer length
 *
 *  Assume little-endian.
 *  Assume BN_BITS is 28.
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNStore(KC_BIGNUM *pBn, uint8_t *pData, uint32_t DataLen)
{
    uint32_t status = KC_OK;
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t Temp = 0;

    // Few validations...
    if (!pBn || !pData)
        return KCERR_NULL_PTR;

    // Output data length must be multiple of 4.
    if (DataLen & 0x03)
        return KCERR_DATA_LENGTH;

    if (pBn->Used > arraysize(pBn->Data))
        return KCERR_BUFFER_OVERFLOW;

    BNTRIM(pBn);

    for (i = 0; i < pBn->Used - 1; i++)
    {
        if (DataLen == 0)
        {
            status = KCERR_BUFFER_OVERFLOW + 0xB00;
            break;
        }

        if (j == 7)
        {
            Temp = pBn->Data[i+1];
            *(uint32_t *)pData = (pBn->Data[i] >> (4 * 7)) + Temp;

            j = 0;
        }
        else
        {
            Temp = pBn->Data[i+1] & (( 1 << ( 4 * (j + 1)) ) - 1 );
            *(uint32_t *)pData = (pBn->Data[i] >> (4 * j)) + (Temp << (BN_BITS - 4 * j));

            j++;
            pData += 4;
            DataLen -= 4;
        }
    }

    return status;
}

/**
 *  Copy one bignumber to another.
 *
 *  Parameters:
 *      pDest - destination bignumber
 *      pSrc  - source bignumber
 */
void BNCopy(KC_BIGNUM *pDest, KC_BIGNUM *pSrc)
{
    if (pDest != pSrc)
        memcpy(pDest, pSrc, sizeof(*pDest));
}

/**
 *  Right shift bignumber for the given number of digits.
 *
 *  Parameters:
 *      pDest  - destination bignumber
 *      pSrc   - source bignumber; can be the same as pDest
 *      nShift - number of digits to shift by
 */
void BNShiftDigR(KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift)
{
    uint32_t i = 0;
    uint32_t *pSrcData  = NULL;
    uint32_t *pDestData = NULL;

    /* For zero shift, just copy data or do nothing */
    if (Shift == 0)
    {
        if (pSrc != pDest)
            BNCopy(pDest, pSrc);

        return;
    }

    if (pSrc->Used <= Shift)
    {
        BN_ZERO(pDest);
    }
    else
    {
        pSrcData = &pSrc->Data[0];
        pDestData = &pDest->Data[0];

        for (i = Shift; i < pSrc->Used; i++)
        {
            pDestData[i - Shift] = pSrcData[i];
        }

        pDest->Used = pSrc->Used - Shift;
        pDest->Sign = pSrc->Sign;
    }
}

/**
 *  Left shift bignumber for the given number of digits.
 *
 *  Parameters:
 *      pDest  - destination bignumber
 *      pSrc   - source bignumber; can be the same as pDest
 *      nShift - number of digits to shift by
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNShiftDigL(KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift)
{
    uint32_t i = 0;
    uint32_t *pSrcData  = NULL;
    uint32_t *pDestData = NULL;

    /* For zero shift or empty data, just copy data or do nothing */
    if ((Shift == 0) || (pSrc->Used == 0))
    {
        if (pSrc != pDest)
            BNCopy( pDest, pSrc );

        return KC_OK;
    }

    /* Check the size of the result */
    if (pSrc->Used + Shift > arraysize(pDest->Data))
        return KCERR_BUFFER_OVERFLOW;

    pDest->Used = pSrc->Used + Shift;
    pDest->Sign = pSrc->Sign;
    pSrcData = &pSrc->Data[0];
    pDestData = &pDest->Data[0];

    /* Shift digits left */
    for (i = pDest->Used - 1; i >= Shift; i--)
    {
        pDestData[i] = pSrcData[i - Shift];
    }

    /* Clear the lower digits */
    for (i = 0; i < Shift; i++)
    {
        pDestData[i] = 0;
    }

    return KC_OK;
}

/**
 *  Shift bignumber left by given number of bits.
 *
 *  Parameters:
 *      pDest - destination bignumber
 *      pSrc  - source bignumber; can be the same as pDest
 *      Shift - number of bits to shift by
 *
 *  Note:   For performance reason we don't check for overflow here. Therefore,
 *          caller is responsible to choose Shift such that it doesn't cause
 *          overflow.
 */
uint32_t BNShiftBitsL(KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift)
{
    uint32_t status = KC_OK;
    uint32_t i = 0;
    uint32_t *pDestData = NULL;
    uint32_t *pSrcData  = NULL;
    uint32_t Temp  = 0;
    uint32_t Sr    = 0;
    uint32_t Carry = 0;

    /* For zero shift or empty data, just copy data or do nothing */
    if ((Shift == 0) || (pSrc->Used == 0))
    {
        if (pSrc != pDest)
            BNCopy(pDest, pSrc);

        return KC_OK;
    }

    do
    {
        /* Shift by the number of digits */
        if (Shift >= BN_BITS)
        {
            status = BNShiftDigL(pDest, pSrc, Shift / BN_BITS);
            if (KC_OK != status)
                break;
            pSrc = pDest;
        }

        Shift = Shift % BN_BITS;

        if ((Shift != 0) && (pSrc->Used > 0))
        {
            /* Shift by the number of bits */
            pSrcData = &pSrc->Data[0];
            pDestData = &pDest->Data[0];
            Carry = 0;
            Sr = BN_BITS - Shift;

            for (i = 0; i < pSrc->Used; i++)
            {
                Temp = pSrcData[i];
                pDestData[i] = (( Temp << Shift ) & BN_MASK ) + Carry;
                Carry = Temp >> Sr;
            }

            pDest->Used = pSrc->Used;
            pDest->Sign = pSrc->Sign;

            /* If carry is not empty, increment the number of digits */
            if (Carry != 0)
            {
                pDestData[i] = Carry;
                pDest->Used++;
            }
        }

    } while (0);

    return status;
}

/**
 *  Shift bignumber right by given number of bits.
 *
 *  Parameters:
 *      pDest - destination bignumber
 *      pSrc  - source bignumber; can be the same as pDest
 *      Shift - number of bits to shift by
 */
void BNShiftBitsR(KC_BIGNUM *pDest, KC_BIGNUM *pSrc, uint32_t Shift)
{
    int i = 0;
    uint32_t *pSrcData  = NULL;
    uint32_t *pDestData = NULL;
    uint32_t Temp  = 0;
    uint32_t Sl    = 0;
    uint32_t Mask  = 0;
    uint32_t Carry = 0;

    /* For zero shift or empty data, just copy data or do nothing */
    if ((Shift == 0) || (pSrc->Used == 0))
    {
        if (pSrc != pDest)
            BNCopy(pDest, pSrc);
        return;
    }

    /* Shift by the number of digits */
    if (Shift >= BN_BITS)
    {
        BNShiftDigR(pDest, pSrc, Shift / BN_BITS);
        pSrc = pDest;
    }

    Shift = Shift % BN_BITS;

    if ((Shift != 0) && (pSrc->Used > 0))
    {
        pSrcData = &pSrc->Data[0];
        pDestData = &pDest->Data[0];
        Carry = 0;
        Sl = BN_BITS - Shift;
        Mask = ( 0x00000001 << Shift ) - 1;

        for (i = pSrc->Used - 1; i >= 0; i--)
        {
            Temp = pSrcData[i];
            pDestData[i] = ( Temp >> Shift ) + Carry;
            Carry = ( Temp & Mask ) << Sl;
        }

        pDest->Used = pSrc->Used;
        pDest->Sign = pSrc->Sign;

        /* If highest digit is empty, reduce the number of digits */
        if (pDest->Data[pSrc->Used-1] == 0)
            pDest->Used--;
    }
}

/**
 *  Set bignumber to 2**Pwr.
 *
 *  Parameters:
 *      pBn - bignumber
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNSet2Pwr(KC_BIGNUM *pBn, uint32_t Pwr)
{
    uint32_t i = 0;
    uint32_t *pData = NULL;
    uint32_t Temp = 0;

    /* Parameter validation */
    if ((Pwr / BN_BITS) >= arraysize(pBn->Data))
        return KCERR_BUFFER_OVERFLOW;

    pData = &pBn->Data[0];
    Temp = Pwr % BN_BITS;

    /* Set to 0 */
    for (i = 0; i < Pwr / BN_BITS; i++)
    {
        pData[i] = 0;
    }

    /* Highest digit */
    pData[i] = 0x00000001 << Temp;
    pBn->Used = i + 1;
    pBn->Sign = 0;        /* Positive number */

    return KC_OK;
}

/**
 *  Subtract absolute values of two bignumbers z = x - y.
 *
 *  Parameters:
 *      z -   x - y; z can be the same as x
 *      x -   larger number
 *      y -   smaller number
 *
 *  Return value:
 *      KC_OK or error code
 */
static uint32_t BNSubtractAbs(KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y)
{
    uint32_t  i = 0;
    uint32_t *pX = NULL;
    uint32_t *pY = NULL;
    uint32_t *pZ = NULL;
    uint32_t  xUsed   = 0;
    uint32_t  yUsed   = 0;
    uint32_t  Temp    = 0;
    uint32_t  Borrow  = 0;   /* Borrow from previous digit */
    uint32_t  Compare = 0;

    Compare = BNCompare(x, y);

    if (Compare == BN_SMALLER)     /* x < y */
    {
        pX = &y->Data[0];
        xUsed = y->Used;
        pY = &x->Data[0];
        yUsed = x->Used;
        z->Sign = ! x->Sign;        /* Change the sign */
    }
    else if (Compare == BN_BIGGER) /* x > y */
    {
        pX = &x->Data[0];
        xUsed = x->Used;
        pY = &y->Data[0];
        yUsed = y->Used;
        z->Sign = x->Sign;
    }
    else                            /* x == y */
    {
        BN_ZERO(z);
        return KC_OK;
    }

    pZ = &z->Data[0];

    /* Perform the subtraction across the common portion */
    Borrow = 0;

    for (i = 0; i < yUsed; i++)
    {
        Temp = pY[i] + Borrow;

        if (Temp > pX[i])
            Borrow = 1;
        else
            Borrow = 0;

        pZ[i] = pX[i] + ( Borrow << BN_BITS ) - Temp;
    }

    /* Then extend across the larger number */
    for (i = yUsed; i < xUsed; i++)
    {
        Temp = Borrow;

        if (Borrow > pX[i])
            Borrow = 1;
        else
            Borrow = 0;

        z->Data[i] = pX[i] + ( Borrow << BN_BITS ) - Temp;
    }

    z->Used = xUsed;
    BNTRIM(z);

    return KC_OK;
}

/**
 *  Add absolute values of two bignumbers z = x + y. Result has the sign of x.
 *
 *  Parameters:
 *      z -   x + y; z can be the same as x or y
 *      x -   bignumber 1
 *      y -   bignumber 2
 *
 *  Return value:
 *      KC_OK or error code
 */
static uint32_t BNAddAbs(KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y)
{
    KC_BIGNUM *pMax = NULL; /* Larger input number */
    KC_BIGNUM *pMin = NULL; /* Smaller input number */
    uint32_t  Carry = 0;
    uint32_t  i   = 0;
    uint32_t *pX  = NULL;
    uint32_t *pY  = NULL;
    uint32_t *pZ  = NULL;
    uint32_t  Sum = 0;      /* Sum at this byte location */

    /* Sort the inputs into the larger and the smaller */
    if (x->Used > y->Used)
    {
        pMax = x;
        pMin = y;
    }
    else
    {
        pMax = y;
        pMin = x;
    }

    /* Make sure there's space for the output */
    if (arraysize(z->Data) < (pMax->Used + 1))
        return KCERR_BUFFER_OVERFLOW;

    pX = &x->Data[0];
    pY = &y->Data[0];
    pZ = &z->Data[0];

    /* Perform the addition across the common portion */
    Carry = 0;

    for (i = 0; i < pMin->Used; i++)
    {
        Sum = pX[i] + pY[i] + Carry;
        pZ[i] = Sum & BN_MASK;
        Carry = Sum >> BN_BITS;
    }

    pX = &pMax->Data[0];

    /* Then extend carry across the larger number */
    for (i = pMin->Used; i < pMax->Used; i++)
    {
        Sum = pX[i] + Carry;
        pZ[i] = Sum & BN_MASK;
        Carry = Sum >> BN_BITS;
    }

    /* Handle the final carry if necessary */
    pZ[i] = Carry;
    z->Used = pMax->Used + 1;
    z->Sign = x->Sign;

    BNTRIM( z );

    return KC_OK;
}

/**
 *  Subtract two bignumbers z = x - y.
 *
 *  Parameters:
 *      z -   x - y; z can be the same as x
 *      x -   larger number
 *      y -   smaller number
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNSubtract(KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y)
{
    /* If signs different, it turns to addition */
    if (x->Sign != y->Sign)
        return BNAddAbs(z, x, y);   /* Result will have the sign of x */
    else                /* Same signs, subtract */
        return BNSubtractAbs(z, x, y);
}

/**
 *  Add two bignumbers z = x + y.
 *
 *  Parameters:
 *      z -   x + y; z can be the same as x or y
 *      x -   bignumber 1
 *      y -   bignumber 2
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNAdd(KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y)
{
    uint32_t status = 0;

    /* If signs are different, subtract */
    if (x->Sign != y->Sign)
    {
        if (y->Sign == 1)                       /* y is negative */
            status = BNSubtractAbs(z, x, y);    /* z = x - y */
        else                                    /* x is negative */
            status = BNSubtractAbs(z, y, x);    /* z = y - x */
    }
    else        /* Both numbers have the same sign */
    {
        status = BNAddAbs(z, x, y);
    }

    return status;
}

/**
 *  Compares the absolute value of x against y.
 *  Fast/Non-constant time
 *
 *  Parameters:
 *      x - first number to compare
 *      y - number to comare against
 *
 *  Return value:
 *   x > y  - BN_BIGGER
 *   x < y  - BN_SMALLER
 *   x == y - BN_EQUAL
 */
uint32_t BNCompare(KC_BIGNUM *x, KC_BIGNUM *y)
{
    int i = 0;
    uint32_t *pX = NULL;
    uint32_t *pY = NULL;

    /* Compare magnitudes */
    if (x->Used > y->Used)
        return BN_BIGGER;

    if (x->Used < y->Used)
        return BN_SMALLER;

    /* ...same magnitudes */

    if (y->Used == 0)
        return BN_BIGGER;

    pX = &x->Data[0];
    pY = &y->Data[0];

    /* Compare the numbers */
    for (i = x->Used - 1; i >= 0; i--)
    {
        if (pX[i] > pY[i])
            return BN_BIGGER;

        if (pX[i] < pY[i])
            return BN_SMALLER;
    }

    return BN_EQUAL;    /* Equal unless otherwise */
}

/**
 *  Compares the absolute value of x against y.
 *  Slow/Constant time
 *  >> 31 because each element is uint32_t (technically each element is BN_BITS)
 *
 *  Borrowed under ISC license from
 *      https://github.com/jedisct1/libsodium
 *      https://github.com/jedisct1/libsodium/blob/master/LICENSE
 *
 *  Parameters:
 *      x - first number to compare
 *      y - number to comare against
 *
 *  Return value:
 *   x > y  - BN_BIGGER
 *   x < y  - BN_SMALLER
 *   x == y - BN_EQUAL
 */
uint32_t BNSecureCompare(KC_BIGNUM *x, KC_BIGNUM *y)
{
    size_t i = MAX_BN_ELEMENTS;
    uint32_t *pX = NULL;
    uint32_t *pY = NULL;
    uint32_t gt = 0;
    uint32_t eq = 1;

    pX = &x->Data[0];
    pY = &y->Data[0];

    /* Compare the numbers */
    while (i != 0)
    {
        i--;
        gt |= ((pY[i] - pX[i]) >> 31) & eq;
        eq &= ((pY[i] ^ pX[i]) - 1) >> 31;
    }

    return (2 + (eq - gt));
}

/**
 *  Multiplication of two bignumbers z = x * y.
 *
 *  Parameters:
 *      z      -  z = x * y; z CANNOT be the same as x or y
 *      x      -  multiplier
 *      y      -  multiplicand
 *      Digits -  how many digits of result are required; if 0, all digits
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNMultiply(KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y, uint32_t Digits)
{
    unsigned long long Carry = 0;   /* Carry to the next digit */
    uint32_t  Limit = 0;            /* Upper limit on array bounds */
    uint32_t  i     = 0;
    uint32_t *pZ    = NULL;
    uint32_t  xMax  = 0;
    uint32_t  yUsed = 0;
    uint32_t *pX    = NULL;
    uint32_t *pY    = NULL;
    uint32_t *pX1   = NULL;
    uint32_t *pY1   = NULL;
    uint32_t *pXlim = NULL;

    /* Few validations */
    if ((z == x) || (z == y))
        return KCERR_INVALID_PARAMETER;

    if ((x->Used == 0) || (y->Used == 0))
    {
        BN_ZERO(z);
        return KC_OK;
    }

    if (Digits == 0)
        Limit = x->Used + y->Used;
    else
        Limit = Digits;

    if (arraysize(z->Data) < Limit)
        return KCERR_BN_TOO_SMALL;

    if (x->Sign != y->Sign)
        z->Sign = 1;
    else
        z->Sign = 0;

    z->Used = Limit;
    pZ = &z->Data[0];
    xMax = x->Used - 1;
    yUsed = y->Used - 1;

    Carry = 0;
    pX = &x->Data[0];
    pY = &y->Data[0];
    pXlim = pX + 1;

    for (i = 0; i < yUsed; i++)
    {
        pX1 = pX;
        pY1 = pY;

        /* Inner loop */
        while (pX1 < pXlim)
        {
            Carry += (unsigned long long)((unsigned long long)(*pX1++) * (unsigned long long)(*pY1--));
        }

        pY++;

        if (xMax > i)
            pXlim++;

        pZ[i] = ((uint32_t)Carry) & BN_MASK;    /* Store the term */
        Carry = Carry >> BN_BITS;               /* Make next carry */
    }

    for (i = yUsed; i < Limit; i++)
    {
        pX1 = pX;
        pY1 = pY;

        /* Inner loop */
        while (pX1 < pXlim)
        {
            Carry += (unsigned long long)((unsigned long long)(*pX1++) * (unsigned long long)(*pY1--));
        }

        pX++;

        if (xMax > i )
            pXlim++;

        pZ[i] = ((uint32_t)Carry) & BN_MASK;    /* Store the term */
        Carry = Carry >> BN_BITS;               /* Make next carry */
    }

    BNTRIM( z );

    return KC_OK;
}

/**
 *  Multiplication of two bignumbers z = x * y.
 *  Digits of the result will be calculated starting from Digits. Below Digits
 *  all will be 0.
 *
 *  Parameters:
 *      z      -   z = x * y; z CANNOT be the same as x or y
 *      x      -   multiplier
 *      y      -   multiplicand
 *      Digits -   how many digits of result are required
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNMultiplyHighDigs(KC_BIGNUM *z, KC_BIGNUM *x, KC_BIGNUM *y, uint32_t Digits)
{
    unsigned long long Carry = 0;   /* Carry to the next digit */
    uint32_t  Limit = 0;            /* Upper limit on array bounds */
    uint32_t  i     = 0;
    uint32_t *pZ    = NULL;
    uint32_t  xUsed = 0;
    uint32_t  yUsed = 0;
    uint32_t *xData = NULL;
    uint32_t *yData = NULL;

    /* Few validations */
    if (( z == x ) || ( z == y ))
        return KCERR_INVALID_PARAMETER;

    if (( x->Used == 0) || ( y->Used == 0))
    {
        BN_ZERO(z);
        return KC_OK;
    }

    Limit = x->Used + y->Used;

    if (arraysize(z->Data) < Limit)
        return KCERR_BN_TOO_SMALL;

    if (Digits != 0)
    {
        for (i = 0; i < Digits; i++)
        {
            z->Data[i] = 0;
        }
    }

    if (x->Sign != y->Sign)
        z->Sign = 1;
    else
        z->Sign = 0;

    z->Used = Limit;
    pZ = &z->Data[0];
    xUsed = x->Used;
    yUsed = y->Used;
    xData = &x->Data[0];
    yData = &y->Data[0];

    Carry = 0;        /* Clear the carry */

    for (i = Digits; i < Limit; i++)
    {
        uint32_t *pX;
        uint32_t *pY;
        uint32_t *pXlim;

        if (yUsed > i + 1)
        {
            pX = xData;
            pY = yData + i;
            pXlim = pX + (( xUsed > i + 1 ) ? ( i + 1 ) : xUsed);
        }
        else
        {
            pX = xData + i - yUsed + 1;
            pY = yData + yUsed - 1;
            pXlim = pX + (( xUsed > i + 1 ) ? yUsed : xUsed + yUsed - i - 1);
        }

        /* Inner loop */
        while (pX < pXlim)
        {
            Carry += (unsigned long long)((unsigned long long)(*pX++) * (unsigned long long)(*pY--));
        }

        /* Store the term */
        pZ[i] = ((uint32_t)Carry) & BN_MASK;

        /* Make next carry */
        Carry = Carry >> BN_BITS;
    }

    BNTRIM(z);

    return KC_OK;
}

/**
 *  Calculate z = x mod 2**Exp. Because modulus is the power of 2, this can
 *  be done without any divisions, by just zeroing upper bits.
 *
 *  Parameters:
 *      z   -   z = x mod 2**Exp; z can be the same as x
 *      x   -   bignumber
 *      Exp -   exponent
 *
 *  Return value:
 *      KC_OK or error code
 */
void BNMod_2Pwr(KC_BIGNUM *z, KC_BIGNUM *x, uint32_t Exp)
{
    /* If exponent is 0, then make result 0 */
    if (Exp == 0)
    {
        BN_ZERO(z);
        return;
    }

    BNCopy(z, x);           /* Copy x to z */

    /* If modulus is larger than x, then return x */
    if (Exp >= x->Used * BN_BITS)
        return;

    /* Clear the digit which is partially in the modulus */
    z->Data[Exp / BN_BITS] &= (( 1 << (Exp % BN_BITS)) - 1 );

    /* Clear the upper part... */
    z->Used = Exp / BN_BITS + 1;

    BNTRIM(z);
}

/**
 *  Calculate number of bits in bignumber.
 *
 *  Parameters:
 *      pBn - bignumber
 *
 *  Return value:
 *      bitcount
 */
uint32_t BNBitCount(KC_BIGNUM *pBn)
{
    uint32_t Count = 0;
    uint32_t Last = 0;

    /* Empty number */
    if (pBn->Used == 0)
        return 0;

    Count = (pBn->Used - 1) * BN_BITS;

    Last = pBn->Data[pBn->Used - 1];

    while (Last > 0)
    {
        Count++;
        Last = Last >> 1;
    }

    return Count;
}

/**
 *  Division of two bignumbers: z = ( a - r ) / b.
 *
 *  Algorithm 14.20 from HAC: http://www.daimi.au.dk/~cmosses/crypt/index.html#Anchor-Th-4441
 *
 *  Parameters:
 *      pScratch - scratch area for temporary variables
 *      z        - result ( can be NULL, if caller only needs remainder );
 *                    can be same as a or b
 *      a        - dividend
 *      b        - divisor
 *      r        - remainder ( can be NULL, if caller doesn't need remainder );
 *                    can be same as a or b
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNDiv(KC_BN_SCRATCH *pScratch, KC_BIGNUM *z, KC_BIGNUM *a, KC_BIGNUM *b, KC_BIGNUM *r)
{
    uint32_t  status = KC_OK;
    uint32_t  i  = 0;
    uint32_t *pQ = NULL;
    uint32_t *pX = NULL;
    uint32_t *pY = NULL;
    uint32_t  Compare = 0;
    uint32_t  Shift   = 0;
    uint32_t  n  = 0;
    uint32_t  t  = 0;
    KC_BIGNUM *x = NULL;
    KC_BIGNUM *y = NULL;
    KC_BIGNUM *q = NULL;
    KC_BIGNUM *BnTmp  = NULL;
    KC_BIGNUM *BnTmp1 = NULL;
    KC_BIGNUM *BnTmp2 = NULL;

    /* Few validations */
    if (b->Used == 0)
        return KCERR_INVALID_PARAMETER;        /* Divide by zero */

    if (a->Used == 0)
    {
        if (r != NULL)
            BN_ZERO(r);
        if (z != NULL)
            BN_ZERO(z);
        return KC_OK;
    }

    Compare = BNCompare(a, b);

    /* If b > a, then z = 0, r = a */
    if (Compare == BN_SMALLER)
    {
        if (r != NULL)
            BNCopy(r, a);
        if (z != NULL)
            BN_ZERO(z);
        return KC_OK;
    }

    /* If a == b, then z = 1, r = 0 */
    if (Compare == BN_EQUAL)
    {
        if (r != NULL)
        {
            BN_ZERO(r);
        }
        if (z != NULL)
        {
            z->Used = 1;
            z->Sign = 0;
            z->Data[0] = 1;
        }
        return KC_OK;
    }

    do
    {
        /* Initialize temporary data in the scratch area */
        x = &pScratch->Temp[0];
        y = &pScratch->Temp[1];
        q = &pScratch->Temp[2];
        BnTmp = &pScratch->Temp[3];
        BnTmp1 = &pScratch->Temp[4];
        BnTmp2 = &pScratch->Temp[5];

        BN_ZERO(q);
        q->Used = a->Used - b->Used;
        pQ = &q->Data[0];
        pX = &x->Data[0];
        pY = &y->Data[0];

        for (i = 0; i < q->Used; i++)
        {
            pQ[i] = 0;
        }

        /* Normalize b ( make sure that highest bit is 1 ) */
        Shift = BNBitCount(b) % BN_BITS;
        if (Shift < BN_BITS - 1)
        {
            Shift = BN_BITS - 1 - Shift;

            /* Shift a LeftShift bits left, compensate for this in b */
            if (KC_OK != (status = BNShiftBitsL( y, b, Shift)))
                break;
            if (KC_OK != (status = BNShiftBitsL( x, a, Shift)))
                break;
        }
        else    /* Last bit of y was 1 */
        {
            BNCopy(x, a);
            BNCopy(y, b);
            Shift = 0;
        }

        n = x->Used - 1;
        t = y->Used - 1;

        /* Prepare temporary number: tmp = y * b**(n-t) */
        if (KC_OK != ( status = BNShiftDigL(BnTmp, y, n-t )))
            break;

        // while ( x >= y*b**(n-t)) do the following: q[n-t] += 1; x -= y*b**(n-t)
        while (BN_SMALLER != BNCompare(x, BnTmp))
        {
            pQ[n-t]++;
            BNSubtract(x, x, BnTmp);
        }

        /* Step 3: For i from n down to (t + 1) do the following:... */
        for (i = n; i >= ( t + 1 ); i--)
        {
            if (i > x->Used )
                continue;

            /*
             * Step 3.1:    if x[i] == y[t], then q[i-t-1] = b-1,
             *                otherwise q[i-t-1] = ( x[i] * b + x[i-1] ) / y[t]
             */
            if (pX[i] == pY[t])
                pQ[i-t-1] = BN_MASK;
            else
            {
                unsigned long long Temp;

                Temp = (unsigned long long)pX[i] << BN_BITS;
                Temp += pX[i-1];
                Temp = Temp / pY[t];

                if (Temp > BN_MASK)
                    Temp = BN_MASK;

                pQ[i-t-1] = (uint32_t)Temp;
            }

            pQ[i-t-1] = ( pQ[i-t-1] + 1 ) & BN_MASK;
            /*
             * Step 3.2:
             *    while q[i-t-1] * ( y[t] * b + y[t-1] ) > x[i] * b**2 + x[i-1] * b + x[i-2]
             *    do: q[i-t-1] -= 1;
             */
            do
            {
                pQ[i-t-1] = ( pQ[i-t-1] - 1 ) & BN_MASK;

                // BnTmp = q[i-t-1] * ( y[t] * b + y[t-1] )
                BN_ZERO(BnTmp2);
                BnTmp2->Used = 1;
                BnTmp2->Data[0] = pQ[i-t-1];
                BN_ZERO(BnTmp1);
                BnTmp1->Used = 2;
                BnTmp1->Data[0] = ( t > 0 ) ? pY[t-1]: 0;
                BnTmp1->Data[1] = pY[t];

                if (KC_OK != (status = BNMultiply( BnTmp, BnTmp1, BnTmp2, 0 )))
                    break;

                // BnTmp1 = x[i] * b**2 + x[i-1] * b + x[i-2]
                BN_ZERO( BnTmp1 );
                BnTmp1->Used = 3;
                BnTmp1->Data[0] = ( i > 1 ) ? pX[i-2] : 0;
                BnTmp1->Data[1] = ( i > 0 ) ? pX[i-1] : 0;
                BnTmp1->Data[2] = pX[i];

                Compare = BNCompare( BnTmp, BnTmp1 );
            } while (Compare == BN_BIGGER);

            if (status != KC_OK)
                break;

            // ...BnTmp2 contains q[i-t-1]

            /* Step 3.3:    x = x - q[i-t-1] * y * b**(i-t-1) */

            if (KC_OK != ( status = BNShiftDigL( BnTmp, y, i-t-1 )))    // y * b**(i-t-1)
                break;
            if (KC_OK != ( status = BNMultiply( BnTmp1, BnTmp, BnTmp2, 0 )))    // q[i-t-1] * y * b**(i-t-1)
                break;

            /*
             * Step 3.3 and 3.4:
             *    x = x - q[i-t-1] * y * b**(i-t-1)
             *    if x < 0
             *        x = x + y * b**(i-t-1)
             *        q[i-t-1]--
             */

            // x = x - q[i-t-1] * y * b**(i-t-1)
            if (KC_OK != ( status = BNSubtract( x, x, BnTmp1 )))
                break;

            if (x->Sign == 1)
            {
                // x = x + y * b**(i-t-1)
                // q[i-t-1]--
                //
                if (KC_OK != ( status = BNAdd( x, x, BnTmp )))
                    break;

                pQ[i-t-1] = ( pQ[i-t-1] - 1 ) & BN_MASK;
            }

        }    // step 3 ( main loop )

        if (status != KC_OK)
            break;
    } while (0);

    if (z != NULL)
    {
        BNCopy(z, q);
        BNTRIM(z);
    }

    if (r != NULL)
    {
        BNShiftBitsR(r, x, Shift);    // compensate for normalization
        BNTRIM(r);
    }

    return status;
}

/**
 *  Calculate u = b**2k / m for Barrett modular reduction.
 *
 *  Parameters:
 *      pScratch - scratch area for temporary variables
 *      m        - modulus
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNBarrettSetup(KC_BN_SCRATCH *pScratch, KC_BIGNUM *m)
{
    uint32_t status = KC_OK;
    KC_BIGNUM *u = NULL;

    do
    {
        u = &pScratch->Barrett_u;

        // k = m->Used * 2 * BN_BITS
        if (KC_OK != ( status = BNSet2Pwr( u, m->Used * 2 * BN_BITS )))
            break;

        if (KC_OK != ( status = BNDiv( pScratch, u, u, m, NULL )))
            break;
    } while (0);

    return status;
}

/**
 *  Calculate r = x mod m.
 *
 *  Barrett modular reduction, algorithm 14.42 from HAC:
 *  http://www.daimi.au.dk/~cmosses/crypt/index.html#Anchor-Th-4441
 *
 *  Parameters:
 *      r        - result; can be same as x
 *      pScratch - scratch area for temporary variables
 *      x        - x
 *      m        - modulus
 *
 *  Return value:
 *      KC_OK or error code
 */
uint32_t BNBarrettReduce(KC_BN_SCRATCH *pScratch, KC_BIGNUM *r, KC_BIGNUM *x, KC_BIGNUM *m)
{
    uint32_t status = KC_OK;
    uint32_t k = 0;
    uint32_t Compare = 0;
    KC_BIGNUM *q1 = NULL;
    KC_BIGNUM *q2 = NULL;
    KC_BIGNUM *q3 = NULL;
    KC_BIGNUM *u  = NULL;
    KC_BIGNUM *r1 = NULL;
    KC_BIGNUM *r2 = NULL;

    /*
     * Barrett reduction only works if x has not more than 2k digits, where k
     * is the number of digits in m.
     */
    if (x->Used > m->Used * 2)
        return KCERR_BN_INVALID_SIZE;

    // Don't have to do anything if x is smaller than modulus.
    if (BN_SMALLER == BNSecureCompare(x, m))
    {
        BNCopy(r, x);
        return KC_OK;
    }

    do
    {
        k = m->Used;

        q1 = &pScratch->BarrettTemp[0];
        q2 = &pScratch->BarrettTemp[1];
        q3 = &pScratch->BarrettTemp[2];
        r1 = q1;
        r2 = q2;
        u = &pScratch->Barrett_u;

        // q1 = x / b**(k-1)
        BNShiftDigR(q1, x, k - 1);

        // q2 = q1 * u
        // note 14.44 (ii) from HAC: it is safe to only compute k-1 most
        // significant digits
        //
        if (KC_OK != ( status = BNMultiplyHighDigs( q2, q1, u, k - 1 )))
            break;

        // q3 = q2 / b**(k+1)
        BNShiftDigR(q3, q2, k + 1);

        // r1 = x mod b**(k+1)
        BNMod_2Pwr(r1, x, BN_BITS * (k + 1));

        // r2 = q3 * m mod b**(k+1)
        if (KC_OK != ( status = BNMultiply( r2, q3, m, k + 1 )))
            break;

        // r = r1 - r2
        // if r < 0, then r = r + b**(k+1)
        if (KC_OK != ( status = BNSubtract( r, r1, r2 )))
            break;

        if (r->Sign == 1)
        {
            if (KC_OK != ( status = BNSet2Pwr( q1, (k + 1) * BN_BITS )))
                break;
            if (KC_OK != ( status = BNAdd( r, r, q1 )))
                break;
        }

        Compare = BNSecureCompare(r, m);

        k = 0;        // use it as counter now

        // while r >= m, do: r = r - m
        while (Compare != BN_SMALLER)
        {
            /*
             * Under normal conditions this loop should not iterate more than 2 times.
             * In case of any errors in bignumber functions or input parameters,
             * it is likely that this loop will iterate virtually infinitely
             * ( 2**1024 or more is a lot of iterations :-)). Instead of hanging, we
             * return error in this case.
             */
            if (k++ > 10)
            {
                status = KCERR_BAD_BIGNUMBER;
                break;
            }

            if (KC_OK != ( status = BNSubtract( r, r, m )))
                break;

            Compare = BNSecureCompare(r, m);
        };
    } while (0);

    BNTRIM(r);

    return status;
}
