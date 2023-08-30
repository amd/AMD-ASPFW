// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "ecc.h"
#include "ecc_utest.h"

static bool ecc_scalar_subtract_utest(void)
{
    bool result = true;
    ecc_scalar_t left;
    ecc_scalar_t right;
    ecc_scalar_t diff;
    ecc_scalar_t expected;
    sev_status_t status = SEV_STATUS_SUCCESS;

    memset(&left, 0, sizeof(left));
    memset(&right, 0, sizeof(right));
    memset(&diff, 0, sizeof(diff));
    memset(&expected, 0, sizeof(expected));

    /* left = 0x530003 */
    left.s[0] = 0x03;
    left.s[1] = 0x00;
    left.s[2] = 0x53;

    /* right = 0x353535 */
    right.s[0] = 0x35;
    right.s[1] = 0x35;
    right.s[2] = 0x35;

    /* expected = 0x1DCACE */
    expected.s[0] = 0xCE;
    expected.s[1] = 0xCA;
    expected.s[2] = 0x1D;

    /* diff = left - right = 0x1DCACE */
    status = ecc_scalar_minus(&diff, &left, &right);
    if (status != SEV_STATUS_SUCCESS || memcmp(&diff, &expected, sizeof(diff)) != 0)
        result = false;

    return result;
}

bool ecc_scalar_mul_utest(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t one;
    ecc_scalar_t product;
    const ecc_curve_t *curve = ecc_get_curve(ECC_CURVE_NAME_SECP384R1);

    memset(&product, 0, sizeof(product));
    memset(&one, 0, sizeof(one));
    one.s[0] = 1;

    status = ecc_scalar_mul(&product, &one, &curve->G.x, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (memcmp(&product, &curve->G.x, sizeof(product)) != 0)
        status = ERR_UNKNOWN;

end:
    return status == SEV_STATUS_SUCCESS ? true : false;
}

sev_status_t ecc_utest(void)
{
    bool result = true;

    result = ecc_scalar_subtract_utest();
    if (!result)
        goto end;

    result = ecc_scalar_mul_utest();

end:
    return result ? SEV_STATUS_SUCCESS : ERR_UNKNOWN;
}
