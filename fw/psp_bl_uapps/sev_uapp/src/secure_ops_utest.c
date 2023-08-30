// Copyright(C) 2020 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "bignum.h"
#include "secure_ops.h"
#include "secure_ops_utest.h"
#include "sev_trace.h"

enum
{
    SC_EQUAL   = 0,
    SC_BIGGER  = 1,
    SC_SMALLER = 2,
};

static const uint8_t b01[4] = {50, 88, 1, 200};
static const uint8_t b02[4] = {50, 3, 1, 200};

static const uint8_t b11[4] = {50, 88, 1, 200};
static const uint8_t b12[4] = {50, 210, 1, 200};

static const uint8_t b21[4] = {50, 255, 0, 200};
static const uint8_t b22[4] = {50, 255, 0, 200};

static const uint8_t b31[4] = {0, 51, 100, 200};
static const uint8_t b32[4] = {55, 99, 50, 200};

static const uint8_t b41[4] = {0, 50, 100, 50};
static const uint8_t b42[4] = {50, 100, 50, 0};

static const uint8_t b51[4] = {0, 255, 100, 50};
static const uint8_t b52[4] = {255, 100, 50, 0};

static const uint8_t b61[4] = {0, 0, 0, 1};
static const uint8_t b62[4] = {0, 0, 0, 2};
static const uint8_t b63[4] = {0, 0, 0, 0};

sev_status_t secure_ops_utest(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (secure_array_compare_le(b01, b02, 4) != SC_BIGGER  ||
        secure_array_compare_le(b11, b12, 4) != SC_SMALLER ||
        secure_array_compare_le(b21, b22, 4) != SC_EQUAL   ||
        secure_array_compare_le(b31, b32, 4) != SC_BIGGER  ||
        secure_array_compare_le(b41, b42, 4) != SC_BIGGER  ||
        secure_array_compare_le(b51, b52, 4) != SC_BIGGER)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    KC_BIGNUM x;
    KC_BIGNUM y;
    if (BNLoad(&x, b01, sizeof(b01)) != KC_OK ||
        BNLoad(&y, b02, sizeof(b02)) != KC_OK ||
        BNSecureCompare(&x, &y) != BN_BIGGER )
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (BNLoad(&x, b11, sizeof(b11)) != KC_OK ||
        BNLoad(&y, b12, sizeof(b12)) != KC_OK ||
        BNSecureCompare(&x, &y) != BN_SMALLER)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (BNLoad(&x, b21, sizeof(b21)) != KC_OK ||
        BNLoad(&y, b22, sizeof(b22)) != KC_OK ||
        BNSecureCompare(&x, &y) != BN_EQUAL)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (BNLoad(&x, b31, sizeof(b31)) != KC_OK ||
        BNLoad(&y, b32, sizeof(b32)) != KC_OK ||
        BNSecureCompare(&x, &y) != BN_BIGGER)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (BNLoad(&x, b41, sizeof(b41)) != KC_OK ||
        BNLoad(&y, b42, sizeof(b42)) != KC_OK ||
        BNSecureCompare(&x, &y) != BN_BIGGER)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (BNLoad(&x, b51, sizeof(b51)) != KC_OK ||
        BNLoad(&y, b52, sizeof(b52)) != KC_OK ||
        BNSecureCompare(&x, &y) != BN_BIGGER)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (BNLoad(&x, b61, sizeof(b61)) != KC_OK ||    /* x = 1  */
        BNLoad(&y, b62, sizeof(b62)) != KC_OK ||    /* y = 2  */
        BNSubtract(&x, &x, &y) != KC_OK       ||    /* x = -1 */
        BNLoad(&y, b61, sizeof(b61)) != KC_OK ||    /* y = 1  */
        BNSecureCompare(&x, &y) != BN_EQUAL   ||    /* ABS(-1) < ABS(1) */
        BNSecureCompare(&y, &x) != BN_EQUAL   ||
        BNLoad(&y, b63, sizeof(b63)) != KC_OK ||    /* y = 0  */
        BNSecureCompare(&x, &y) != BN_BIGGER ||    /* ABS(-1) < ABS(0) */
        BNSecureCompare(&y, &x) != BN_SMALLER)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("secure_ops_utest failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("secure_ops_utest succeed!\n");
    }

    return status;
}
