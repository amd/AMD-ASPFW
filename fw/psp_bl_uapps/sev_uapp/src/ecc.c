// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stdint.h>
#include <string.h>

#include "bignum.h"
#include "ecc.h"
#include "secure_ops.h"
#include "sev_hal.h"

/**
 * The following domain parameters is from:
 * http://www.secg.org/sec2-v2.pdf.
 * Note: the parameters have been converted to little endian.
 *
 * Note: All ECC data must be in little-endian according to CCP 5.0 TRM!!!
 *
 * For each prime p, a pseudo-random curve
 * E : y^2 = x^3 - 3x + b (mod p)
 * of prime order n is listed4. (Thus, for these curves, the cofactor is always h = 1.)
 */

/**
 * The elliptic curve domain parameters over Fp associated with a Koblitz curve
 * secp256k1 are specified by the sextuple T = (p, a, b, G, n, h)
 */
static const ecc_curve_t ECC_CURVE_SECP256K1 = {
    .name = ECC_CURVE_NAME_SECP256K1,

    .p = {{ 0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }},

    .a = {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }},

    .b = {{ 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, }},

    .G = {{{0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
            0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79,}},

          {{0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
            0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48,}}},

    .n = {{ 0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }},

    .h = {{ 0x01, }},
};

/**
 * The verifiably random elliptic curve domain parameters over Fp secp384r1 are
 * specified by the sextuple T = (p, a, b, G, n, h)
 */
static const ecc_curve_t ECC_CURVE_SECP384R1 = {
    .name = ECC_CURVE_NAME_SECP384R1,

    .p = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }},

    .a = {{ 0xFC, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }},

    .b = {{ 0xEF, 0x2A, 0xEC, 0xD3, 0xED, 0xC8, 0x85, 0x2A, 0x9D, 0xD1, 0x2E, 0x8A, 0x8D, 0x39, 0x56, 0xC6,
            0x5A, 0x87, 0x13, 0x50, 0x8F, 0x08, 0x14, 0x03, 0x12, 0x41, 0x81, 0xFE, 0x6E, 0x9C, 0x1D, 0x18,
            0x19, 0x2D, 0xF8, 0xE3, 0x6B, 0x05, 0x8E, 0x98, 0xE4, 0xE7, 0x3E, 0xE2, 0xA7, 0x2F, 0x31, 0xB3, }},

    .G = {{{0xB7, 0x0A, 0x76, 0x72, 0x38, 0x5E, 0x54, 0x3A, 0x6C, 0x29, 0x55, 0xBF, 0x5D, 0xF2, 0x02, 0x55,
            0x38, 0x2A, 0x54, 0x82, 0xE0, 0x41, 0xF7, 0x59, 0x98, 0x9B, 0xA7, 0x8B, 0x62, 0x3B, 0x1D, 0x6E,
            0x74, 0xAD, 0x20, 0xF3, 0x1E, 0xC7, 0xB1, 0x8E, 0x37, 0x05, 0x8B, 0xBE, 0x22, 0xCA, 0x87, 0xAA}},

          {{0x5F, 0x0E, 0xEA, 0x90, 0x7C, 0x1D, 0x43, 0x7A, 0x9D, 0x81, 0x7E, 0x1D, 0xCE, 0xB1, 0x60, 0x0A,
            0xC0, 0xB8, 0xF0, 0xB5, 0x13, 0x31, 0xDA, 0xE9, 0x7C, 0x14, 0x9A, 0x28, 0xBD, 0x1D, 0xF4, 0xF8,
            0x29, 0xDC, 0x92, 0x92, 0xBF, 0x98, 0x9E, 0x5D, 0x6F, 0x2C, 0x26, 0x96, 0x4A, 0xDE, 0x17, 0x36,}}},

    .n = {{ 0x73, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC, 0x7A, 0xA7, 0xB0, 0x48, 0xB2, 0x0D, 0x1A, 0x58,
            0xDF, 0x2D, 0x37, 0xF4, 0x81, 0x4D, 0x63, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, }},

    .h = {{ 0x01, }},
};

static const ecc_curve_t *sev_supported_curves[] = {
        [ECC_CURVE_NAME_INVALID]   = NULL,
        [ECC_CURVE_NAME_SECP256K1] = &ECC_CURVE_SECP256K1,
        [ECC_CURVE_NAME_SECP384R1] = &ECC_CURVE_SECP384R1,
};

/**
 * Checks to see if EC points are on the curve, before doing any
 * real math with them. CSF-338
 */
static bool check_ec_points_on_curve(const ecc_pubkey_t *pubkey)
{
    if (!pubkey)
        return false;

    bool is_valid = false;
    /*
     * To check whether (x,y) is on the curve, it needs to satisfy the elliptic
     * curve equation: y^2 = x^3 + a*x + b
     * over the field Fp, where a and b are taken from the curve parameters.
     * That amounts to this Boolean expression: (y^2)%p == (x^3 + a*x + b) % p
     * Note: a=-3 for the NIST P-256 and P-384 curves.
     *          b is hardcoded in the existing sources.
     *          The %p operation can be done at each step of the calculation, as
     *            part of each multiplication or subtraction.
     */
    /* Need to try this for all curves we support */
    const ecc_curve_t *curve = ecc_get_curve(pubkey->curve);
    if (!curve)
        return false;
    const ecc_scalar_t *x = &pubkey->Q.x;
    const ecc_scalar_t *y = &pubkey->Q.y;
    const ecc_scalar_t *a = &curve->a;
    const ecc_scalar_t *b = &curve->b;
    const ecc_scalar_t *p = &curve->p;

    ecc_scalar_t y_sq_modp;
    ecc_scalar_t x_sq_modp;
    ecc_scalar_t x_cub_modp;
    ecc_scalar_t ax_modp;
    ecc_scalar_t b_modp;
    ecc_scalar_t x_cub_plus_ax;
    ecc_scalar_t x_cub_plus_ax_plus_b;
    ecc_scalar_t subtraction;

    /* Zero everything */
    memset(&y_sq_modp, 0, sizeof(y_sq_modp));
    memset(&x_sq_modp, 0, sizeof(x_sq_modp));
    memset(&x_cub_modp, 0, sizeof(x_cub_modp));
    memset(&ax_modp, 0, sizeof(ax_modp));
    memset(&b_modp, 0, sizeof(b_modp));
    memset(&x_cub_plus_ax, 0, sizeof(x_cub_plus_ax));
    memset(&x_cub_plus_ax_plus_b, 0, sizeof(x_cub_plus_ax_plus_b));
    memset(&subtraction, 0, sizeof(subtraction));

    /* (y^2)%p == (x^3 + a*x + b) % p */
    /* Do the %p as we go */
    if (ecc_scalar_mul(&y_sq_modp, y, y, p) != SEV_STATUS_SUCCESS)
        goto end;
    if (ecc_scalar_mul(&x_sq_modp, x, x, p) != SEV_STATUS_SUCCESS)
        goto end;
    if (ecc_scalar_mul(&x_cub_modp, &x_sq_modp, x, p) != SEV_STATUS_SUCCESS)
        goto end;
    if (ecc_scalar_mul(&ax_modp, a, x, p) != SEV_STATUS_SUCCESS)
        goto end;
    if (ecc_scalar_mod(&b_modp, b, p) != SEV_STATUS_SUCCESS)
        goto end;
    if (ecc_scalar_add(&x_cub_plus_ax, &x_cub_modp, &ax_modp, p) != SEV_STATUS_SUCCESS)
        goto end;
    if (ecc_scalar_add(&x_cub_plus_ax_plus_b, &x_cub_plus_ax, &b_modp, p) != SEV_STATUS_SUCCESS)
        goto end;

    if (ecc_scalar_minus(&subtraction, &x_cub_plus_ax_plus_b, &y_sq_modp) != SEV_STATUS_SUCCESS)
        goto end;
    is_valid = ecc_scalar_is_zero(&subtraction);

end:
    return is_valid;
}

bool curve_id_is_valid(ecc_curve_name_t id)
{
    return (id != ECC_CURVE_NAME_INVALID) && (id < ARRAY_LENGTH(sev_supported_curves));
}

const ecc_curve_t *ecc_get_curve(ecc_curve_name_t id)
{
    return curve_id_is_valid(id) ? sev_supported_curves[id] : NULL;
}

sev_status_t ecc_get_pubkey(const ecc_keypair_t *keypair, ecc_pubkey_t *pubkey)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!keypair || !pubkey)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /*
     * Since there are no unions in ecc_keypair_t or ecc_pubkey_t,
     * this should be safe.
     */
    memcpy(pubkey, keypair, sizeof(*pubkey));

end:
    return status;
}

bool ecc_pubkey_is_valid(const ecc_pubkey_t *pubkey)
{
    bool is_valid = false;

    if (!curve_id_is_valid(pubkey->curve) || pubkey->curve != ECC_CURVE_NAME_SECP384R1)
    {
        is_valid = false;
        goto end;
    }

    is_valid = check_ec_points_on_curve(pubkey);

end:
    return is_valid;
}

sev_status_t ecc_scalar_init(ecc_scalar_t *scalar, const uint8_t *buffer,
                             size_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t temp;

    if (!scalar || !buffer || size > sizeof(*scalar))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp, 0, sizeof(temp));
    memcpy(temp.s, buffer, size);

    /*
     * FIPS 186-4 Appendix C.2 specifies the conversion of a byte string to
     * an ECC integer:
     *
     * "Note that the first bit of a sequence corresponds to the most
     * significant bit of the corresponding integer, and the last bit
     * corresponds to the least significant bit."
     *
     * Thus, we need to swap the input bytes. Note that the CCP also requires
     * big-endian input.
     */
    status = reverse_bytes(temp.s, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memcpy(scalar, &temp, sizeof(*scalar));

end:
    return status;
}

/* Constant time */
bool ecc_scalar_is_greater(const ecc_scalar_t *a, const ecc_scalar_t *b)
{
    int compare = false;

    compare = secure_array_compare_le(&(a->s), &(b->s), sizeof(ecc_scalar_t));

    return (compare == 1) ? true : false;
}

/* Semi-constant-time */
bool ecc_scalar_is_zero(const ecc_scalar_t *rop)
{
    bool is_zero = false;

    if (rop->s[0]==0)
        is_zero = secure_compare(&rop->s[0], &rop->s[1], (sizeof(*rop)-1)) == 0;

    return is_zero;
}

sev_status_t ecc_scalar_add(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *op2, const ecc_scalar_t *modulus)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;

    if (!rop || !op1 || !op2 || !modulus)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = SCALAR_ADD;
    ecc.cmd.scalar_add.r = rop;
    ecc.cmd.scalar_add.n = (ecc_scalar_t *)modulus;
    ecc.cmd.scalar_add.a = (ecc_scalar_t *)op1;
    ecc.cmd.scalar_add.b = (ecc_scalar_t *)op2;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_scalar_minus(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                              const ecc_scalar_t *op2)
{
    sev_status_t    status = SEV_STATUS_SUCCESS;
    uint32_t        borrow;
    uint8_t        *result;
    const uint8_t  *a;
    const uint8_t  *b;
    uint8_t         op_left;
    uint8_t         op_right;
    size_t          index;

    if (!rop || !op1 || !op2 || ecc_scalar_is_greater(op2, op1))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    result = (uint8_t *)rop;
    a = (const uint8_t *)op1;
    b = (const uint8_t *)op2;
    borrow = 0;

    for (index = 0; index < sizeof(*rop); index++)
    {
        op_left = a[index] - borrow;
        op_right = b[index];

        if (op_left > a[index])
        {
            /* op1[index] must be 0 and have been borrowed by lower byte.
               the borrowed bit must be borrowed again from higher byte. */
            borrow = 1;
            result[index] = op_left - op_right;
        }
        else
        {
            borrow = 0;
            result[index] = op_left - op_right;
            if (result[index] > op_left)
            {
                /* Need to borrow from higher byte */
                borrow = 1;
            }
        }
    }

end:
    return status;
}

sev_status_t ecc_scalar_mod(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *modulus)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t op;

    if (!rop || !op1 || !modulus)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memcpy(&op, op1, sizeof(op));

    do
    {
        if (ecc_scalar_is_greater(modulus, &op))
        {
            memcpy(rop, &op, sizeof(*rop));
            break;
        }
        else
        {
            status = ecc_scalar_minus(&op, &op, modulus);
            if (status != SEV_STATUS_SUCCESS)
            {
                break;
            }
        }

    } while (1);

end:
    return status;
}

sev_status_t ecc_scalar_reduce(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                               const ecc_scalar_t *modulus)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    KC_BN_SCRATCH scratch;
    KC_BIGNUM mod;
    KC_BIGNUM x;
    KC_BIGNUM result;
    uint32_t rc = KC_OK;

    if (!rop || !op1 || !modulus)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    rc = BNLoad(&mod, modulus->s, sizeof(modulus->s));
    if (rc != KC_OK)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    rc = BNLoad(&x, op1->s, sizeof(op1->s));
    if (rc != KC_OK)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&scratch, 0, sizeof(scratch));
    rc = BNBarrettSetup(&scratch, &mod);
    if (rc != KC_OK)
    {
        status = ERR_UNKNOWN;
        goto end;
    }

    memset(&result, 0, sizeof(result));
    rc = BNBarrettReduce(&scratch, &result, &x, &mod);
    if (rc != KC_OK)
    {
        status = ERR_UNKNOWN;
        goto end;
    }

    rc = BNStore(&result, rop->s, sizeof(rop->s));
    if (rc != KC_OK)
    {
        status = ERR_UNKNOWN;
        goto end;
    }

end:
    return status;
}

sev_status_t ecc_scalar_mul(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *op2, const ecc_scalar_t *modulus)

{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;

    if (!rop || !op1 || !op2 || !modulus)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = SCALAR_MUL;
    ecc.cmd.scalar_mul.r = rop;
    ecc.cmd.scalar_mul.n = (ecc_scalar_t *)modulus;
    ecc.cmd.scalar_mul.a = (ecc_scalar_t *)op1;
    ecc.cmd.scalar_mul.b = (ecc_scalar_t *)op2;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_scalar_inv(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *modulus)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;

    if (!rop || !op1 || !modulus)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = SCALAR_INV;
    ecc.cmd.scalar_inv.r = rop;
    ecc.cmd.scalar_inv.n = (ecc_scalar_t *)modulus;
    ecc.cmd.scalar_inv.a = (ecc_scalar_t *)op1;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_point_add(ecc_point_t *rop, const ecc_point_t *op1,
                           const ecc_point_t *op2, ecc_curve_name_t curve_id)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;
    const ecc_curve_t *curve = ecc_get_curve(curve_id);

    if (!rop || !op1 || !op2 || !curve)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = POINT_ADD;
    ecc.cmd.point_add.R = rop;
    ecc.cmd.point_add.n = (ecc_scalar_t *)&curve->p;
    ecc.cmd.point_add.P = (ecc_point_t *)op1;
    ecc.cmd.point_add.Q = (ecc_point_t *)op2;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_point_double(ecc_point_t *rop, const ecc_point_t *op1,
                              ecc_curve_name_t curve_id)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;
    const ecc_curve_t *curve = ecc_get_curve(curve_id);

    if (!rop || !op1 || !curve)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = POINT_DOUBLE;
    ecc.cmd.point_double.R = rop;
    ecc.cmd.point_double.n = (ecc_scalar_t *)&curve->p;
    ecc.cmd.point_double.a = (ecc_scalar_t *)&curve->a;
    ecc.cmd.point_double.P = (ecc_point_t *)op1;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_point_scale(ecc_point_t *rop, const ecc_point_t *op1,
                             const ecc_scalar_t *k, ecc_curve_name_t curve_id)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;
    const ecc_curve_t *curve = ecc_get_curve(curve_id);

    if (!rop || !op1 || !k || !curve)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = POINT_SCALE;
    ecc.cmd.point_scale.R = rop;
    ecc.cmd.point_scale.n = (ecc_scalar_t *)&curve->p;
    ecc.cmd.point_scale.a = (ecc_scalar_t *)&curve->a;
    ecc.cmd.point_scale.k = (ecc_scalar_t *)k;
    ecc.cmd.point_scale.P = (ecc_point_t *)op1;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_point_linear(ecc_point_t *rop, const ecc_point_t *op1,
                              const ecc_scalar_t *k, const ecc_point_t *op2,
                              const ecc_scalar_t *h, ecc_curve_name_t curve_id)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_ecc_primitive_t ecc;
    const ecc_curve_t *curve = ecc_get_curve(curve_id);

    if (!rop || !op1 || !k || !op2 || !h || !curve)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ecc.primitive = POINT_DUAL_MUL;
    ecc.cmd.point_dual_mul.R = rop;
    ecc.cmd.point_dual_mul.n = (ecc_scalar_t *)&curve->p;
    ecc.cmd.point_dual_mul.a = (ecc_scalar_t *)&curve->a;
    ecc.cmd.point_dual_mul.k = (ecc_scalar_t *)k;
    ecc.cmd.point_dual_mul.P = (ecc_point_t *)op1;
    ecc.cmd.point_dual_mul.h = (ecc_scalar_t *)h;
    ecc.cmd.point_dual_mul.Q = (ecc_point_t *)op2;

    status = sev_hal_ecc_primitive(&ecc);

end:
    return status;
}

sev_status_t ecc_keypair_from_extra_bits(ecc_keypair_t *keypair,
                                         ecc_curve_name_t curve_id,
                                         const uint8_t *rdata, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_keypair_t temp_keypair;
    ecc_scalar_t c;
    ecc_scalar_t one;
    ecc_scalar_t modulus;
    const ecc_curve_t *curve = ecc_get_curve(curve_id);

    if (!keypair || !curve || !rdata ||
        length != SEV_ECC_CURVE_SIZE_BYTES + ECC_KEYGEN_EXTRA_BYTES)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp_keypair, 0, sizeof(temp_keypair));
    memset(&modulus, 0, sizeof(modulus));
    memset(&one, 0, sizeof(one));
    one.s[0] = 1;
    memset(&c, 0, sizeof(c));
    memcpy(&c.s, rdata, length);    /* Is this little endian? */

    /*
     * Note, no need to validate domain parameters as we are using NIST curves.
     */

    /* Calculate d = c mod(n-1) + 1 */
    status = ecc_scalar_minus(&modulus, &curve->n, &one);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = ecc_scalar_reduce(&temp_keypair.d, &c, &modulus);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Since we just reduced the data mod(n-1), doing the addition mod(n)
     * guarantees that we can add one without wrapping.
     */
    status = ecc_scalar_add(&temp_keypair.d, &temp_keypair.d, &one, &curve->n);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Calculate Q=d*G */
    status = ecc_point_scale(&temp_keypair.Q, &curve->G, &temp_keypair.d, curve_id);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the result */
    memcpy(keypair, &temp_keypair, sizeof(*keypair));
    keypair->curve = curve_id;

end:
    return status;
}

sev_status_t ecc_keypair_from_candidates(ecc_keypair_t *keypair,
                                         ecc_curve_name_t curve_id,
                                         const uint8_t *rdata, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t c;
    ecc_scalar_t n_x;
    size_t i = 0;
    uint8_t prev_val = 0;
    bool borrow = false;
    bool carry  = false;
    const ecc_curve_t *curve = ecc_get_curve(curve_id);

    if (!keypair || !curve || !rdata || length == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Clear the output buffer */
    memset(keypair, 0, sizeof(*keypair));

    /* Note, no need to validate curve domain parameter data as we are using NIST curve */

    /* Calculate n_x = n-2 */
    memcpy(&n_x, &(curve->n), sizeof(n_x));
    prev_val = n_x.s[0];
    n_x.s[0] = prev_val - 2;            /* First byte minus 2 */
    borrow = (prev_val < n_x.s[0]);
    for (i = 1; i < sizeof(n_x); i++)   /* Start from second byte */
    {
        if (!borrow)
        {
            break;
        }
        prev_val = n_x.s[i];
        n_x.s[i] = prev_val - 1;        /* Borrow 1 */
        borrow = (prev_val < n_x.s[i]);
    }

    /* Check if c > n-2 */
    memset(&c, 0, sizeof(c));
    memcpy(&c, rdata, length);
    if (ecc_scalar_is_greater(&c, &n_x))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Calculate d=c+1 */
    for (i = 0; i < sizeof(c); i++)
    {
        prev_val = n_x.s[i];
        n_x.s[i] = prev_val + 1;    /* Carry 1 */
        carry = (prev_val > n_x.s[i]);

        if (!carry)
        {
            break;
        }
    }

    /* Calculate Q=d*G */
    status = ecc_point_scale( &keypair->Q, &curve->G, &c, curve_id);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* Copy private key */
    memcpy(&keypair->d, &c, sizeof(c));

    /* Set the curve */
    keypair->curve = curve_id;

end:
    return status;
}

sev_status_t ecc_keypair_generate_rdata(ecc_keypair_t *keypair,
                                        ecc_curve_name_t curve_id,
                                        const uint8_t *rdata, size_t length)
{
    return ecc_keypair_from_candidates(keypair, curve_id, rdata, length);
}
