// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_ECC_H
#define SEV_ECC_H

#include <stdint.h>

#include "sev_errors.h"
#include "sev_svc.h"

#define ECC_CURVE_SECP256R1_SIZE_BYTES  32
#define ECC_CURVE_SECP256R1_SIZE_BITS   256
#define ECC_CURVE_SECP384R1_SIZE_BYTES  48
#define ECC_CURVE_SECP384R1_SIZE_BITS   384

// SEV supported ECC curve size
#define SEV_ECC_CURVE_SIZE_BYTES        ECC_CURVE_SECP384R1_SIZE_BYTES

/**
 * For ECC keys generated from extra bits, FIPS 180-4 requires that the
 * input contain an additional 64 bits (8 bytes) of random data.
 */
#define ECC_KEYGEN_EXTRA_BITS   (64)
#define ECC_KEYGEN_EXTRA_BYTES  (8)

// All ECC data must be in little-endian
// CCP5.0 ECC engine support prime curves up to 521 bits, Binary curves up to 571 bits
#define ECC_SCALAR_SIZE_BYTES   72

typedef enum ecc_curve_name
{
    ECC_CURVE_NAME_INVALID   = 0,
    ECC_CURVE_NAME_SECP256K1 = 1,
    ECC_CURVE_NAME_SECP384R1 = 2,
} ecc_curve_name_t;

typedef uint8_t ecc_int_t[ECC_SCALAR_SIZE_BYTES];

/**
 * in the prime case, the domain parameters are (p,a,b,G,n,h);
 * in the binary case, they are (m,f,a,b,G,n,h).
 */
typedef struct ecc_curve
{
    ecc_curve_name_t name;
    ecc_scalar_t p;         /* Prime, the field is defined by p in the prime case. Field size q=p (odd prime), or q = 2^m for binary case */
    ecc_scalar_t a;         /* Curve coefficient (i.e. y^2 = x^3 + ax + b) */
    ecc_scalar_t b;         /* Curve coefficient (i.e. y^2 = x^3 + ax + b) */
    ecc_point_t  G;         /* Base point */
    ecc_scalar_t n;         /* The order of base point */
    ecc_scalar_t h;         /* Cofactor */
} ecc_curve_t;

typedef struct ecc_keypair
{
    ecc_curve_name_t    curve;
    ecc_point_t         Q;       /* Public key */
    ecc_scalar_t        d;       /* Private key, Q=d*G */
} ecc_keypair_t;

typedef struct ecc_pubkey
{
    ecc_curve_name_t    curve;
    ecc_point_t         Q;
} ecc_pubkey_t;

const ecc_curve_t *ecc_get_curve(size_t id);
sev_status_t ecc_get_pubkey(const ecc_keypair_t *keypair, ecc_pubkey_t *pubkey);
bool ecc_pubkey_is_valid(const ecc_pubkey_t *pubkey);

/**
 * Initialize the scalar using 'size' bytes copied from 'buffer'. The scalar
 * is formatted properly for use by the CCP.
 */
sev_status_t ecc_scalar_init(ecc_scalar_t *scalar, const uint8_t *buffer,
                             size_t size);
bool ecc_scalar_is_greater(const ecc_scalar_t *a, const ecc_scalar_t *b);
bool ecc_scalar_is_zero(const ecc_scalar_t *rop);
sev_status_t ecc_scalar_minus(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                              const ecc_scalar_t *op2);

sev_status_t ecc_scalar_add(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *op2, const ecc_scalar_t *modulus);

sev_status_t ecc_scalar_mod(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *modulus);
sev_status_t ecc_scalar_reduce(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                               const ecc_scalar_t *modulus);

sev_status_t ecc_scalar_mul(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *op2, const ecc_scalar_t *modulus);

sev_status_t ecc_scalar_inv(ecc_scalar_t *rop, const ecc_scalar_t *op1,
                            const ecc_scalar_t *modulus);

sev_status_t ecc_point_add(ecc_point_t *rop, const ecc_point_t *op1,
                           const ecc_point_t *op2, ecc_curve_name_t curve_id);

sev_status_t ecc_point_double(ecc_point_t *rop, const ecc_point_t *op1,
                              ecc_curve_name_t curve_id);

sev_status_t ecc_point_scale(ecc_point_t *rop, const ecc_point_t *op1,
                             const ecc_scalar_t *k, ecc_curve_name_t curve_id);

sev_status_t ecc_point_linear(ecc_point_t *rop, const ecc_point_t *op1,
                              const ecc_scalar_t *k, const ecc_point_t *op2,
                              const ecc_scalar_t *h, ecc_curve_name_t curve_id);

/**
 *  Key pair generation following NIST-FIPS-186-4.pdf section B.4.2:
 *
 *  Key pair generation by:
 *      1. extra random bits,
 *      2. testing candidates.
 */
sev_status_t ecc_keypair_generate_rdata(ecc_keypair_t *keypair,
                                        ecc_curve_name_t curve_id,
                                        const uint8_t *rdata, size_t length);

sev_status_t ecc_keypair_from_extra_bits(ecc_keypair_t *keypair,
                                         ecc_curve_name_t curve_id,
                                         const uint8_t *rdata, size_t length);

sev_status_t ecc_keypair_from_candidates(ecc_keypair_t *keypair,
                                         ecc_curve_name_t curve_id,
                                         const uint8_t *rdata, size_t length);

#endif /* SEV_ECC_H */
