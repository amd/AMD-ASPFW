// Copyright(C) 2017 Advanced Micro Devices, Inc. All rights reserved.

#ifndef AMD_CERT_H
#define AMD_CERT_H

#include "sev_cert.h"
#include "sev_errors.h"

#define AMD_CERT_VERSION        (0x01)
#define AMD_CERT_ID_SIZE_BYTES  (16)

enum amd_cert_key_bits
{
    AMD_CERT_KEY_BITS_2K = 2048,
    AMD_CERT_KEY_BITS_4K = 4096,
};

typedef struct amd_cert_fixed
{
    uint32_t    version;
    uint8_t     key_id[AMD_CERT_ID_SIZE_BYTES];
    uint8_t     certifying_id[AMD_CERT_ID_SIZE_BYTES];
    uint32_t    key_usage;
    uint8_t     reserved[AMD_CERT_ID_SIZE_BYTES];
    uint32_t    pubexp_size_bits;
    uint32_t    modulus_size_bits;
} amd_cert_fixed_t;

#define AMD_CERT_MAX_LENGTH     (sizeof(amd_cert_fixed_t) +             \
                                    3*AMD_CERT_KEY_BITS_4K/(BITS_PER_BYTE))
#define AMD_CERT_MIN_LENGTH     (sizeof(amd_cert_fixed_t) +             \
                                    3*AMD_CERT_KEY_BITS_2K/(BITS_PER_BYTE))
typedef struct amd_cert_pubkey
{
    uint32_t        pubexp_size;
    uint32_t        modulus_size;
    const uint8_t   *pubexp;
    const uint8_t   *modulus;
} amd_cert_pubkey_t;

typedef struct amd_cert
{
    amd_cert_fixed_t    fixed;
    amd_cert_pubkey_t   pubkey;
    const uint8_t       *signature;
} amd_cert_t;

/**
 * Initialize an amd_cert_t object. AMD certificates are far too large to store
 * on the stack, so the caller must first copy the certificate into a
 * sufficiently large buffer.
 *
 * Parameters:
 *     cert    [out] AMD certificate object,
 *     buffer  [in]  buffer containing the raw AMD certificate,
 *     size    [in]  size of the data in the buffer.
 */
sev_status_t amd_cert_init(amd_cert_t *cert, const uint8_t *buffer,
                           size_t size);

/**
 * Validate the AMD Root Key certificate.
 *
 * Parameters:
 *     cert    [in] ARK certificate object.
 */
sev_status_t amd_cert_validate_ark(const amd_cert_t *ark);

/**
 * Validate the AMD SEV Signing Key certificate.
 *
 * Parameters:
 *     ask        [in] ASK certificate object,
 *     ark        [in] ARK certificate object,
 */
sev_status_t amd_cert_validate_ask(const amd_cert_t *ask,
                                   const amd_cert_t *ark);

size_t amd_cert_get_size(const amd_cert_t *cert);
sev_status_t amd_cert_export_pubkey(const amd_cert_t *cert,
                                    sev_cert_pubkey_t *pubkey);
bool amd_cert_chain_length_is_valid(size_t length);

#endif /* AMD_CERT_H */
