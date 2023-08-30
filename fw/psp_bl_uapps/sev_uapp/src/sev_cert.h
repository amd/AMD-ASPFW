// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_CERT_H
#define SEV_CERT_H

#include <stdlib.h>
#include <stdint.h>

#include "ecdsa.h"
#include "rsa.h"
#include "sev_status.h"

enum sev_cert_usage
{
    SEV_CERT_USAGE_ARK      = 0x00,
    SEV_CERT_USAGE_ASK      = 0x13,

    SEV_CERT_USAGE_INVALID  = 0x1000,
    SEV_CERT_USAGE_OCA      = 0x1001,
    SEV_CERT_USAGE_PEK      = 0x1002,
    SEV_CERT_USAGE_PDH      = 0x1003,
    SEV_CERT_USAGE_CEK      = 0x1004,
};

// every place uses this as a uint32_t because there's a circular reference
// between this enum and sev_cert_sig in ecdsa.h/rsa.h.
enum sev_cert_algo
{
    SEV_CERT_ALGO_INVALID      = 0x000,
    SEV_CERT_ALGO_RSA_SHA256   = 0x001,
    SEV_CERT_ALGO_ECDSA_SHA256 = 0x002,
    SEV_CERT_ALGO_ECDH_SHA256  = 0x003,

    SEV_CERT_ALGO_RSA_SHA384   = 0x101,
    SEV_CERT_ALGO_ECDSA_SHA384 = 0x102,
    SEV_CERT_ALGO_ECDH_SHA384  = 0x103,
    SEV_CERT_ALGO_LIMIT,
};

typedef struct sev_cert_sig
{
    uint32_t            usage;
    uint32_t            algo;
    union {
        rsa_sig_t       rsa;
        ecdsa_sig_t     ecdsa;
    } sig;
} sev_cert_sig_t;

typedef struct sev_cert_keypair
{
    uint32_t            usage;
    uint32_t            algo;
    union {
        rsa_keypair_t   rsa;
        ecc_keypair_t   ecdsa;
    } keypair;
} sev_cert_keypair_t;

typedef struct sev_cert_pubkey
{
    uint32_t            usage;
    uint32_t            algo;
    union {
        rsa_pubkey_t    rsa;
        ecc_pubkey_t    ecdsa;
    } key;
} sev_cert_pubkey_t;

typedef struct sev_cert_body
{
    uint32_t            version;
    uint8_t             api_major;
    uint8_t             api_minor;
    uint8_t             reserved[2];
    sev_cert_pubkey_t   pubkey;
} sev_cert_body_t;

typedef struct sev_cert
{
    sev_cert_body_t     body;
    sev_cert_sig_t      sig1;
    sev_cert_sig_t      sig2;
} sev_cert_t;

/**
 * Check if a certificate has a valid public key.
 */
bool sev_cert_has_pubkey(const sev_cert_t *cert);

/**
 * Validate the body metadata for the certificate.
 */
sev_status_t sev_cert_sanity_check(const sev_cert_t *cert, uint32_t expected_usage,
                                   uint32_t expected_algo);

/**
 * Retrieve the public portion of the key pair.
 */
sev_status_t sev_cert_keypair_get_pubkey(const sev_cert_keypair_t *keypair,
                                         sev_cert_pubkey_t *pubkey);

/**
 * Retrieve the public key of the certificate.
 */
sev_status_t sev_cert_get_pubkey(const sev_cert_t *cert, sev_cert_pubkey_t *pubkey);

/**
 * Retrieve the signature of the certificate.
 */
sev_status_t sev_cert_get_sig1(const sev_cert_t *cert, sev_cert_sig_t *sig);
sev_status_t sev_cert_get_sig2(const sev_cert_t *cert, sev_cert_sig_t *sig);

/**
 * Set the public key of the certificate.
 */
sev_status_t sev_cert_set_pubkey(sev_cert_t *cert, const sev_cert_pubkey_t *pubkey);

/**
 * Set the signature of the certificate.
 */
sev_status_t sev_cert_set_sig(sev_cert_t *cert, const sev_cert_sig_t *sig);

/**
 * Add a signature to the cert using the given signing key.
 */
sev_status_t sev_cert_sign(sev_cert_t *cert, const sev_cert_keypair_t *key);

/**
 * Initialize a sev_cert_t object.
 */
sev_status_t sev_cert_init(sev_cert_t *cert);

/**
 * Generate and sign a certificate.
 */
sev_status_t sev_cert_create(sev_cert_t *cert, const sev_cert_pubkey_t *pubkey,
                             const sev_cert_keypair_t *signing_key);

/**
 * Validate the signature (XXX and possibly other things) on the
 * certificate.
 */
sev_status_t sev_cert_validate(const sev_cert_t *cert,
                               const sev_cert_pubkey_t *signing_key);

#endif /* SEV_CERT_H */
