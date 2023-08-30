// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef ECDSA_H
#define ECDSA_H

#include <stddef.h>
#include <stdint.h>

#include "ecc.h"
#include "sev_errors.h"

typedef struct ecdsa_sig
{
    ecc_scalar_t r;
    ecc_scalar_t s;
} ecdsa_sig_t;

/**
 * Generates a new key pair using the RNG HAL.
 *
 * This function generate enough random data using the RNG and then
 * calls 'ecc_keypair_generate_rdata()'.
 *
 * \param [out] keypair  generated keypair
 */
sev_status_t ecdsa_keypair_generate(ecc_keypair_t *keypair);

/**
 * Copies the public key out of the 'keypair' object into the 'pubkey'
 * object.
 *
 * We do this so the higher level code never has to unwrap and access
 * the raw data of the keypair (and accidentally copying out the wrong
 * part of the keypair).
 */
sev_status_t ecdsa_export_pubkey(ecc_pubkey_t *pubkey, const ecc_keypair_t *keypair);

/**
   Sign the digest of a message using the random data provided in
   'rdata'.

   This function _does not_ calculate the hash of the message. It is
   up to the caller to calculate the digest.

   \warning Passing the actual message and not the digest into this
   function will result in an incorrect signature and will likely lead
   to vulnerabilities.

   The signing algorithm is specified by FIPS 186-4, section
   6.4. However, very annoyingly, this section only refers to the ANSI
   X9.62 standard, which is not immediately available. Therefore,
   we'll assume that [RFC 6979][1] matches X9.62 exactly.

   [1]: https://tools.ietf.org/html/rfc6979

   The algorithm is reproduced here with edits.

   'rdata' is transformed into an integer modulo 'n' using the
   'bits2int' (see [RFC 6979][1] for further details) transform and an
   extra modular reduction:

   ~~~
   h = bits2int(H(m)) mod q
   ~~~

   A random value modulo 'n', dubbed 'k', is generated. That value shall
   not be '0'; hence, it lies in the ['1', 'q-1'] range.

   A value 'r' (modulo 'n') is computed from 'k' and the key
   parameters. The point 'kG' is computed; its X coordinate (a member
   of the field over which the curve is defined) is converted to an
   integer, which is reduced modulo 'n', yielding 'r'.

   If 'r' turns out to be zero, the function returns an error. This
   should _never_ happen with secure random data, but we must check in
   case we're running tests with degenerate data.

   The value 's' (modulo 'n') is computed:

   ~~~
   s = (h+x*r) * (h^(-1)) mod q
   ~~~

   The pair (r, s) is the signature.

   \param [in]  keypair  the signing key pair
   \param [out] sig      the generated signature
   \param [in]  digest   the digest of the message
   \param [in]  length   the length of 'digest' in bytes
   \param [in]  rdata    secure random data
   \param [in]  rlength  length of 'rdata' in bytes
 */
sev_status_t ecdsa_sign_rdata(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                              const uint8_t *digest, size_t length,
                              const uint8_t *rdata, size_t rlength);

/**
 * Sign the digest of a message using RNG HAL.
 *
 * This function generate enough random data using the RNG and then
 * calls 'ecdsa_keypair_sign_rdata()'.
 *
 * \see 'ecdsa_keypair_sign_rdata()'
 *
 * \param [out] sig      the generated signature
 * \param [in]  keypair  the signing key pair
 * \param [in]  digest   the digest of the message
 * \param [in]  length   the length of 'digest' in bytes
 */
sev_status_t ecdsa_sign(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                        const uint8_t *digest, size_t length);

/**
 * Sign a message using ECC DSA.
 *
 * This function generates a random 'k' and then
 * calls 'ecdsa_keypair_sign_rdata()'.
 *
 * \see 'ecdsa_keypair_sign_rdata()'
 *
 * \param [out] sig      the generated signature
 * \param [in]  keypair  the signing key pair
 * \param [in]  msg      the message
 * \param [in]  length   the length of 'msg' in bytes
 * \param [in]  algo     the algorithm type
 */
sev_status_t ecdsa_sign_msg(ecdsa_sig_t *sig, const ecc_keypair_t *keypair,
                            const uint8_t *msg, size_t length, const uint32_t algo);

/**
 * Verifies the signature on a digest.
 *
 * Note that this function does __not__ take the message itself
 * as a parameter. It is up to the caller to generate the correct
 * digest (probably SHA-256) and provide it.
 *
 */
sev_status_t ecdsa_verify(const ecdsa_sig_t *sig, const ecc_pubkey_t *pubkey,
                          const uint8_t *digest, size_t length);

/**
 * Verifies the signature on a digest.
 *
 * Note that this function does __not__ take the message itself
 * as a parameter. It is up to the caller to generate the correct
 * digest (probably SHA-256) and provide it.
 *
 */
sev_status_t ecdsa_verify_msg(const ecdsa_sig_t *sig, const ecc_pubkey_t *pubkey,
                              const uint8_t *msg, size_t length, const uint32_t algo);

#endif /* ECDSA_H */
