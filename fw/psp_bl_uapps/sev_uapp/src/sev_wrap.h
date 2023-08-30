// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_WRAP_H
#define SEV_WRAP_H

#include <stddef.h>
#include <stdint.h>

#include "cipher.h"
#include "hmac.h"
#include "sev_errors.h"

/**
 *   Wrap the data
 *
 *   algorithm: secure data is encrypted and HMAC'd as following.
 *       IV is the initial AES counter,
 *       KE is the encryption key,
 *       KI is the integrity key,
 *       M is the plaintext data, then we'd produce C:
 *
 *          C = { IV, AES-CTR(M; KE, IV), HMAC(AES-CTR(M; KE, IV); KI) }
 *
 *   'src': must be 16 bytes aligned.
 *   'dest': must be 16 bytes aligned.
 *
 *   support In Place operation
 */
sev_status_t sev_secure_data_wrap(const cipher_aes_key_t *aes_key,
                                  uint8_t *hmac_key, size_t hmac_key_len,
                                  uint8_t *src, size_t src_len,
                                  uint8_t *dest, size_t *dest_len,
                                  hmac_sha256_t *hmac);

/**
 *   Unwrap the data
 *
 *   'src': must be 16 bytes aligned.
 *   'dest': must be 16 bytes aligned.
 *
 *   support In Place operation
 */
sev_status_t sev_secure_data_unwrap(const cipher_aes_key_t *aes_key,
                                    uint8_t *hmac_key, size_t hmac_key_len,
                                    uint8_t *src, size_t src_len,
                                    uint8_t *dest, size_t *dest_len);

#endif /* SEV_WRAP_H */
