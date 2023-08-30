// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef KDF_H
#define KDF_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

/**
 * Implements the KDF in Counter Mode defined in section 5.1 of NIST
 * SP 800-108.
 *
 * 'context': a one-time use nonce or context value, can be zero
 *
 * 'key_in': may be NULL, if so, derive the key from PSP fused AES key;
 *
 * 'label': null terminated string describing key, no rules
 *
 * All other pointers must not be 'NULL'.
 *
 * The PRF used is the HMAC-SHA256 implementation in this firmware.
 */
sev_status_t bl_kdf_derive(uint8_t *key_out, size_t key_out_length,
                           const uint8_t *key_in, size_t key_in_length,
                           const uint8_t *label, size_t label_length,
                           const uint8_t *context, size_t context_length);

#endif /* KDF_H */
