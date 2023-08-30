// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef ECDH_H
#define ECDH_H

#include <stddef.h>
#include <stdint.h>

#include "ecc.h"
#include "sev_errors.h"

/**
 * Generate a key pair with the RNG HAL.
 */
sev_status_t ecdh_keypair_generate(ecc_keypair_t *keypair);

/**
 * Compute the shared secret with the ECDH key material.
 */
sev_status_t ecdh_key_agreement(const ecc_keypair_t *lkeypair,
                                const ecc_pubkey_t *rpubkey,
                                uint8_t *secret, size_t length);

#endif /* ECDH_H */
