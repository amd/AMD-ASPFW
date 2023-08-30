// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_PERSISTENT_H
#define SEV_PERSISTENT_H

#include <stddef.h>
#include <stdint.h>

#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "sev_errors.h"

#define SEV_PERSISTENT_NR_BLOCKS        (8)
#define SEV_PERSISTENT_BLOCK_SIZE       (4*1024)
#define SEV_PERSISTENT_STORE_MAX_SIZE   ((SEV_PERSISTENT_NR_BLOCKS)*(SEV_PERSISTENT_BLOCK_SIZE))

/**
 * "Device address" of 0 means use SPI storage. Otherwise,
 * it is the physical address of system memory. Ref: INIT EX command.
 */
#define SEV_PERSISTENT_SPI_DEV          (0ULL)

typedef struct sev_persistent_store
{
    uint8_t            cdata[sizeof(sev_persistent_t)]; // ciphertext for SEV persistent data
    hmac_sha256_t      hmac;                            // plaintext
    cipher_aes_iv_t    iv;                              // plaintext. stored at end for backwards compatibility
} sev_persistent_store_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_persistent_store_t) <= SEV_PERSISTENT_STORE_MAX_SIZE, sev_persistent_h);

/**
 * Init the interface
 */
sev_status_t sev_persistent_store_init(void);

/**
 * De-init the interface
 */
sev_status_t sev_persistent_store_deinit(void);

/**
 * Retrieve the persistent data
 */
sev_status_t sev_persistent_store_retrieve(uint64_t dev_addr,
                                           sev_persistent_t *persistent);

/**
 * Save the persistent data
 */
sev_status_t sev_persistent_store_save(uint64_t dev_addr,
                                       const sev_persistent_t *persistent);

/**
 * Delete the persistent data
 */
sev_status_t sev_persistent_store_delete(uint64_t dev_addr);

#endif /* SEV_PERSISTENT_H */
