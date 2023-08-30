// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "cipher.h"
#include "hmac.h"
#include "kdf.h"
#include "secure_ops.h"
#include "sev_hal.h"
#include "sev_persistent.h"
#include "sev_wrap.h"
#include "x86_copy.h"

#define SEV_PERSISTENT_ENCRYPTION_LABEL ("sev-persistent-encryption")
#define SEV_PERSISTENT_INTEGRITY_LABEL  ("sev-persistent-integrity")

#define SPI_RETRY                       (8)
#define SPI_BYTE_ERASED_VAL             (0xFF)

/* Used when using system memory instead of SPI flash/eeprom. */
#define ERASE_CHUNK_SIZ                 (256)
#define CHUNKS_PER_BLOCK        (SEV_PERSISTENT_BLOCK_SIZE / ERASE_CHUNK_SIZ)
#define TOTAL_NR_CHUNKS         (SEV_PERSISTENT_NR_BLOCKS * CHUNKS_PER_BLOCK)

static cipher_aes_key_t     g_persistent_aes_key      = {0};
static uint8_t              g_persistent_hmac_key[16] = {0};
static bool                 g_persistent_initialized  = false;

/**
 * Note: moved from .bss to zero_init once section.
 */
static struct persistent_scratch
{
    sev_persistent_store_t  save;
    sev_persistent_store_t  retrieve;
    sev_persistent_t        readback;
} scratch  __attribute__((section ("init_once"), zero_init));


/**
 * Init the interface
 */
sev_status_t sev_persistent_store_init(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t context;

    /*
     * This context can be used to differentiate different derived keys with
     * the same label. For example, we could associate context with API version,
     * so that derived keys can be associated with the API version. This would
     * restrict the SEV persistent data to be only accessible by firmware
     * associated with a specific API version.
     */
    context = 0;

    g_persistent_initialized = true;

    status = bl_kdf_derive((uint8_t *)(&g_persistent_aes_key),
                           sizeof(g_persistent_aes_key),
                           NULL,
                           0,
                           SEV_PERSISTENT_ENCRYPTION_LABEL,
                           sizeof(SEV_PERSISTENT_ENCRYPTION_LABEL),
                           (const uint8_t *)&context,
                           sizeof(context));
    if (status != SEV_STATUS_SUCCESS)
        goto exit_deinit;

    status = bl_kdf_derive(g_persistent_hmac_key,
                           sizeof(g_persistent_hmac_key),
                           NULL,
                           0,
                           SEV_PERSISTENT_INTEGRITY_LABEL,
                           sizeof(SEV_PERSISTENT_INTEGRITY_LABEL),
                           (const uint8_t *)&context,
                           sizeof(context));
exit_deinit:
    if (status != SEV_STATUS_SUCCESS)
        (void)sev_persistent_store_deinit();
    return status;
}

/**
 * De-init the interface
 */
sev_status_t sev_persistent_store_deinit(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    secure_memzero(&g_persistent_aes_key, sizeof(g_persistent_aes_key));
    secure_memzero(g_persistent_hmac_key, sizeof(g_persistent_hmac_key));
    g_persistent_initialized = false;

    return status;
}

/**
 * Delete the persistent data
 */
sev_status_t sev_persistent_store_delete(uint64_t dev_addr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t num_blocks = 0;
    uint64_t tmp_addr   = 0;
    uint8_t  chunk[ERASE_CHUNK_SIZ];
    uint32_t chunk_cnt  = 0;

    if (!dev_addr)
    {
        /* SPI: calculate at run time how many blocks need to be erased */
        num_blocks = (sizeof(sev_persistent_store_t))/SEV_PERSISTENT_BLOCK_SIZE;
        if (0 != ((sizeof(sev_persistent_store_t))%SEV_PERSISTENT_BLOCK_SIZE))
        {
            num_blocks++;
        }
        status = sev_hal_persistent_erase(num_blocks);  /* SPI storage. */
    }
    else
    {
        /*
         * Using system memory for storage. Ref: INIT_EX command. 'Erase' the
         * entire storage area to all FF's like the SPI device. Since
         * gpSevScratchBuf is used by some callers, copy from small buffer
         * on stack instead.
         */
        memset(chunk, SPI_BYTE_ERASED_VAL, ERASE_CHUNK_SIZ);
        tmp_addr = dev_addr;
        chunk_cnt = TOTAL_NR_CHUNKS;
        for (uint32_t i = 0; i < chunk_cnt; i++)
        {
            status = copy_to_x86(tmp_addr, &chunk, ERASE_CHUNK_SIZ);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            tmp_addr += ERASE_CHUNK_SIZ;
        }
    }

end:
    return status;
}

/**
 * Retrieve the persistent data
 */
sev_status_t sev_persistent_store_retrieve(uint64_t dev_addr,
                                           sev_persistent_t *persistent)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t size = sizeof(*persistent);
    const uint32_t empty = 0xFFFFFFFF;
    size_t retry = SPI_RETRY;

    if (!persistent)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Read the data to scratch area */
    do
    {
        retry--;
        if (!dev_addr)
        {
            /* SPI storage. */
            status = sev_hal_persistent_read(&scratch.retrieve,
                                             sizeof(scratch.retrieve));
        }
        else
        {
            /* System memory. */
            status = copy_from_x86(dev_addr, &scratch.retrieve,
                                   sizeof(scratch.retrieve));
            retry = 0;  /* No retry for system memory access. */
        }
    } while (status != SEV_STATUS_SUCCESS && retry > 0);

    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_HARDWARE_PLATFORM;
        goto end;
    }

    /* Check if the persistent store is empty, based upon the first 4 bytes */
    if (memcmp(&scratch.retrieve, &empty, sizeof(empty)) == 0)
    {
        status = ERR_SECURE_DATA_NON_EXIST;
        goto end;
    }

    if (!g_persistent_initialized)
    {
        status = sev_persistent_store_init();
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Unwrap */
    status = sev_secure_data_unwrap(&g_persistent_aes_key,
                                    g_persistent_hmac_key,
                                    sizeof(g_persistent_hmac_key),
                                    (uint8_t *)&scratch.retrieve,
                                    sizeof(scratch.retrieve),
                                    (uint8_t *)persistent, &size);

end:
    return status;
}

/**
 * Save the persistent data
 */
sev_status_t sev_persistent_store_save(uint64_t dev_addr,
                                       const sev_persistent_t *persistent)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    hmac_sha256_t hmac;
    size_t size = sizeof(sev_persistent_store_t);
    size_t retry = SPI_RETRY;

    if (!persistent)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&hmac, 0, sizeof(hmac));

    if (!g_persistent_initialized)
    {
        status = sev_persistent_store_init();
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Wrap */
    status = sev_secure_data_wrap(&g_persistent_aes_key,
                                  g_persistent_hmac_key,
                                  sizeof(g_persistent_hmac_key),
                                  (uint8_t *)persistent, sizeof(*persistent),
                                  (uint8_t *)&scratch.save, &size, &hmac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    do {
        retry--;

        /* The SPI-ROM must be erased before we can write new data */
        status = sev_persistent_store_delete(dev_addr);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Write the data from the scratch area */
        if (!dev_addr)
        {
            /* SPI storage. */
            sev_hal_persistent_write(&scratch.save, sizeof(scratch.save));
        }
        else
        {
            /* System memory. */
            copy_to_x86(dev_addr, &scratch.save, sizeof(scratch.save));
            retry = 0;  /* No retry for system memory access. */
        }

        /* Read back the data to ensure that it was stored properly */
        status = sev_persistent_store_retrieve(dev_addr, &scratch.readback);
    } while (status != SEV_STATUS_SUCCESS && retry > 0);

    if (status != SEV_STATUS_SUCCESS)
    {
        /* The data was corrupted, so leave the SPI-ROM in a known-good state */
        sev_persistent_store_delete(dev_addr);
        status = SEV_STATUS_HARDWARE_PLATFORM;
    }

end:
    return status;
}

