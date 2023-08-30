// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_persistent.h"
#include "sev_persistent_utest.h"
#include "sev_plat.h"
#include "sev_trace.h"

sev_status_t sev_persistent_store_utest(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_persistent_t *persistent = NULL;
    size_t i = 0;
    uint8_t random = 0;
    uint8_t *buf = NULL;

    persistent = (sev_persistent_t *)gpSevScratchBuf;

    status = sev_persistent_store_delete(SEV_PERSISTENT_SPI_DEV); /* use SPI */
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    // Generate random data for testing
    status = sev_hal_trng(&random, sizeof(random));
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    memset(persistent, random, sizeof(*persistent));
    status = sev_persistent_store_save(SEV_PERSISTENT_SPI_DEV, persistent);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    memset(persistent, 0, sizeof(*persistent));
    status = sev_persistent_store_retrieve(SEV_PERSISTENT_SPI_DEV, persistent);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    // Check the result
    buf = (uint8_t *)persistent;
    for (i = 0; i < sizeof(*persistent); i++)
    {
        if (buf[i] != random)
        {
            status = ERR_SECURE_DATA_VALIDATION;
            (void)sev_persistent_store_delete(SEV_PERSISTENT_SPI_DEV); /* use SPI */
            goto end;
        }
    }

    status = sev_persistent_store_delete(SEV_PERSISTENT_SPI_DEV); /* use SPI */
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        SEV_TRACE("sev_persistent_store_utest failed...\n");
        SEV_TRACE_EX(status, 0, 0, 0);
    }
    else
    {
        SEV_TRACE("sev_persistent_store_utest succeed!\n");
    }

    return status;
}
