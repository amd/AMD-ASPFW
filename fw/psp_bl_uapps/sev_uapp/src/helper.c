// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>

#include "commontypes.h"
#include "helper.h"

bool is_empty(const void *object, size_t size)
{
    bool rc = true;
    size_t i = 0;
    const uint8_t *buffer = (const uint8_t *)object;

    if (!object)
    {
        rc = false;
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        if (buffer[i] != 0)
        {
            rc = false;
            goto end;
        }
    }

end:
    return rc;
}

sev_status_t reverse_bytes(uint8_t *bytes, size_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t *start = bytes;
    uint8_t *end = bytes + size - 1;

    if (!bytes)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    while (start < end)
    {
        uint8_t byte = *start;
        *start = *end;
        *end = byte;
        start++;
        end--;
    }

end:
    return status;
}
