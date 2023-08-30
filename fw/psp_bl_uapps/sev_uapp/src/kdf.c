// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include "kdf.h"
#include "sev_hal.h"

sev_status_t bl_kdf_derive( uint8_t *key_out, size_t key_out_length,
                            const uint8_t *key_in, size_t key_in_length,
                            const uint8_t *label, size_t label_length,
                            const uint8_t *context, size_t context_length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_hal_key_derive_t params;

    if (!key_out || key_out_length == 0 || !label || label_length == 0 ||
        !context || context_length == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    params.key_out = key_out;
    params.key_out_length = key_out_length;
    params.key_in = key_in;
    params.key_in_length = key_in_length;
    params.label = label;
    params.label_length = label_length;
    params.context = context;
    params.context_length = context_length;

    status = sev_hal_key_derive(&params);

end:
    return status;
}
