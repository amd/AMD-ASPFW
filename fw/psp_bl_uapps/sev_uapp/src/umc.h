// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_UAPP_UMC_H
#define SEV_UAPP_UMC_H

#include <stddef.h>
#include <stdint.h>

#include "sev_status.h"

/**
 * Copies 'size' bytes from 'key' into the key slot for 'asid' in all UMCs on
 * each die.
 */
sev_status_t set_umc_key(uint32_t asid, const uint8_t *seed, size_t size);

/**
 * Checks the state of the memory encryption bits in the UMC configuration
 * registers. Returns true if memory encryption is enabled in the UMC, and
 * false otherwise.
 */
bool umc_encryption_enabled(void);

#endif /* SEV_UAPP_UMC_H */
