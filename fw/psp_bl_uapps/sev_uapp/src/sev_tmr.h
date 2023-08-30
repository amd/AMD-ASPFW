// Copyright(C) 2019-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_TMR_H
#define SEV_TMR_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

/**
 * Create and enable a generic, non-SEV-ES, TMR region
 *   Input: tmr_num - Which TMR to enable
 *          base    - 64 bit start address
 *          size    - 64 bit end address
 *          flags   - TMR flags for protection
 */
sev_status_t enable_tmr(uint8_t tmr_num, uint64_t base, uint64_t size, uint32_t flags);

/**
 * Modify the TMR_CTRL flags on an enabled TMR
 */
sev_status_t modify_tmr_flags(uint8_t tmr_num, uint32_t flags, bool set);

/**
 * Release and disable the TMR region for RMP table.
 */
sev_status_t disable_tmr(uint8_t tmr_num);

#endif /* SEV_TMR_H */
