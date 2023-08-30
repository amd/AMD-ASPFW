// Copyright(C) 2017-2018 Advanced Micro Devices, Inc. All rights reserved.

#ifndef TMR_CACHE_H
#define TMR_CACHE_H

#include <stddef.h>
#include <stdint.h>

#include "df_regs.h"
#include "sev_errors.h"

typedef struct tmr
{
    uint64_t base;
    uint64_t limit;
    uint32_t control;
    uint32_t trust_lvl;
} tmr_t;

typedef struct tmr_cache
{
    uint32_t present_mask;
    tmr_t    tmr[TMR_NR_MAX+1];
} tmr_cache_t;


/**
 * Initialize the TMR cache.
 */
void tmr_cache_init(void);

/**
 * Clear the cached register values for the given TMR. Future reads/writes will
 * re-populate the cache.
 *
 * Parameters:
 *     tmr : [in]  TMR number (0-7)
 */
sev_status_t tmr_cache_invalidate(size_t tmr_nr);

/**
 * Read the cached values of TMR registers. If the given TMR has not been
 * cached, read directly from the data fabric and cache the results.
 *
 * Parameters:
 *     tmr       : [in]  TMR number (0-7)
 *     base      : [out] base address of trusted region
 *     limit     : [out] limit address of trusted region
 *     control   : [out] control flags
 *     trust_lvl : [out] bit mask of entities allowed to access this trusted region
 *
 */
sev_status_t tmr_cache_read(size_t tmr_nr, uint64_t *base, uint64_t *limit,
                            uint32_t *control, uint32_t *trust_lvl);

/**
 * Write directly to the data fabric and update the values in the cache.
 *
 * Parameters:
 *     tmr       : [in] TMR number (0-7)
 *     base      : [in] base address of trusted region
 *     limit     : [in] limit address of trusted region
 *     control   : [in] control flags
 *     trust_lvl : [in] bit mask of entities allowed to access this trusted region
 */
sev_status_t tmr_cache_write(size_t tmr_nr, uint64_t base, uint64_t limit,
                             uint32_t control, uint32_t trust_lvl);

/**
 * Read modify write the control register to set/clear bits. Update the tmr
 * cache afterwards.
 *
 * Parameters:
 *     tmr       : [in] TMR number (0-7)
 *     flags     : [in] TMR CTRL bits to set/clear
 *     set       : [in] to set or clear the bits/flags
 */
sev_status_t tmr_cache_modify_flags(size_t tmr_nr, uint32_t flags, bool set);

#endif /* TMR_CACHE_H */
