// Copyright(C) 2017-2018 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "df_regs.h"
#include "sev_globals.h"
#include "tmr_cache.h"

static tmr_cache_t *tmr_cache = &gPersistent.tmr_cache;

bool tmr_cache_is_present(size_t tmr)
{
    return tmr <= TMR_NR_MAX ? tmr_cache->present_mask & (1ul << tmr) : false;
}

void tmr_cache_init(void)
{
    memset(tmr_cache, 0, sizeof(*tmr_cache));
}

sev_status_t tmr_cache_invalidate(size_t tmr_nr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    tmr_t *cache = &tmr_cache->tmr[tmr_nr];

    if (tmr_nr > TMR_NR_MAX)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(cache, 0, sizeof(*cache));
    tmr_cache->present_mask &= ~(1ul << tmr_nr);

end:
    return status;
}

sev_status_t tmr_cache_read(size_t tmr_nr, uint64_t *base, uint64_t *limit,
                            uint32_t *control, uint32_t *trust_lvl)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    tmr_t *cache = &tmr_cache->tmr[tmr_nr];

    if (tmr_nr > TMR_NR_MAX)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (!tmr_cache_is_present(tmr_nr))
    {
        /* Call to disable DF C State, required to access TMR */
        status = df_access_lock();
         if (status != SEV_STATUS_SUCCESS)
             goto end;
        status = get_tmr_info(tmr_nr, &cache->base, &cache->limit,
                              &cache->trust_lvl, &cache->control);
        /* Enable Df C State, preserve the status */
        df_access_unlock();
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        tmr_cache->present_mask |= 1ul << tmr_nr;
    }

    if (base)
        *base = cache->base;
    if (limit)
        *limit = cache->limit;
    if (control)
        *control = cache->control;
    if (trust_lvl)
        *trust_lvl = cache->trust_lvl;

end:
    return status;
}

sev_status_t tmr_cache_write(size_t tmr_nr, uint64_t base, uint64_t limit,
                             uint32_t control, uint32_t trust_lvl)
{
    sev_status_t status = SEV_STATUS_HARDWARE_PLATFORM;
    tmr_t *cache = &tmr_cache->tmr[tmr_nr];

    if (tmr_nr > TMR_NR_MAX)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = set_tmr(tmr_nr, base, limit, control, trust_lvl);
    if (status != SEV_STATUS_SUCCESS)
    {
        /*
         * We can't be sure which registers were written before the failure,
         * so invalidate this TMR. Future reads will re-populate the cache
         * from the fabric.
         */
        (void)tmr_cache_invalidate(tmr_nr);
        goto end;
    }

    cache->base = base;
    cache->limit = limit;
    cache->control = control;
    cache->trust_lvl = trust_lvl;
    tmr_cache->present_mask |= 1ul << tmr_nr;

end:
    return status;
}

sev_status_t tmr_cache_modify_flags(size_t tmr_nr, uint32_t flags, bool set)
{
    sev_status_t status = SEV_STATUS_HARDWARE_PLATFORM;
    tmr_t *cache = &tmr_cache->tmr[tmr_nr];

    if (tmr_nr > TMR_NR_MAX)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = set_tmr_modify_flags(tmr_nr, flags, set);
    if (status != SEV_STATUS_SUCCESS)
    {
        /*
         * We can't be sure which registers were written before the failure,
         * so invalidate this TMR. Future reads will re-populate the cache
         * from the fabric.
         */
        (void)tmr_cache_invalidate(tmr_nr);
        goto end;
    }

    /* Update the tmr cache info */
    status = get_tmr_info(tmr_nr, &cache->base, &cache->limit,
                          &cache->trust_lvl, &cache->control);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    tmr_cache->present_mask |= 1ul << tmr_nr;

end:
    return status;
}
