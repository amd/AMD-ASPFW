// Copyright(C) 2021 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_scmd.h"

/**
 * Levels for TMR calls
 *     x -> sev_tmr.c -> sev_hal.c -> tmr_cache.c -> df_regs.c
 */

/* Note that this function takes a base address and length/size, not base and end addresses */
sev_status_t enable_tmr(uint8_t tmr_num, uint64_t base, uint64_t size, uint32_t flags)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t trust_level = 0;       /* Don't care about trust level, not used */

    /* Setup the TMR on this die */
    status = sev_hal_set_tmr(tmr_num, base, (size - 1), trust_level, flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Only send slave commands if this is the master die */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        /* Setup the TMR on slave dies as well */
        sev_scmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_ID_SET_TMR;
        cmd.scmd.set_tmr.tmr_nr = tmr_num;
        cmd.scmd.set_tmr.base = base;
        cmd.scmd.set_tmr.size = (uint32_t)((size - 1ULL) >> TMR_X86_PHYS_ADDR_SHIFT);
        cmd.scmd.set_tmr.trust_level = trust_level;
        cmd.scmd.set_tmr.flags = flags;
        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

end:
    return status;
}

sev_status_t modify_tmr_flags(uint8_t tmr_num, uint32_t flags, bool set)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_scmd_t cmd;

    /* This function is designed to read-modify-write the TmrCtl register without
       disabling it first. It will set/clear the flag bits */
    status = sev_hal_modify_tmr_flags(tmr_num, flags, set);
    if (status != SEV_STATUS_SUCCESS)
           goto end;

    /* Only send slave commands if this is the master die */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        /* Setup the TMR on slave dies as well */
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_ID_MODIFY_TMR_FLAGS;
        cmd.scmd.modify_tmr.tmr_nr = tmr_num;
        cmd.scmd.modify_tmr.flags = flags;
        cmd.scmd.modify_tmr.set = set;

        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

end:
    return status;
}

sev_status_t disable_tmr(uint8_t tmr_num)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    sev_scmd_t cmd;

    /* Release the TMR on this die */
    status = sev_hal_reset_tmr(tmr_num);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Release the TMR on slave dies */
    memset(&cmd, 0, sizeof(cmd));
    cmd.id = SEV_SCMD_ID_RESET_TMR;
    cmd.scmd.reset_tmr.tmr_nr = tmr_num;

    status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}
