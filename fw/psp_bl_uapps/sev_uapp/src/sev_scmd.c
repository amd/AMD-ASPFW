// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "secure_ops.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_plat.h"
#include "sev_scmd.h"
#include "pspsmc.h"

sev_status_t sev_scmd_df_flush(sev_scmd_t *ignored)
{
    return sev_hal_df_write_flush();
}

sev_status_t sev_scmd_set_tmr(sev_scmd_t *cmd)
{
    uint64_t tmr_size = 0;
    if (cmd == NULL)
    {
        return ERR_INVALID_PARAMS;
    }

    tmr_size = (uint64_t)(cmd->scmd.set_tmr.size);
    tmr_size <<= TMR_X86_PHYS_ADDR_SHIFT;

    /* Setup the TMR on this die */
    return sev_hal_set_tmr(cmd->scmd.set_tmr.tmr_nr, cmd->scmd.set_tmr.base,
                           tmr_size, cmd->scmd.set_tmr.trust_level,
                           cmd->scmd.set_tmr.flags);
}

sev_status_t sev_scmd_reset_tmr(sev_scmd_t *cmd)
{
    return cmd != NULL ? sev_hal_reset_tmr(cmd->scmd.reset_tmr.tmr_nr)
                       : ERR_INVALID_PARAMS;
}

sev_status_t sev_scmd_enable_tmr(sev_scmd_t *cmd)
{
    return cmd != NULL ? sev_hal_enable_tmr(cmd->scmd.enable_tmr.tmr_nr)
                       : ERR_INVALID_PARAMS;
}

sev_status_t sev_scmd_get_cuk(sev_scmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t cuk[2*CUK_SIZE];
    uint8_t *pCukAligned = NULL;
    size_t cuk_size = CUK_SIZE;

    do {
        pCukAligned = (uint8_t *)ALIGN_TO_32_BYTES(cuk);
        status = sev_hal_get_chip_unique_key(pCukAligned, &cuk_size);
        if (status != SEV_STATUS_SUCCESS)
            break;
        memcpy(gpDram->p1_info.p1cuk, pCukAligned, cuk_size);
        sev_hal_clean_dcache((uint32_t)gpDram->p1_info.p1cuk, sizeof(gpDram->p1_info.p1cuk));
    } while (0);

    /* Clean up */
    secure_memzero(pCukAligned, cuk_size);

    return status;
}

sev_status_t sev_scmd_get_apicid(sev_scmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (gCurrentDieID != SEV_SLAVE_SOCKET_MASTER_DIE)
        return status;

    do {
        gpDram->p1_info.activate_ex_enable = gSev.activate_ex_enable;
        memcpy(gpDram->p1_info.apic_ids, gSev.apic_ids,
               sizeof(gpDram->p1_info.apic_ids));
        sev_hal_clean_dcache((uint32_t)&gpDram->p1_info, sizeof(gpDram->p1_info));
    } while (0);

    return status;
}

sev_status_t sev_scmd_modify_tmr_flags(sev_scmd_t *cmd)
{
    if (cmd == NULL)
    {
        return ERR_INVALID_PARAMS;
    }

    return sev_hal_modify_tmr_flags(cmd->scmd.modify_tmr.tmr_nr, cmd->scmd.modify_tmr.flags,
                                    cmd->scmd.modify_tmr.set);
}

sev_status_t sev_scmd_tlb_flush(sev_scmd_t *ignored)
{
    return sev_hal_flush_tlb();
}

sev_status_t sev_scmd_rd_sz_wrbkinvd(sev_scmd_t *cmd)
{
    return sev_hal_set_misc_read_sized_wrbkinvd(cmd->scmd.sz_wrbkinvd.enable);
}

sev_status_t sev_scmd_df_acquire(sev_scmd_t *ignored)
{
    return sev_hal_df_acquire();
}

sev_status_t sev_scmd_df_release(sev_scmd_t *ignored)
{
    return sev_hal_df_release();
}

sev_status_t sev_scmd_get_mcm_info(sev_scmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (gCurrentDieID != SEV_SLAVE_SOCKET_MASTER_DIE)
        return status;

    do {
        /* Get the data from BL for this socket */
        status = sev_hal_get_mcm_info(&gPersistent);
        if (status != SEV_STATUS_SUCCESS)
            break;

        /* Copy the data to the shared DRAM so P0 can see it */
        gpDram->p1_info.socket_info = gPersistent.socket_info[gCurrentDieID];

        sev_hal_clean_dcache((uint32_t)&gpDram->p1_info, sizeof(gpDram->p1_info));
    } while (0);

    return status;
}

sev_status_t sev_scmd_check_msrs(sev_scmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    do {
        status = sev_hal_check_msrs(gpDram->p1_info.msrs);
        if (status != SEV_STATUS_SUCCESS)
            break;

    } while (0);

    /* Always flush the msrs informatio cache */
    sev_hal_clean_dcache((uint32_t)gpDram->p1_info.msrs, sizeof(gpDram->p1_info.msrs));

    return status;
}

sev_status_t sev_scmd_set_msr(sev_scmd_t *cmd)
{
    if (Svc_SendPspSmuMsg(PSPSMC_MSG_UpdateC001MSR, cmd->scmd.set_msr.val, NULL, 0) != BL_OK)
        return SEV_STATUS_HARDWARE_PLATFORM;

    return SEV_STATUS_SUCCESS;
}
