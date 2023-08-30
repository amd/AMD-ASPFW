// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_SCMD_H
#define SEV_SCMD_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

/**
 * How to use this file:
 * The slaves commands are called by the master using sev_hal_master_to_slave
 * to either get data from the slaves, or pass data to the slaves. Add your
 * command in sev_scmd.* and in sev_dispatch.* (the translation table that
 * turns the cmd.id param into (and calls) the corresponding function in
 * sev_scmd.c)
 */
typedef enum sev_scmd_id
{
    SEV_SCMD_ID_DF_FLUSH         = 0x0001,
    SEV_SCMD_ID_SET_TMR          = 0x0002,
    SEV_SCMD_ID_RESET_TMR        = 0x0003,
    SEV_SCMD_ID_ENABLE_TMR       = 0x0004,
    SEV_SCMD_ID_GET_CUK          = 0x0005,
    SEV_SCMD_ID_GET_APICID       = 0x0006,
    SEV_SCMD_ID_MODIFY_TMR_FLAGS = 0x0007,
    SEV_SCMD_ID_TLB_FLUSH        = 0x0008,
    SEV_SCMD_ID_RD_SZ_WRBKINVD   = 0x000B,
    SEV_SCMD_ID_DF_ACQUIRE       = 0x000C,
    SEV_SCMD_ID_DF_RELEASE       = 0x000D,
    SEV_SCMD_GET_MCM_INFO        = 0x000E,
    SEV_SCMD_CHECK_MSRS          = 0x000F,
    SEV_SCMD_SET_MSR             = 0x0010,
    /** XXX more to be added **/

    SEV_SCMD_ID_LIMIT,
} sev_scmd_id_t;

typedef struct sev_scmd_set_tmr
{
    uint64_t    base;
    size_t      size;
    uint8_t     tmr_nr;
    uint8_t     trust_level;
    uint32_t    flags;
} sev_scmd_set_tmr_t;

typedef struct sev_scmd_tmr_ops
{
    uint8_t     tmr_nr;
    uint32_t    flags;
    bool        set;
} sev_scmd_tmr_ops_t;

typedef struct sev_scmd_df_ccm_privilege
{
    uint8_t     ccd;
} sev_scmd_df_ccm_privilege_t;

typedef struct sev_scmd_rd_sz_wrbkinvd
{
    bool        enable;
} sev_scmd_rd_sz_wrbkinvd_t;

typedef struct sev_scmd_set_msr
{
    uint32_t    val;
} sev_scmd_set_msr_t;

/**
 * NOTE: This structure must be small enough to fit into the P2P message
 * buffer, which is currently 32 bytes!
 */
typedef struct sev_scmd
{
    sev_scmd_id_t   id;
    uint8_t         die;

    union
    {
        sev_scmd_set_tmr_t          set_tmr;
        sev_scmd_tmr_ops_t          reset_tmr;
        sev_scmd_tmr_ops_t          enable_tmr;
        sev_scmd_tmr_ops_t          modify_tmr;
        sev_scmd_rd_sz_wrbkinvd_t   sz_wrbkinvd;
        sev_scmd_set_msr_t          set_msr;
    } scmd;
} sev_scmd_t;

sev_status_t sev_scmd_df_flush(sev_scmd_t *ignored);
sev_status_t sev_scmd_set_tmr(sev_scmd_t *cmd);
sev_status_t sev_scmd_reset_tmr(sev_scmd_t *cmd);
sev_status_t sev_scmd_enable_tmr(sev_scmd_t *cmd);
sev_status_t sev_scmd_get_cuk(sev_scmd_t *ignored);
sev_status_t sev_scmd_get_apicid(sev_scmd_t *ignored);
sev_status_t sev_scmd_modify_tmr_flags(sev_scmd_t *cmd);
sev_status_t sev_scmd_tlb_flush(sev_scmd_t *cmd);
sev_status_t sev_scmd_rd_sz_wrbkinvd(sev_scmd_t *cmd);
sev_status_t sev_scmd_df_acquire(sev_scmd_t *ignored);
sev_status_t sev_scmd_df_release(sev_scmd_t *ignored);
sev_status_t sev_scmd_get_mcm_info(sev_scmd_t *ignored);
sev_status_t sev_scmd_check_msrs(sev_scmd_t *ignored);
sev_status_t sev_scmd_set_msr(sev_scmd_t *cmd);

#endif /* SEV_SCMD_H */
