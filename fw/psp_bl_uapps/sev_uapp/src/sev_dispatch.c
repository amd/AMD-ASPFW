// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>

#include "df_regs.h"
#include "sev_dispatch.h"
#include "sev_globals.h"
#include "sev_mcmd.h"
#include "sev_plat.h"
#include "sev_rmp.h"
#include "sev_scmd.h"
#include "x86_copy.h"

#define LOCK_DF         (true)
#define CMD_BUF_WRITE   (true)

typedef enum CMD_INPUT_BUF_TYPE_E
{
    CMD_BUF_INPUT_ONLY             = 0, /* Take input only */
    CMD_BUF_OUTPUT_ONLY            = 1, /* Give output only */
    CMD_BUF_INPUT_AND_OUTPUT       = 2, /* Take input and give output */
    CMD_BUF_INPUT_AND_OUTPUT_ERROR = 3, /* Take input and give output even on error conditions */
    CMD_BUF_IGNORE                 = 4, /* Ignore the command buffer, so no need to copy it */
} CMD_INPUT_BUF_TYPE;

struct table_entry
{
    sev_status_t (*handler)(sev_t *sev, sev_mcmd_t *cmd);
    size_t cmd_size;
    bool lock_df;                 /* Should we lock (wake up) the DF for this whole command */
    bool snp_cmd_buf_enforcement; /* Does this cmd write back to the command buffer (SNP requires Firmware state) */
    CMD_INPUT_BUF_TYPE cmd_buf_type;
};

/**
 * Table of master command handlers indexed by command ID
 */
static struct table_entry master_handler_table[SEV_MCMD_ID_LIMIT] = {
    [SEV_MCMD_ID_INIT]                 = { sev_mcmd_init,                 sizeof(sev_mcmd_init_t),                  LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_SHUTDOWN]             = { sev_mcmd_shutdown,             0,                                        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SEV_MCMD_ID_PLATFORM_RESET]       = { sev_mcmd_platform_reset,       0,                                       !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SEV_MCMD_ID_PLATFORM_STATUS]      = { sev_mcmd_platform_status,      sizeof(sev_mcmd_platform_status_t),      !LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_OUTPUT_ONLY },
    [SEV_MCMD_ID_PEK_GEN]              = { sev_mcmd_pek_gen,              0,                                       !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SEV_MCMD_ID_PEK_CSR]              = { sev_mcmd_pek_csr,              sizeof(sev_mcmd_pek_csr_t),              !LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_PEK_CERT_IMPORT]      = { sev_mcmd_pek_cert_import,      sizeof(sev_mcmd_pek_cert_import_t),      !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_PDH_CERT_EXPORT]      = { sev_mcmd_pdh_cert_export,      sizeof(sev_mcmd_pdh_cert_export_t),      !LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_PDH_GEN]              = { sev_mcmd_pdh_gen,              0,                                       !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SEV_MCMD_ID_DF_FLUSH]             = { sev_mcmd_df_flush,             0,                                        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SEV_MCMD_ID_DOWNLOAD_FIRMWARE]    = { sev_mcmd_download_firmware,    sizeof(sev_mcmd_download_firmware_t),     LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_GET_ID]               = { sev_mcmd_get_id,               sizeof(sev_mcmd_get_id_t),               !LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_INIT_EX]              = { sev_mcmd_init_ex,              sizeof(sev_mcmd_init_ex_t),               LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_NOP]                  = { sev_mcmd_nop,                  0,                                       !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SEV_MCMD_ID_RING_BUFFER]          = { sev_mcmd_ring_buffer,          sizeof(sev_mcmd_ring_buffer_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_DECOMMISSION]         = { sev_mcmd_decommission,         sizeof(sev_mcmd_decommission_t),          LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_ACTIVATE]             = { sev_mcmd_activate,             sizeof(sev_mcmd_activate_t),              LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_DEACTIVATE]           = { sev_mcmd_deactivate,           sizeof(sev_mcmd_deactivate_t),            LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_GUEST_STATUS]         = { sev_mcmd_guest_status,         sizeof(sev_mcmd_guest_status_t),          LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT },
    [SEV_MCMD_ID_COPY]                 = { sev_mcmd_copy,                 sizeof(sev_mcmd_copy_t),                  LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_ACTIVATE_EX]          = { sev_mcmd_activate_ex,          sizeof(sev_mcmd_activate_ex_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_LAUNCH_START]         = { sev_mcmd_launch_start,         sizeof(sev_mcmd_launch_start_t),          LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT },
    [SEV_MCMD_ID_LAUNCH_UPDATE_DATA]   = { sev_mcmd_launch_update_data,   sizeof(sev_mcmd_launch_update_t),         LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_LAUNCH_UPDATE_VMSA]   = { sev_mcmd_launch_update_vmsa,   sizeof(sev_mcmd_launch_update_t),         LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_LAUNCH_MEASURE]       = { sev_mcmd_launch_measure,       sizeof(sev_mcmd_launch_measure_t),        LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_LAUNCH_SECRET]        = { sev_mcmd_launch_secret,        sizeof(sev_mcmd_transport_t),             LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_LAUNCH_FINISH]        = { sev_mcmd_launch_finish,        sizeof(sev_mcmd_launch_finish_t),         LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_ATTESTATION]          = { sev_mcmd_attestation,          sizeof(sev_mcmd_attestation_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_SEND_START]           = { sev_mcmd_send_start,           sizeof(sev_mcmd_send_start_t),            LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_SEND_UPDATE_DATA]     = { sev_mcmd_send_update_data,     sizeof(sev_mcmd_transport_t),             LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_SEND_UPDATE_VMSA]     = { sev_mcmd_send_update_vmsa,     sizeof(sev_mcmd_transport_t),             LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_SEND_FINISH]          = { sev_mcmd_send_finish,          sizeof(sev_mcmd_send_finish_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_SEND_CANCEL]          = { sev_mcmd_send_cancel,          sizeof(sev_mcmd_send_cancel_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_RECEIVE_START]        = { sev_mcmd_receive_start,        sizeof(sev_mcmd_receive_start_t),         LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT },
    [SEV_MCMD_ID_RECEIVE_UPDATE_DATA]  = { sev_mcmd_receive_update_data,  sizeof(sev_mcmd_transport_t),             LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_RECEIVE_UPDATE_VMSA]  = { sev_mcmd_receive_update_vmsa,  sizeof(sev_mcmd_transport_t),             LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_RECEIVE_FINISH]       = { sev_mcmd_receive_finish,       sizeof(sev_mcmd_receive_finish_t),        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_DBG_DECRYPT]          = { sev_mcmd_dbg_decrypt,          sizeof(sev_mcmd_debug_t),                 LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_DBG_ENCRYPT]          = { sev_mcmd_dbg_encrypt,          sizeof(sev_mcmd_debug_t),                 LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SEV_MCMD_ID_SWAP_OUT]             = { sev_mcmd_swap_out,             sizeof(sev_mcmd_swap_out_t),              LOCK_DF,  CMD_BUF_WRITE, CMD_BUF_INPUT_AND_OUTPUT_ERROR },
    [SEV_MCMD_ID_SWAP_IN]              = { sev_mcmd_swap_in,              sizeof(sev_mcmd_swap_in_t),               LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },

    /* SNP Commands */
    [SNP_MCMD_ID_INIT]                 = { snp_mcmd_init,                 0,                                        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SNP_MCMD_ID_SHUTDOWN]             = { snp_mcmd_shutdown,             0,                                        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SNP_MCMD_ID_PLATFORM_STATUS]      = { snp_mcmd_platform_status,      sizeof(snp_mcmd_platform_status_t),       LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_DF_FLUSH]             = { snp_mcmd_df_flush,             0,                                        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SNP_MCMD_ID_INIT_EX]              = { snp_mcmd_init_ex,              sizeof(snp_mcmd_init_ex_t),               LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_SHUTDOWN_EX]          = { snp_mcmd_shutdown_ex,          sizeof(snp_mcmd_shutdown_ex_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_DECOMMISSION]         = { snp_mcmd_decommission,         sizeof(snp_mcmd_decommission_t),          LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_ACTIVATE]             = { snp_mcmd_activate,             sizeof(snp_mcmd_activate_t),              LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_GUEST_STATUS]         = { snp_mcmd_guest_status,         sizeof(snp_mcmd_guest_status_t),         !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_ACTIVATE_EX]          = { snp_mcmd_activate_ex,          sizeof(snp_mcmd_activate_ex_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_GCTX_CREATE]          = { snp_mcmd_gctx_create,          sizeof(snp_mcmd_gctx_create_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_GUEST_REQUEST]        = { snp_mcmd_guest_request,        sizeof(snp_mcmd_guest_request_t),         LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_LAUNCH_START]         = { snp_mcmd_launch_start,         sizeof(snp_mcmd_launch_start_t),          LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_LAUNCH_UPDATE]        = { snp_mcmd_launch_update,        sizeof(snp_mcmd_launch_update_t),         LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_LAUNCH_FINISH]        = { snp_mcmd_launch_finish,        sizeof(snp_mcmd_launch_finish_t),         LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_DBG_DECRYPT]          = { snp_mcmd_dbg_decrypt,          sizeof(snp_mcmd_dbg_decrypt_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_DBG_ENCRYPT]          = { snp_mcmd_dbg_encrypt,          sizeof(snp_mcmd_dbg_encrypt_t),           LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_SWAP_OUT]             = { snp_mcmd_swap_out,             sizeof(snp_mcmd_swap_out_t),              LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_SWAP_IN]              = { snp_mcmd_swap_in,              sizeof(snp_mcmd_swap_in_t),               LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_PAGE_MOVE]            = { snp_mcmd_page_move,            sizeof(snp_mcmd_page_move_t),             LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_MD_INIT]              = { snp_mcmd_md_init,              sizeof(snp_mcmd_md_init_t),              !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_PAGE_RECLAIM]         = { snp_mcmd_page_reclaim,         sizeof(snp_mcmd_page_reclaim_t),         !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_PAGE_UNSMASH]         = { snp_mcmd_page_unsmash,         sizeof(snp_mcmd_page_unsmash_t),         !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_CONFIG]               = { snp_mcmd_config,               sizeof(snp_mcmd_config_t),                LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_DOWNLOAD_FIRMWARE_EX] = { snp_mcmd_download_firmware_ex, sizeof(snp_mcmd_download_firmware_ex_t),  LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_COMMIT]               = { snp_mcmd_commit,               sizeof(snp_mcmd_commit_t),                LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_PAGE_SET_STATE]       = { snp_mcmd_page_set_state,       sizeof(snp_mcmd_page_set_state_t),       !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_DLFW_CONTINUE]        = { snp_mcmd_dlfw_continue,        0,                                        LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_IGNORE },
    [SNP_MCMD_ID_VLEK_LOAD]            = { snp_mcmd_vlek_load,            sizeof(snp_mcmd_vlek_load_t),            !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
    [SNP_MCMD_ID_FEATURE_INFO]         = { snp_mcmd_feature_info,         sizeof(snp_mcmd_feature_info_t),         !LOCK_DF, !CMD_BUF_WRITE, CMD_BUF_INPUT_ONLY },
};

/**
 * Table of slave command handlers indexed by command ID
 */
static sev_status_t (* const slave_handler_table[SEV_SCMD_ID_LIMIT])(sev_scmd_t *cmd) = {
    [SEV_SCMD_ID_DF_FLUSH]         = sev_scmd_df_flush,
    [SEV_SCMD_ID_SET_TMR]          = sev_scmd_set_tmr,
    [SEV_SCMD_ID_RESET_TMR]        = sev_scmd_reset_tmr,
    [SEV_SCMD_ID_ENABLE_TMR]       = sev_scmd_enable_tmr,
    [SEV_SCMD_ID_GET_CUK]          = sev_scmd_get_cuk,
    [SEV_SCMD_ID_GET_APICID]       = sev_scmd_get_apicid,
    [SEV_SCMD_ID_MODIFY_TMR_FLAGS] = sev_scmd_modify_tmr_flags,
    [SEV_SCMD_ID_TLB_FLUSH]        = sev_scmd_tlb_flush,
    [SEV_SCMD_ID_RD_SZ_WRBKINVD]   = sev_scmd_rd_sz_wrbkinvd,
    [SEV_SCMD_ID_DF_ACQUIRE]       = sev_scmd_df_acquire,
    [SEV_SCMD_ID_DF_RELEASE]       = sev_scmd_df_release,
    [SEV_SCMD_GET_MCM_INFO]        = sev_scmd_get_mcm_info,
    [SEV_SCMD_CHECK_MSRS]          = sev_scmd_check_msrs,
    [SEV_SCMD_SET_MSR]             = sev_scmd_set_msr,
};

/**
 * Dispatches an SEV slave command.
 *
 * The 'sev_svc_slave()' function calls this function.
 */
sev_status_t sev_dispatch_slave(void *pCmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_scmd_t *pScmd;

    if (!pCmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    pScmd = (sev_scmd_t *)pCmd;
    pScmd->die = gCurrentDieID;

    switch (pScmd->id)
    {
    /*
     * These commands take a command buffer.
     */
    case SEV_SCMD_ID_SET_TMR:
    case SEV_SCMD_ID_RESET_TMR:
    case SEV_SCMD_ID_ENABLE_TMR:
    case SEV_SCMD_ID_MODIFY_TMR_FLAGS:
    case SEV_SCMD_ID_RD_SZ_WRBKINVD:
    case SEV_SCMD_SET_MSR:
        status = slave_handler_table[pScmd->id](pScmd);
        break;
    /*
     * These commands take no input.
     */
    case SEV_SCMD_ID_DF_FLUSH:
    case SEV_SCMD_ID_GET_CUK:
    case SEV_SCMD_ID_GET_APICID:
    case SEV_SCMD_ID_TLB_FLUSH:
    case SEV_SCMD_ID_DF_ACQUIRE:
    case SEV_SCMD_ID_DF_RELEASE:
    case SEV_SCMD_GET_MCM_INFO:
    case SEV_SCMD_CHECK_MSRS:
        status = slave_handler_table[pScmd->id](NULL);
        break;
    default:
        status = ERR_UNIMPLEMENTED;
    }

end:
    return status;
}

/**
 * Dispatches an SEV API (aka master) command.
 *
 * The 'sev_svc_master()' function calls this function. Once called,
 * this function performs the following steps:
 *
 *   1. Reads the command ID from 'CmdResp' to determine which command
 *      is being called.
 *
 *   2. Validates the pointer+length of the command buffer.
 *
 *   3. Copies the command buffer (but not any data that the command
 *      buffer may point to) into private memory.
 *
 *   4. Passes the command buffer to the correct command handler.
 *
 *   5. Copies any output data back to the command buffer.
 *
 *   6. Returns.
 */
sev_status_t sev_dispatch_master(sev_mcmd_id_t CmdId, uint32_t CmdBuf_Lo, uint32_t CmdBuf_Hi)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t address = to_addr64(CmdBuf_Lo, CmdBuf_Hi);
    sev_mcmd_t buffer;
    size_t size = 0;
    bool lock_df = false;
    bool snp_cmd_buf_enforcement = false;
    CMD_INPUT_BUF_TYPE cmd_buf_type;

    /* Immediately reject any commands not in the table */
    if ((CmdId >= SEV_MCMD_ID_LIMIT) || (master_handler_table[CmdId].handler == NULL))
        return SEV_STATUS_INVALID_COMMAND;

    size = master_handler_table[CmdId].cmd_size;
    lock_df = master_handler_table[CmdId].lock_df;
    snp_cmd_buf_enforcement = master_handler_table[CmdId].snp_cmd_buf_enforcement;
    cmd_buf_type = master_handler_table[CmdId].cmd_buf_type;

    reset_rmp_addr_check();
    reset_cpu_tmr_addr_check();

    /* DF C State Lock if the command needs it */
    if (lock_df)
    {
        status = df_access_lock();
        if (status != SEV_STATUS_SUCCESS)
            return status;
    }

    /* Calls every time after first SNP Init */
    if (is_rmp_table_initialized())
    {
        if (snp_cmd_buf_enforcement)
        {
            /* Only check the firmware state if it's in INIT state */
            if (gpDram->perm.snp_state == SNP_STATE_INIT)
            {
                /* Validate the address range before checking its RMP entry */
                status = validate_address_range(address, size);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_cmd_buf;

                /* Check command buffer state for every page boundary it may cross.
                   There is no alignment requirement on the command buffer */
                /* Verify that the provided page is in Firmware or Default State */
                status = check_page_range_firmware_writable(address, size);
                if (status != SEV_STATUS_SUCCESS) {
                    status += 64;
                    goto exit_cmd_buf;
                }
            }
        }
    }

    switch (cmd_buf_type)
    {
    case CMD_BUF_INPUT_ONLY:    /* These commands take input only */
        /* Copy the command buffer to PSP private memory */
        status = copy_from_x86(address, &buffer, size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = master_handler_table[CmdId].handler(&gSev, &buffer);
        break;

    case CMD_BUF_OUTPUT_ONLY:   /* These commands give output only */
        status = master_handler_table[CmdId].handler(&gSev, &buffer);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Copy the result to the x86 */
        status = copy_to_x86(address, &buffer, size);
        break;

    case CMD_BUF_INPUT_AND_OUTPUT:    /* These commands take input and give output */
        /* Copy the command buffer to PSP private memory */
        status = copy_from_x86(address, &buffer, size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = master_handler_table[CmdId].handler(&gSev, &buffer);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Copy the result to the x86 */
        status = copy_to_x86(address, &buffer, size);
        break;

    case CMD_BUF_INPUT_AND_OUTPUT_ERROR:    /* These commands take input and give output even on error conditions */
        /* Copy the command buffer to PSP private memory */
        status = copy_from_x86(address, &buffer, size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = master_handler_table[CmdId].handler(&gSev, &buffer);
        if (status == SEV_STATUS_INVALID_LENGTH)
        {
            /*
             * Copy the output to the x86, but preserve
             * the status code from the command handler.
             */
            copy_to_x86(address, &buffer, size);
        }
        else if (status == SEV_STATUS_SUCCESS)
        {
            /* Copy the result to the x86 normally */
            status = copy_to_x86(address, &buffer, size);
        }
        break;

    case CMD_BUF_IGNORE:    /* These commands ignore the command buffer, so no need to copy it */
        status = master_handler_table[CmdId].handler(&gSev, NULL);
        break;

    default:    /* Reject all other command IDs */
        status = SEV_STATUS_INVALID_COMMAND;
    }

end:
    /* Transition the state to Reclaim state */
    if (snp_cmd_buf_enforcement)
    {
        sev_status_t status_snp = SEV_STATUS_SUCCESS;
        uint64_t page_rmp_paddr = 0;
        rmp_entry_t page_rmp_entry;

        status_snp = get_rmp_paddr(address, &page_rmp_paddr); /* Get RMP entry for page given sPA */
        if (status_snp != SEV_STATUS_SUCCESS)
            goto exit_cmd_buf;
        status_snp = rmp_entry_read(page_rmp_paddr, &page_rmp_entry); /* Do x86 copy to pull RMP entry into readable memory */
        if (status_snp != SEV_STATUS_SUCCESS)
            goto exit_cmd_buf;

        /* Set the Cmd Buffer State from Firmware to Reclaim */
        page_rmp_entry.q1.f.immutable = 0;
        page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;

        /* Write all our RMP changes back to x86 memory */
        status_snp = rmp_entry_write(page_rmp_paddr, &page_rmp_entry);
        if (status_snp != SEV_STATUS_SUCCESS)
             goto exit_cmd_buf;
    }

exit_cmd_buf:
    if (lock_df)
        df_access_unlock();
    return status;
}

/**
 * Function that wipes out the dispatch master table, except for
 * the command ID provided as a parameter. This is used by DLFW_EX_CONTINUED
 * in the awkward case where the new/current FW can't abide the system
 * configuration, but the Boot Loader can't restore the old FW (1.0.0.4 to
 * 1.0.0.6 boot loaders had a bug in the RESTORE subop for cache_new_image.)
 * Rather than add code to every command to check for the rare case, we
 * instead levarage the existing tests in sev_dispatch_master() to prevent
 * execution of any command except DLFW_EX, which will expect the committed
 * old FW to be restored by the HV.
 */
sev_status_t clear_dispatch_master(sev_mcmd_id_t CmdId)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    for (size_t i = 0; i < sizeof(master_handler_table)/sizeof(master_handler_table[0]); i++)
    {
        if (i != CmdId)
            master_handler_table[i].handler = NULL;
    }

    return status;
}
