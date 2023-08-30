// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sev_dispatch.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_persistent.h"
#include "sev_plat.h"
#include "sev_status.h"
#include "sev_trace.h"
#include "tmr_cache.h"

//*** Unit Tests ***
#include "cipher_utest.h"
#include "df_regs_utest.h"
#include "digest_utest.h"
#include "ecc_utest.h"
#include "ecdh_utest.h"
#include "ecdsa_utest.h"
#include "encrypt_memory_utest.h"
#include "hmac_utest.h"
#include "rsa_utest.h"
#include "secure_ops_utest.h"
#include "sev_cert_utest.h"
#include "sev_persistent_utest.h"

#define UTEST_MSG_SIZE    (128)

/* Command descriptions */
#define SEV_CMD_STATUS_SHIFT        31
#define SEV_CMD_STATUS_MASK         (1ul << SEV_CMD_STATUS_SHIFT)
#define SEV_CMD_ID_SHIFT            16
#define SEV_CMD_ID_MASK             (0xFFul << SEV_CMD_ID_SHIFT)
#define SEV_CMD_ERROR_SHIFT         0
#define SEV_CMD_ERROR_MASK          (0xFFFFul << SEV_CMD_ERROR_SHIFT)

/* Initialize it known value */
void *__stack_chk_guard = (void *)0xdeadbeef;

/**
 * @brief Initalize the stack canary
 *
 * @return none. As any failure from this function is considered as non fatal.
 */
void init_stack_canary(void)
{
    uint32_t status = BL_OK;
    uint32_t canary;

    status = Svc_Trng((uint8_t *)&canary, sizeof(canary));
    if (status != BL_OK)
        return;

    __stack_chk_guard = (void *)canary;
}

void __stack_chk_fail(void)
{
    Svc_Exit(BL_ERR_DATA_CORRUPTION);
}

/**
 * This is called by ASM code before calling sev_uapp_entry().
 * This functions calls SVC service to map application stack.
 *
 * Return value : Virtual Address of stack pointer.
 */
uint32_t allocate_stack(void)
{
    uint32_t Status = 0;
    uint32_t StackVa = 0;
    uint32_t StackStart = (uint32_t)&Image$$SEV_UAPP_STACK$$ZI$$Base;
    uint32_t StackEnd = (uint32_t)&Image$$SEV_UAPP_STACK$$ZI$$Limit;

    // Call BL service to map AGESA stack.
    Status = Svc_MapUserStack( StackStart, StackEnd, &StackVa );

    // In case of error, return error to main Boot Loader.
    if ((Status != BL_OK) || (StackVa == 0))
    {
        Svc_Exit( SEV_STATUS_HARDWARE_PLATFORM );
    }

    return StackVa;
}

void sev_uapp_utests(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    char message[UTEST_MSG_SIZE] = {0};

    status = digest_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "digest_utest() failed. (%d)", status);
        goto unit_test_done;
    }

    status = hmac_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "hmac_utest() failed. (%d)", status);
        goto unit_test_done;
    }

#ifdef GENOA_BRINGUP
    status = cipher_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "cipher_utest() failed. (%d)", status);
        goto unit_test_done;
    }
#endif

#if 0   /* Commented out because memory has limited number of writes */
    status = sev_persistent_store_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "sev_persistent_store_utest() failed. (%d)", status);
        goto unit_test_done;
    }
#endif

    status = ecc_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "ecc_utest() failed. (%d)", status);
        goto unit_test_done;
    }

    status = ecdh_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "ecdh_utest() failed. (%d)", status);
        goto unit_test_done;
    }

    status = ecdsa_utest(); /* Takes ~5 seconds */
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "ecdsa_utest() failed. (%d)", status);
        goto unit_test_done;
    }

    status = rsa_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "rsa_utest() failed. (%d)", status);
        goto unit_test_done;
    }

    status = sev_cert_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "sev_cert_utest() failed. (%d)", status);
        goto unit_test_done;
    }

    status = secure_ops_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "secure_ops_utest() failed. (%d)", status);
        goto unit_test_done;
    }

#ifdef GENOA_BRINGUP
    {
        // Data fabric register access unit test
        size_t nr_df_tests = 0, nr_passed = 0;
        df_utest(&nr_df_tests, &nr_passed);
        if (nr_passed != nr_df_tests)
        {
            snprintf(message, UTEST_MSG_SIZE, "%d/%d DF tests passed.", nr_passed, nr_df_tests);
            status = ERR_UNKNOWN;
            SEV_TRACE("df_utest failed...\n");
            SEV_TRACE_EX(status, 0, 0, 0);

            goto unit_test_done;
        }
        else
        {
            SEV_TRACE("df_utest succeed!\n");
        }
    }
#endif

#if 0 /* Need to manually set TEST_X86_ADDR for each platform */
    status = encrypt_memory_utest();
    if (status != SEV_STATUS_SUCCESS)
    {
        snprintf(message, UTEST_MSG_SIZE, "encrypt_memory_utest() failed. (%d)", status);
        goto unit_test_done;
    }
#endif

unit_test_done:
    if (status != SEV_STATUS_SUCCESS)
        while (1);   // soft hang!!!
}

sev_status_t sev_copy_state(sev_t *sev, bool save)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_rsvd_dram_t *backup = NULL;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_get_reserved_dram((void **)&backup, sizeof(sev_rsvd_dram_t));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (save)
    {
        memcpy(&backup->sev_bkup, sev, sizeof(*sev));        /* Save state to DRAM */
        memcpy(&backup->persistent_bkup, &gPersistent, sizeof(sev_persistent_globals_t));

        /* Wipe elements of gPersistent that contain sensitive data (HMAC and AES keys) */
        status = sev_persistent_store_deinit();

        /* Clean cache after writing, so slaves see updated values */
        sev_hal_clean_dcache((uint32_t)&(gpDram->sev_bkup), sizeof(gpDram->sev_bkup));
        sev_hal_clean_dcache((uint32_t)&(gpDram->persistent_bkup), sizeof(gpDram->persistent_bkup));
    }
    else
    {
        /*
         * This is for RELOAD case - at this point, we have to assume SRAM is
         * not initialized, and state of data needs to be restored properly
         */
        memcpy(sev, &backup->sev_bkup, sizeof(*sev));        /* Load state from DRAM */
        memcpy(&gPersistent, &backup->persistent_bkup, sizeof(sev_persistent_globals_t));
    }

end:
    return status;
}

sev_status_t sev_save_state(sev_t *sev)
{
    return sev_copy_state(sev, true);
}

sev_status_t sev_load_state(sev_t *sev)
{
    return sev_copy_state(sev, false);
}

sev_status_t sev_uapp_init(sev_t *sev, uint32_t CurrentDieId,
                           uint32_t TotalDieNum, enum sev_uapp_state uapp_state)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (TotalDieNum == 0 || CurrentDieId >= TotalDieNum)
    {
        status = SEV_STATUS_HARDWARE_PLATFORM;
        goto end;
    }

    gTotalDieNum = TotalDieNum;
    gCurrentDieID = CurrentDieId;

    switch (uapp_state)
    {
    case SEV_UAPP_STATE_FIRST_RUN:    /* First entry since boot, or after a cache_new_image (after a DLFW/DLFW_EX). */
        /*
         * Initialize the platform state.
         * This gets called on the very first run after boot or after a DownloadFirmware.
         */
        status = sev_hal_get_reserved_dram((void **)&gpDram, sizeof(sev_rsvd_dram_t));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Initialize the platform state */
        sev->sev.context_initialized = false;
        sev->common_context_initialized = false;
        sev->snp.context_initialized = false;
        status = sev_init(sev);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Initialize the TMR cache */
        tmr_cache_init();

        break;
    case SEV_UAPP_STATE_RUNNING:    /* Entered previously since loaded. */
        /* After full shutdown, re-init everything */
        status = sev_init(sev);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        break;
    case SEV_UAPP_STATE_RELOADED:    /* First entry since SEV FW reload. */
        /*
         * This gets called after an SDU or DRTM.
         * The master state needs to get restored, and no guest states modified,
         * so have it do a load_state. The slaves need to re-fill their SRAM
         * and populate gSev again, so re-init them. This won't change the
         * state of the guests.
         */
        /* For master or slave, init global pointer to SEV Reserved DRAM */
        status = sev_hal_get_reserved_dram((void **)&gpDram, sizeof(sev_rsvd_dram_t));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
        {
            /* Retrieve the initialized platform state */
            status = sev_load_state(sev);    /* DRAM -> SRAM */
        }
        else
        {
            /*
             * For slave die, just re-initialize it as the gSEV
             * space is used for the socket's CCD/CCX information
             */
            sev->sev.context_initialized = false;
            sev->common_context_initialized = false;
            sev->snp.context_initialized = false;
            status = sev_init(sev);
        }
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        break;
    case SEV_UAPP_STATE_NEW_FW:        /* This is not an entry state. */
    default:
        /* Invalid app state! */
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }


    // *** Unit Tests ****
#ifdef SEV_UAPP_UTEST
    /* Only run unit tests on the master die */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
        sev_uapp_utests();
#endif

end:
    return status;
}

/* Called for BOTH master and slave die command exits! */
sev_status_t sev_uapp_exit()
{
    return SEV_STATUS_SUCCESS;
}

uint64_t sev_error_stack;

sev_status_t sev_error(sev_status_t status, uint16_t error_id)
{
    if (status != SEV_STATUS_SUCCESS)
    {
        /* Make room for the new error */
        sev_error_stack <<= 10;
        sev_error_stack |= error_id & 0x3FF;
    }

    return status;
}

void sev_uapp_entry(uint32_t CurrentDieId, uint32_t TotalDieNum, void *pCmd, enum sev_uapp_state uapp_state)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool rb_enable = false;
    sev_error_stack = 0; /* Reset the error stack */

    init_stack_canary();

    status = sev_uapp_init(&gSev, CurrentDieId, TotalDieNum, uapp_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (CurrentDieId == 0)
    {
        /* Master command for Master die */
        bool cmd_fetched = true;
        SEV_TRACE("SEV_UAPP master command received...");

        SEV_MBOX *pMasterCmd = NULL;
        sev_mcmd_id_t CmdId;

        pMasterCmd = (SEV_MBOX *)pCmd;

        /*
         * Per command read rb_enable once. Ring Buffer Mode could enable it for
         * the "next command" in gPersistent. In Ring Buffer mode, the code can
         * exit it but still has to report ring buffer status in the mode it was in.
         */
         if (gpDram->perm.rb_config.rb_enable)
            sev_rb_copy_mailbox(&gpDram->perm.rb_config.state);
start_rb_processing:
        rb_enable = gpDram->perm.rb_config.rb_enable;
        if (rb_enable == false)
        {
            CmdId = (sev_mcmd_id_t)((pMasterCmd->MboxCmdSts & SEV_CMD_ID_MASK) >> SEV_CMD_ID_SHIFT);
            SEV_TRACE_EX(CmdId, 0, 0, 0);
        }
        else
        {
            SEV_MBOX_FLAG_CLEAR( pMasterCmd->Flags, UPDATE_MAILBOX );
            status = sev_rb_pre_cmd_process(&gpDram->perm.rb_config.state, &CmdId,
                                            (uint32_t *)&pMasterCmd->CmdRsp_Lo, (uint32_t*)&pMasterCmd->CmdRsp_Hi,
                                            &cmd_fetched);
            if (cmd_fetched == false)
            {
                /*
                 * Check to see if ring buffer mode is still active. If not, exit.
                 * This can only happen if the CMDRESP mailbox is receiving regular
                 * non-RB command and hence we have to return an error and exit
                 * without processing
                 */
                if (gpDram->perm.rb_config.rb_enable == false)
                {
                    /* Ring Buffer got disabled */
                    status = SEV_STATUS_EXIT_RING_BUFFER;
                    SEV_MBOX_FLAG_SET( pMasterCmd->Flags, UPDATE_MAILBOX );

                    /* Reclaim Ring Buffer for SNP enabled system */
                    if (gpDram->perm.rb_config.status_ptr_high_priority_reclaim)
                    {
                        snp_reclaim_buffer(gpDram->perm.rb_config.status_ptr_high_priority_reclaim);
                    }

                    if (gpDram->perm.rb_config.status_ptr_low_priority_reclaim)
                    {
                        snp_reclaim_buffer(gpDram->perm.rb_config.status_ptr_low_priority_reclaim);
                    }

                    /* This should exit to the end and generate an interrupt in BL code */
                    goto exit_rb_processing;
                }
            }
        }

        if (cmd_fetched)
        {
            /* This command is not allowed to come from the x86 */
            if (CmdId == SNP_MCMD_ID_DLFW_CONTINUE)
            {
                CmdId = SEV_MCMD_ID_LIMIT;
            }
            if (SEV_MBOX_FLAG_GET(pMasterCmd->Flags, CONTINUE))
            {
                SEV_MBOX_FLAG_CLEAR(pMasterCmd->Flags, CONTINUE);
                switch (CmdId)
                {
                /* This is the only case... so far... */
                case SNP_MCMD_ID_DOWNLOAD_FIRMWARE_EX:
                    CmdId = SNP_MCMD_ID_DLFW_CONTINUE;
                    break;
                default:
                    break;
                }
            }

            /* Actually execute the command! */
            status = sev_dispatch_master(CmdId, pMasterCmd->CmdRsp_Lo, pMasterCmd->CmdRsp_Hi);
        }

        /* If the command wants to be "continued", tell BL to not update
         * the mailbox and re-invoke the (possibly updated) SEV UApp. */
        if (status == ERR_SEV_DLFW_CONTINUING)
        {
            SEV_MBOX_FLAG_CLEAR( pMasterCmd->Flags, UPDATE_MAILBOX );
            SEV_MBOX_FLAG_SET( pMasterCmd->Flags, CONTINUE);
        }

        /* If we need to exit the RB loop to give the BL a chance to load new FW, do it. */
        if (SEV_MBOX_FLAG_GET(pMasterCmd->Flags, CONTINUE) == SEV_MBOX_FLAG_CONTINUE_TRUE)
            goto exit_rb_processing;

        if (rb_enable)
        {
            if (cmd_fetched)
            {
                sev_rb_post_cmd_process(&gpDram->perm.rb_config.state, (sev_status_t)status);
                sev_rb_copy_mailbox(&gpDram->perm.rb_config.state);
                sev_rb_generate_interrupt(&gpDram->perm.rb_config.state);

                /* Handle the ugly case where DLFW_EX is rejected by the new FW image.
                 * The command HAS completed... and the status has been posted, interrupts
                 * generated, etc. Now... what to do to have the rest of the RB commands
                 * executed, which is only a problem if the DLFW_EX 'continuation' failed.
                 */
                if (CmdId == SNP_MCMD_ID_DLFW_CONTINUE && status != SEV_STATUS_SUCCESS)
                {
                    /* If the old image was restored, then we need to exit this FW back to
                     * the BL to have it load up the restored FW and use it to process
                     * commands.
                     * If the old image could not be restored, we need to process commands
                     * with this FW until the x86 does the restore using DLFW_EX.
                     * There's a special error code from DLFW_CONTINUED to distinguish
                     * these cases. SEV_STATUS_RESTORE_REQUIRED if the HV has to restore.
                     */
                    if (status != SEV_STATUS_RESTORE_REQUIRED)
                    {
                        SEV_MBOX_FLAG_SET( pMasterCmd->Flags, CONTINUE);
                        goto exit_rb_processing;
                    }
                }

                /* If the command (SHUTDOWN) resulted in exiting RB mode... */
                if (!gpDram->perm.rb_config.rb_enable)
                    goto exit_rb_processing;

                sev_hal_yield();
                goto start_rb_processing;
            }
            else
            {
                /* Not valid command, but check if we still need to interrupt x86 */
                sev_rb_generate_interrupt(&gpDram->perm.rb_config.state);
            }
        }
        else /* !rb_enable */
        {
            /* Store the extended error information in the mailbox ADDR regs. */
            WriteReg32(SEV_CMD_BUF_ADDR_HI_REG, (uint32_t)(sev_error_stack >> 32));
            WriteReg32(SEV_CMD_BUF_ADDR_LO_REG, (uint32_t)(sev_error_stack));
        }


exit_rb_processing:
        /* Only the MASTER die should attempt to update the DRAM copy of gSEV! */
        sev_save_state(&gSev);    /* SRAM -> DRAM */
    }
    else
    {
        /* Slave command for Slave die */
        status = sev_dispatch_slave(pCmd);
    }

    sev_uapp_exit();

end:
    SEV_TRACE("SEV_UAPP exit...");
    SEV_TRACE_EX(status, 0, 0, 0);
    Svc_Exit(status);  // this returns to the main Boot Loader
}
