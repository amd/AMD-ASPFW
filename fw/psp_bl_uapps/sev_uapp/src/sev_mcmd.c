// Copyright(C) 2016-2021 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "amd_cert.h"
#include "apicid.h"
#include "ccp_direct_cipher.h"
#include "nist_kdf.h"
#include "secure_ops.h"
#include "sev_extended_errors.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_mcmd.h"
#include "sev_persistent.h"
#include "sev_scmd.h"
#include "sev_tmr.h"
#include "sscb.h"
#include "umc.h"
#include "x86_copy.h"
#include "sw_hash.h"

/* For the SEV COPY command */
#define SEV_COPY_LENGTH_MULT    (4096)
#define SEV_COPY_ALIGN_MBZ_MASK (4096-1)

/* For SEV INIT_EX command */
#define SEV_INIT_EX_CMD_LEN     (0x24)
#define SEV_INIT_EX_NV_LEN      (32*1024)

/**
 * These are too big for the stack, so store them in the scratch buffer
 */
typedef struct import_scratch
{
    sev_persistent_t    saved;
    sev_cert_t          pek;
    sev_cert_t          oca;
} import_scratch_t;

typedef struct pdh_cert_chain
{
    sev_cert_t pek;
    sev_cert_t oca;
    sev_cert_t cek;
} pdh_cert_chain_t;

/**
 * This command is used to inform the firmware that the guest is bound to a
 * particular ASID and designate which specific CCX will be allowed to run
 * the guest. The firmware then loads the guest's VEK into the
 * memory controller at the key slot for that ASID.
 * Once the guest is RUNNING, the designated CCXs will be allowed to execute
 * the guest.
 */
typedef struct act_ex_apicids
{
    uint32_t apic_ids[APIC_ID_LIST_MAX_CNT];
} act_ex_apicids_t;

typedef struct send_start_scratch
{
    pdh_cert_chain_t    chain;  /* PEK/OCA/CEK */
    sev_cert_t          pdh;
    sev_cert_pubkey_t   ask_pubkey;
    uint8_t             amd_chain[1];
} send_start_scratch_t;

static bool init_cmd_buf_valid(const sev_mcmd_init_t *init)
{
    uint16_t mbz_flags = (uint16_t)~SEV_CONFIG_ES_FLAG;
    sev_mcmd_init_t zero;

    memset(&zero, 0, sizeof(zero));

    return init != NULL && flags_valid(init->flags, mbz_flags) &&
           memcmp(init->reserved, zero.reserved, sizeof(init->reserved)) == 0;
}

static bool init_ex_cmd_buf_valid(const sev_mcmd_init_ex_t *init)
{
    uint16_t mbz_flags = (uint16_t)~SEV_CONFIG_ES_FLAG;
    sev_mcmd_init_ex_t zero;

    memset(&zero, 0, sizeof(zero));

    return init != NULL && flags_valid(init->flags, mbz_flags) &&
        memcmp(init->reserved1, zero.reserved1, sizeof(init->reserved1)) == 0 &&
        memcmp(&init->reserved2, &zero.reserved2, sizeof(init->reserved2)) == 0;
}

static bool vlek_installed(void)
{
    const uint8_t *p = &gpDram->perm.vlek[0][0];
    const uint8_t *end = p + sizeof(gpDram->perm.vlek);
    bool retval = false;

    do {
        retval |= *p != 0;
    } while (++p < end);

    return retval;
}

/**
 * (CSF-684) wrbkinvd is needed anytime you are writing to a page with a different
 * encryption/asid key than what it currently contains and need to evict any
 * stale data in the caches.
 * Two main cases
 *   1. Reading from a page unencrypted and writing to it encrypted (LaunchUpdate)
 *      - Only the wrbkinvd is needed. Do not have to do a dummy read on the dst
 *        page because the read will cause the necessary invalidates
 *   2. Writing to a page encrypted that may currently be unencrypted (x86 key)
 *      or encrypted with a different asid. Need to evict any stale data by
 *      performing the dummy read on the dst page. See CSF-698 below
 *
 *
 * (CSF-698) Since copy_to_x86_encrypted encryption/decryption operations are not
 * being done in-place, and if using cached memory, need to take some extra steps
 * to handle caching issues. For DbgEncrypt, for example, the PSP is going to write
 * to DstPage with ciphertext, but before it does that, you need to ensure that
 * any dirty plaintext data in that page is evicted. To do that, need to do both
 *  1) Set the RdSzWrBkInvd bit and then
 *  2) Do a copy_from_x86 on the DstPage (and just throw away the result).
 *     This step ensures that you evict any of those cachelines on the x86
 *      side before you write to that page. You should only need to do that
 *      for DbgEncrypt though since with DbgDecrypt you're issuing plaintext
 *      writes (which will naturally cause appropriate evictions).
 * Issue is in DbgEncrypt, LaunchSecret, ReceiveUpdate, and SwapIn
 */
static sev_status_t set_misc_read_sized_wrbkinvd(bool enable)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Set/clear the master die */
    status = sev_hal_set_misc_read_sized_wrbkinvd(enable);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Set/clear on slave die also */
    if (gTotalDieNum > 1)
    {
        sev_scmd_t scmd;
        memset(&scmd, 0, sizeof(scmd));
        scmd.id = SEV_SCMD_ID_RD_SZ_WRBKINVD;
        scmd.scmd.sz_wrbkinvd.enable = enable;
        status = sev_hal_master_to_slave(1, &scmd, sizeof(scmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

end:
    return SEV_ERROR(status, EXT_ERR_001);
}

/**
 * Refresh the perm.committed* variables from the current FW header
 */
static sev_status_t update_committed_versions(SEV_FW_IMAGE_HEADER *hdr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (hdr == NULL)
        hdr = (SEV_FW_IMAGE_HEADER *)&Image$$SEV_UAPP_CODE$$Base;

    /* Set the cached committed FW versions from the current FW */
    gpDram->perm.committed_build_id  = (hdr->FWVersion & 0xff);
    gpDram->perm.committed_api_minor = (hdr->FWVersion >> 8) & 0xff;
    gpDram->perm.committed_api_major = (hdr->FWVersion >> 16) & 0xff;

    /* Set the committed TCB SNP component from the current FW */
    (void)get_running_tcb(&gpDram->perm.committed_tcb, hdr); /* Can't return an error */

    /* Finally, when a "commit" occurs, that flushes any CONFIG'd TCB */
    gPersistent.config_tcb.val = 0;

    /* Regnerate the VCEK using the new TCB */
    status = vcek_hash_derive(gpDram->perm.snp_identity.vcek_hash, DIGEST_SHA384_SIZE_BYTES, NULL);
    if (status == SEV_STATUS_SUCCESS)
        status = vcek_derive(&gpDram->perm.snp_identity);

    /* If we have an error here, nuke the VCEK */
    if (status != SEV_STATUS_SUCCESS)
        memset(&gpDram->perm.snp_identity, 0, sizeof(gpDram->perm.snp_identity));
    return status;
}

/**
 * Divide the DesiredTscFreq by the Ref Clk of the PSP and store the
 * result in a 8.32 fixed-point binary number format.
 * See TSC Ratio MSR (C000_0104h) in APM Vol. 2 for format.
 * Also, http://twiki.amd.com/twiki/bin/viewauth/PSArch/PsHldUcSecureTsc
 * Input frequencies in kHz.
 */
#define FRAC_WIDTH 32
static uint64_t calc_tsc_scale(uint32_t desired_tsc_freq, uint32_t ref_clk_freq)
{
    uint64_t guest_tsc_scale = 0, integer_part = 0, fractional_part = 0;
    if(ref_clk_freq != 0)
    {
        integer_part = desired_tsc_freq / ref_clk_freq;
        fractional_part = desired_tsc_freq - integer_part*ref_clk_freq;  /* Remainder */
        fractional_part = ((fractional_part << FRAC_WIDTH) + (ref_clk_freq - 1)) / ref_clk_freq;
    }

    /* Truncate any number that's taking up more bits than allowed */
    integer_part &= 0xFF;
    fractional_part &= (1ULL << FRAC_WIDTH) - 1;

    guest_tsc_scale = (integer_part << FRAC_WIDTH) | fractional_part;

    return guest_tsc_scale;
}

sscb_t gSSCB = {0};

/* Check that the TSEG MSRs match the SSCB advertised to everyone else */
static sev_status_t check_tseg(void)
{
    uint64_t tseg_base = 0;
    uint64_t tseg_mask = 0;
    uint64_t tseg_end = 0;
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t is_same = false;

    status = sev_hal_check_msr(MSR_TSEG_BASE, &is_same, &tseg_base);
    if (status != SEV_STATUS_SUCCESS)
        return status;
    status = sev_hal_check_msr(MSR_TSEG_MASK, &is_same, &tseg_mask);
    if (status != SEV_STATUS_SUCCESS)
        return status;

    tseg_mask &= GET_MASK64(47,17);     /* APM is wrong, PPR is right */
    tseg_base &= tseg_mask;
    /* tseg_end always has the bottom 17 bits set */
    tseg_end = (tseg_base + (~tseg_mask & GET_MASK64(47,17))) | GET_MASK64(16,0);
    if (tseg_base != gSSCB.SMM_Base || tseg_end != gSSCB.SMM_End)
        return SEV_STATUS_INVALID_CONFIG;

    return status;
}

/**
 * Note that for the SEV and SNP functions, the hierarchy of checks must be kept
 *  the same. You must check Platform state before checking Guest state, etc.
 * All of the _common functions are assuming that a valid Guest is being passed
 * in and not NULL.
 */

/* -------------- Common Functions between SEV and SNP  -------------- */
static sev_status_t mcmd_df_flush_common(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool wbinvd_is_done = false;
    uint32_t ccds_wbinvd_done = 0;
    uint32_t asid_idx = 0;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check that a WBINVD has been done for the cores on all dies */
    status = is_wbinvd_done(&wbinvd_is_done, &ccds_wbinvd_done);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * For each CCX for which all of its cores' WBINVD_DONE flags are set,
     * all ASIDs that are in FW state "dirty" transition to state "clean".
     */
    if (ccds_wbinvd_done)
    {
        for (asid_idx = 0; asid_idx < MAX_SEV_ASIDS; asid_idx++)
        {
            uint32_t tmp_mask = gpDram->perm.asid_dirty[asid_idx] & ccds_wbinvd_done;
            if (tmp_mask)
            {
                gpDram->perm.asid_dirty[asid_idx] &= ~tmp_mask;
                gpDram->perm.asid_clean[asid_idx] |= tmp_mask;
            }
        }
    }

    /* Were all cores done? */
    if (!wbinvd_is_done)
    {
        status = SEV_STATUS_WBINVD_REQUIRED;
        goto end;
    }

    /* Flush pending writes to the UMC */
    status = sev_hal_df_write_flush();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Flush pending writes on slave dies if any */
    if (gTotalDieNum > 1)
    {
        sev_scmd_t scmd;
        memset(&scmd, 0, sizeof(scmd));
        scmd.id = SEV_SCMD_ID_DF_FLUSH;
        status = sev_hal_master_to_slave(1, &scmd, sizeof(scmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* If the platform is SEV-ES enabled, it is now safe to initialize the TMR */
    /* SEV has to be initialized with ES to have a TMR. Don't run if just SNP */
    if (sev->sev.state != SEV_STATE_UNINIT && sev_es_platform_enabled(sev) && !sev_es_is_initialized(&sev->sev.es))
    {
        status = sev_es_init_trusted_region(&sev->sev.es);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Note: Leaving the ASIDs marked invalid until used by guests
       when Activated and Running. Likewise for slave dies. */

end:
    return status;
}

static sev_status_t mcmd_decommission_common(sev_t *sev, sev_guest_t *guest)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev || !guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (guest->asid && asid_is_active(sev, guest->asid))
    {
        status = SEV_STATUS_ACTIVE;
        goto end;
    }

    /*
     * If SEV-ES CRC is allocated, then free any blocks used to store the
     * VMSA checksums.
     */
    if (sev_es_allocation_guest_enabled(guest))
    {
        pool_vcpu_t *pool = &sev->sev.es.crc32_pool;
        /* Free if the blocks are allocated */
        if (guest->es.head_index != INVALID_BLOCK && guest->es.tail_index != INVALID_BLOCK)
        {
            status = pool_vcpu_free_list(pool, guest->es.head_index, guest->es.tail_index, guest->es.num_vcpus);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

    /* Only count launched guests in guest_count */
    if (guest->type == SEV_GUEST_TYPE_SEV)
    {
        sev->sev.guest_count--;
    }
    else if ((guest->type == SEV_GUEST_TYPE_SNP) && (guest->snp_state != SNP_GUEST_STATE_INIT)) /* Can call Decommission from any SNP state */
    {
        gpDram->perm.snp_guest_count--;
    }

    sev_guest_clear(guest); /* Clears guest_t thus setting state to invalid */

end:
    return status;
}

static sev_status_t activate_common(sev_t *sev, sev_guest_t *guest,
                                    uint32_t asid, uint32_t ccxs)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev || !guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Do not allow activate/activate-ex for SENT state */
    if (guest->sev_state == SEV_GUEST_STATE_SENT)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (!guest_has_asid(guest))
    {
        /* First time for guest: Make sure ALL CCXs for this ASID are
          'clean', else error out. */
        if (gpDram->perm.asid_dirty[asid-1])
        {
            status = SEV_STATUS_DF_FLUSH_REQUIRED;
            goto end;
        }
        if (gpDram->perm.asid_clean[asid-1] != gPersistent.ccx_present_bit_mask)
        {
            status = SEV_STATUS_ASID_OWNED;
            goto end;
        }
        guest->ccxs = 0;  /* Make sure. */
        /* Note: Don't set guest asid here. */
    }
    else
    {
        /* Allow subsequent Activates for this guest on same ASID only. */
        if (asid != guest->asid)
        {
            status = SEV_STATUS_ACTIVE;
            goto end;
        }
        guest->ccxs |= ccxs;
    }

    /*
     * This will install guest key in the UMC and save/update
     * the CCXs to be enabled.
     * If the guest is Running, the ASID is enabled in each of the
     * CCXs to be enabled, and the guest Active flag is set.
     * Otherwise only the guest 'Pending activation' flag is set.
     */
    status = sev_guest_activate(guest, asid, ccxs);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (guest_is_pending(guest))
    {
        /* Add specified CCXs to 'Allocated'. */
        gpDram->perm.asid_allocated[asid-1] |= ccxs;
        gpDram->perm.asid_clean[asid-1]   &= ~ccxs;
    }
    else if (guest_is_active(guest))
    {
        /* Guest fully activated. */
        /* Mark all of the guest's enabled CCXs for its ASID 'In use'. */
        gpDram->perm.asid_in_use[asid-1] |= guest->ccxs;
        gpDram->perm.asid_allocated[asid-1] &= ~guest->ccxs;
        gpDram->perm.asid_clean[asid-1]   &= ~guest->ccxs;
    }

end:
    return status;
}

static sev_status_t mcmd_activate_common(sev_t *sev, sev_guest_t *guest, uint32_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev || !guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check that the ASID is valid */
    if ((asid == 0) || (asid > GetMaxSEVASID()))
    {
        status = SEV_STATUS_INVALID_ASID;
        goto end;
    }

    /* Check that no guest has this ASID. */
    if ((gpDram->perm.asid_in_use[asid-1]) || (gpDram->perm.asid_allocated[asid-1]))
    {
        status = SEV_STATUS_ASID_OWNED;
        goto end;
    }

    /* Check if this guest is already active */
    if (!(guest_is_inactive(guest)))
    {
        status = SEV_STATUS_ACTIVE;
        goto end;
    }

    status = activate_common(sev, guest, asid, gPersistent.ccx_present_bit_mask);

end:
    return status;
}

static sev_status_t mcmd_activate_ex_common(sev_t *sev, sev_guest_t *guest,
                                            uint32_t asid, uint32_t numids,
                                            uint64_t ids_paddr, uint64_t ma_paddr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t ccxs = 0;
    act_ex_apicids_t *apicids = (act_ex_apicids_t *)gpSevScratchBuf;

    if (!sev || !guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Make sure ASID is valid */
    if ((asid == 0) || (asid > GetMaxSEVASID()))
    {
        status = SEV_STATUS_INVALID_ASID;
        goto end;
    }

    /*
     * If there was a problem with creation of system
     * APICID tables, this command is not supported.
     */
    if (sev->activate_ex_enable == false)
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    /* Validate Activate_EX specific fields. */
    if ((numids == 0) || (numids > APIC_ID_LIST_MAX_CNT))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Get the list of apic IDs */
    status = copy_from_x86(ids_paddr, (void *)apicids->apic_ids,
                           numids * sizeof(uint32_t));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = apicid_to_ccx_bitmask(sev, apicids->apic_ids, numids,
                                   (uint32_t *)&ccxs);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* If POLICY.SINGLE_SOCKET is 1 do the following checks
       This check has to go here because it needs the ccxs which get decided above */
    if (guest->policy_snp & SNP_GUEST_POLICY_SINGLE_SOCKET_FLAG)
    {
        /* If the guest is bound to a migration agent, the migration agent must
           already be activated and completing this command must not result in
           activating the guest on a different socket than its migration agent */
        if (ma_paddr != PADDR_INVALID)
        {
            void *ma_gctx_x86_buffer = NULL;
            guest_context_page_t *ma_gctx = NULL;

            /* Map to the migration agent's context page so we can read */
            status = sev_hal_map_guest_context(ma_paddr, &ma_gctx_x86_buffer, PAGE_SIZE_4K);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            ma_gctx = (guest_context_page_t *)ma_gctx_x86_buffer;

            /* Check that the migration agent is activated */
            if (!guest_is_active(&ma_gctx->guest))
            {
                sev_hal_unmap_guest_context(ma_gctx_x86_buffer, PAGE_SIZE_4K);  /* Unmap the ma_gctx_page mem */
                status = SEV_STATUS_POLICY_FAILURE;
                goto end;
            }

            /* Check that the pending ccxs are on the same socket as the MA's activated ccxs */
            if ((CCXS_ON_P0(ma_gctx->guest.ccxs) && CCXS_ON_P1(ccxs)) || /* MA active on P0 and trying to activate on P1 */
                (CCXS_ON_P1(ma_gctx->guest.ccxs) && CCXS_ON_P0(ccxs)))   /* MA active on P1 and trying to activate on P0 */
            {
                sev_hal_unmap_guest_context(ma_gctx_x86_buffer, PAGE_SIZE_4K);  /* Unmap the ma_gctx_page mem */
                status = SEV_STATUS_POLICY_FAILURE;
                goto end;
            }

            /* Unmap the gctx_page mem */
            sev_hal_unmap_guest_context(ma_gctx_x86_buffer, PAGE_SIZE_4K);
        }

        /* Check that completing this command will not result in activating the guest on multiple sockets */
        if ((CCXS_ON_P0(ccxs) && CCXS_ON_P1(ccxs)) ||        /* Trying to activate on P0 and P1 */
            (CCXS_ON_P0(guest->ccxs) && CCXS_ON_P1(ccxs)) || /* Active on P0 and trying to activate on P1 */
            (CCXS_ON_P1(guest->ccxs) && CCXS_ON_P0(ccxs)))   /* Active on P1 and trying to activate on P0 */
        {
            status = SEV_STATUS_POLICY_FAILURE;
            goto end;
        }
    }

    status = activate_common(sev, guest, asid, ccxs);

end:
    return status;
}

/* Supports DebugDecrypt and DebugEncrypt */
static sev_status_t debug_crypt_common(sev_t *sev, sev_guest_t *guest, bool encrypt,
                                       uint64_t src_paddr, uint64_t dst_paddr, uint32_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t bytes_remaining = 0, size = 0;
    uint64_t src = 0, dest = 0;

    if (!sev || !guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (guest_is_inactive(guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    /* Use the scratch buffer as an intermediate buffer for the encryption operation */
    bytes_remaining = length;
    src = src_paddr;
    dest = dst_paddr;

    do
    {
        size = bytes_remaining < SEV_SCRATCH_BUF_LEN ? bytes_remaining
                                                     : SEV_SCRATCH_BUF_LEN;
        if (encrypt)
            status = encrypt_memory(src, dest, gpSevScratchBuf, size, guest->asid);
        else
            status = decrypt_memory(src, dest, gpSevScratchBuf, size, guest->asid);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        bytes_remaining -= size;
        src += size;
        dest += size;
    } while (bytes_remaining > 0);

end:
    return status;
}

/* -------------------------- SEV Functions -------------------------- */
/**
 * The platform must be in the PSTATE.UNINIT state.
 *
 * The firmware first loads the persistent state into its private memory, and
 * then performs the following actions:
 *  - The CEK is derived from the chip unique values.
 *  - If no OCA certificate exists, an OCA signing key is generated and a
 *    self-signed OCA certificate is created. The signing is written to
 *    persistent memory.
 *  - If no PEK exists or the OCA was just regenerated, a PEK signing key is
 *    generated and a PEK certificate is created and signed by the OCA and CEK.
 *    The PEK and its certificate are written to persistent memory.
 *  - A new PDH key is generated unconditionally. A certificate is created for
 *    the PDH and is signed by the PEK.
 *  - All SEV-related ASIDs on all cores are marked invalid. Each core requires
 *    a WBINVD before activating any guest. See ACTIVATE and DEACTIVATE.
 *  - If CONFIG.ES=1, then the TMR region is made inaccessible by the x86 and
 *    will be used for SEV-ES related operations.
 *
 *  Upon successful completion, the platform transitions to the PSTATE.INIT state.
 */
static sev_status_t sev_mcmd_init_common(sev_t *sev, sev_mcmd_t *cmd, bool is_init_ex)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool update_storage = false;
    bool init_valid = false;
    bool rc = false;
    uint16_t flags = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_UNINIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Need mcm_info to know which UMCs to skip checking during umc_encryption_enabled() */
    status = sev_init(sev);
    if (status != SEV_STATUS_SUCCESS)
        goto end;


    /* Bergamo is not supported in BL versions less than MIN_BL_VERSION_BERGAMO */
    if ((gPersistent.bl_fw_version < MIN_BL_VERSION_BERGAMO) &&
        (gPersistent.soc_version >= RSDN_A0_SOC_VER_VAL))
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    /*
     * We are cleared to do the INIT. Beyond here, goto exit_sev_init_invalid
     * on error. That clears sev state back to Shutdown condition.
     * Don't do that above here!
     */

    /* Hardware check */
    if (!umc_encryption_enabled() || !sme_is_enabled_all_cores() || gPersistent.smke_enabled)
    {
        status = SEV_STATUS_HARDWARE_PLATFORM;
        goto exit_sev_init_invalid;
    }

    /* Validate the command buffer */
    rc = (is_init_ex) ? init_ex_cmd_buf_valid(&cmd->sev_init_ex) :
                        init_cmd_buf_valid(&cmd->sev_init);
    if (rc == false)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto exit_sev_init_invalid;
    }

    /*
     * If SNPEn is set, the RMP table must be initialized up before calling SEVInit.
     * Even if SNPShutdown is called, the RMP will still be set/up protected until the
     * next SNPInit, so there is no chance for SEV to be able to modify the RMP.
     * To know it's been set up, check that the page state of RMP_BASE is FIRMWARE.
     */
    if (snp_is_enabled_all_cores())
    {
        status = get_rmp_bounds();  /* Global vars may have gotten cleared during dlfw */
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        if (!is_rmp_table_initialized())
        {
            status = SEV_STATUS_INVALID_PLATFORM_STATE;
            goto exit_sev_init_invalid;
        }
    }

    /* Need to populate sev->sev.init_ex_nv_paddr before persistent access */
    if (!is_init_ex)
    {
        sev->sev.init_ex_nv_paddr = SEV_PERSISTENT_SPI_DEV;    /* INIT: SPI access. */
    }
    else
    {
        /* INIT_EX: First, validate command buffer parameters. */
        if (cmd->sev_init_ex.iex_len != SEV_INIT_EX_CMD_LEN)
        {
            status = SEV_STATUS_INVALID_LENGTH;
            goto exit_sev_init_invalid;
        }
        if (cmd->sev_init_ex.nv_paddr != SEV_PERSISTENT_SPI_DEV)
        {
            if (!IS_ALIGNED_TO_4KB(cmd->sev_init_ex.nv_paddr))
            {
                status = SEV_STATUS_INVALID_ADDRESS;
                goto exit_sev_init_invalid;
            }

            status = validate_address_range(cmd->sev_init_ex.nv_paddr,
                                            cmd->sev_init_ex.nv_length);
            if (status != SEV_STATUS_SUCCESS)
                goto exit_sev_init_invalid;

            if (cmd->sev_init_ex.nv_length != SEV_INIT_EX_NV_LEN)
            {
                status = SEV_STATUS_INVALID_LENGTH;
                goto exit_sev_init_invalid;
            }
        }
        sev->sev.init_ex_nv_paddr = cmd->sev_init_ex.nv_paddr;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        if (is_init_ex)
        {
            status = check_page_range_firmware_writable(cmd->sev_init_ex.nv_paddr,
                                                        cmd->sev_init_ex.nv_length);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

    /*
     * The data might not always exist. Ex, PLATFORM_RESET clears the
     * Persistent OCA, PEK, PDH, etc
     */
    status = sev_persistent_store_retrieve(sev->sev.init_ex_nv_paddr,
                                          &sev->sev.identity.persistent);
    if (status != SEV_STATUS_SUCCESS && status != ERR_SECURE_DATA_NON_EXIST)
    {
        if (status == SEV_STATUS_SECURE_DATA_INVALID)
        {
            /* INIT_EX NV area: Before returning that error, erase the area. */
            (void)sev_persistent_store_delete(sev->sev.init_ex_nv_paddr);
        }
        goto exit_sev_init_invalid;
    }

    /* Derive the CEK unconditionally */
    status = sev_cek_derive(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    if (!sev_cert_has_pubkey(&sev->sev.identity.persistent.oca_cert))
    {
        /* Generate a new OCA key and certificate */
        status = sev_oca_generate(&sev->sev.identity);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /* Delete the old PEK and generate a new one below */
        status = sev_pek_delete(&sev->sev.identity);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        update_storage = true;
    }

    if (!sev_cert_has_pubkey(&sev->sev.identity.persistent.pek_cert))
    {
        /* Generate and sign a new PEK */
        status = sev_pek_generate(&sev->sev.identity);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /* Delete the old PDH and generate a new one below */
        status = sev_pdh_delete(&sev->sev.identity);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        update_storage = true;
    }

    if (!sev_cert_has_pubkey(&sev->sev.identity.persistent.pdh_cert))
    {
        /* Generate and sign a new PDH */
        status = sev_pdh_generate(&sev->sev.identity);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        update_storage = true;
    }

    /* Update the persistent storage with any new keys and certificates */
    if (update_storage)
    {
        status = sev_persistent_store_save(sev->sev.init_ex_nv_paddr,
                                          &sev->sev.identity.persistent);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;
    }

    /* ASID initialization should be run only by SEV_INIT or SNP_INIT when
       both are in UNINIT state */
    if (gpDram->perm.snp_state == SNP_STATE_UNINIT)
    {
        /* Synchronize APICID Table between master and slave */
        /* CCX population. */
        status = sync_apicid_tables(sev);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /* Mark ASIDs invalid on all the dies */
        status = mark_all_asids_invalid();
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /* Clear WBINVD_DONE bits on all dies */
        status = clear_wbinvd_done(gPersistent.ccx_present_bit_mask);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /*
         * Init state of all ASIDs/CCXs to 'dirty', not 'clean', not 'in-use',
         * and not 'allocated'.
         */
        for (uint32_t i = 0; i < SEV_ASID_ARRAY_SIZE; i++)
        {
            gpDram->perm.asid_dirty[i] = gPersistent.ccx_present_bit_mask;
            gpDram->perm.asid_clean[i] = 0;
            gpDram->perm.asid_allocated[i] = 0;
            gpDram->perm.asid_in_use[i] = 0;
        }
    }

    /* TMR reservation for SEV ES */
    flags = is_init_ex ? cmd->sev_init_ex.flags : cmd->sev_init.flags;
    if (flags & SEV_CONFIG_ES_FLAG)
    {
        uint64_t tmr_paddr, tmp_tmr_addr, tmp_nv_addr, tmr_end_addr, nv_end_addr;
        uint32_t tmr_length;

        if (is_init_ex)
        {
            tmr_paddr = cmd->sev_init_ex.tmr_paddr;
            tmr_length = cmd->sev_init_ex.tmr_length;

            /* First, if not using SPI, make sure the TMR and the NV storage
               do not overlap. Want to do this before TMR reserve. */
            if (cmd->sev_init_ex.nv_paddr)
            {
                /* Mainly to make sure no unwanted bits are set. */
                status = validate_address_range(tmr_paddr, tmr_length);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_sev_init_invalid;

                /* Compare TMR and NV buffer ranges ignoring C-bit. */
                tmp_tmr_addr = tmr_paddr;
                if (is_rmp_table_initialized())
                    tmr_end_addr = tmp_tmr_addr + SEV_ES_TMR_SIZE_SNP - 1ULL;
                else
                    tmr_end_addr = tmp_tmr_addr + SEV_ES_TMR_SIZE - 1ULL;

                tmp_nv_addr = cmd->sev_init_ex.nv_paddr;
                nv_end_addr = tmp_nv_addr + SEV_INIT_EX_NV_LEN - 1ULL;

                /* Check for overlap and ignore the C-bit */
                if (ranges_overlap(tmp_tmr_addr, tmr_end_addr, tmp_nv_addr, nv_end_addr))
                {
                    status = SEV_STATUS_INVALID_ADDRESS;
                    goto exit_sev_init_invalid;
                }
            }
        }
        else
        {
            tmr_paddr = cmd->sev_init.tmr_paddr;
            tmr_length = cmd->sev_init.tmr_length;
        }

        /* Check page state if SNP is initialized  */
        if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
        {
            if (flags & SEV_CONFIG_ES_FLAG)
            {
                status = check_page_range_firmware_writable(tmr_paddr, tmr_length);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
            }
        }

        status = sev_es_reserve_trusted_region(&sev->sev.es, tmr_paddr, tmr_length);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /*
         * Don't initialize the pool here. We need to force a WBINVD and
         * DF_FLUSH before it is safe to store data in the TMR.
         */
    }

    /* Advance the platform state machine */
    status = sev_state_transition(sev, SEV_MCMD_ID_INIT);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* No errors. */
    sev->sev.config_flags = is_init_ex ? cmd->sev_init_ex.flags : cmd->sev_init.flags;
    init_valid = true;

exit_sev_init_invalid:
    if (init_valid == false)    /* Clear sev state to Shutdown condition. */
    {
        (void)sev_clear(sev);
    }

end:
    return status;
}

/* Supports LaunchUpdateData and LaunchUpdateVMSA */
static sev_status_t launch_update_common(sev_t *sev, sev_mcmd_t *cmd, bool is_vmsa)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_launch_update_t *lud = NULL;
    sev_guest_t *guest = NULL;
    uint32_t size = 0, bytes_remaining = 0;
    uint64_t x86_addr = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    lud = &cmd->sev_launch_update;
    if (!handle_is_valid(lud->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, lud->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_LUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (is_vmsa && !sev_es_guest_enabled(guest))    /* Your Guest/Policy must support ES */
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    if (guest_is_inactive(guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    if (!IS_ALIGNED_TO_16_BYTES(lud->paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    if (!IS_ALIGNED_TO_16_BYTES(lud->length) || (lud->length == 0))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(lud->paddr, lud->length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Enable rd_sz_wbinvd around copy_from_x86. Reading in unencrypted and
       writing out encrypted from same page so don't need a dummy read on dst */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Use the scratch buffer as an intermediate buffer for the encryption
     * operation. If the request is larger than the scratch buffer size, break
     * the operation into scratch-buffer-sized chunks.
     */
    bytes_remaining = lud->length;
    x86_addr = lud->paddr;
    do
    {
        size = bytes_remaining < SEV_SCRATCH_BUF_LEN ? bytes_remaining
                                                     : SEV_SCRATCH_BUF_LEN;

        /* Copy the data to PSP private memory */
        status = copy_from_x86(x86_addr, gpSevScratchBuf, size);
        if (status != SEV_STATUS_SUCCESS)
            goto end1;

        /* Measure the (unaltered) guest data */
        status = SW_SHA256_Process(&guest->sw_sha_ctx, gpSevScratchBuf, size);
        if (status != SEV_STATUS_SUCCESS)
            goto end1;

        if (is_vmsa)
        {
            /* Setup the VMSA for use with SEV-ES */
            status = sev_es_setup_vmsa(&sev->sev.es, guest, gpSevScratchBuf, size);
            if (status != SEV_STATUS_SUCCESS)
                goto end1;

            /*
             * Only prepare the VMSA once. Any left over memory should be
             * encrypted normally.
             */
            is_vmsa = false;
        }

        /* Encrypt the data using the UMC */
        status = copy_to_x86_encrypted(x86_addr, gpSevScratchBuf, size,
                                       guest->asid);
        if (status != SEV_STATUS_SUCCESS)
            goto end1;

        bytes_remaining -= size;
        x86_addr += size;
    } while (bytes_remaining > 0);

end1:
    /* Clear the rd_sz_wbinvd */
    set_misc_read_sized_wrbkinvd(false);

end:
    return status;
}

sev_status_t sev_mcmd_init(sev_t *sev, sev_mcmd_t *cmd)
{
    return sev_mcmd_init_common(sev, cmd, false); /* not init_ex */
}

sev_status_t sev_mcmd_shutdown(sev_t *sev, sev_mcmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Ensure that the platform state is reset */
    status = sev_state_transition(sev, SEV_MCMD_ID_SHUTDOWN);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Clear non-persistent platform/guest state.
     * NOTE: This also effectively resets the platform state to UNINIT.
     * Will also mark SEV asids as invalid (and decommission all SEV guests)
     *  before when we release the TMR.
     * NOTE: Don't affect SNP guests
     */
    status = sev_clear(sev);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_HARDWARE_UNSAFE;
        goto end;
    }

    /* This is redundant, but ensure that the platform state is reset */
    status = sev_state_transition(sev, SEV_MCMD_ID_SHUTDOWN);

end:
    return status;
}

sev_status_t sev_mcmd_platform_reset(sev_t *sev, sev_mcmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_UNINIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* SPI device only. */
    status = sev_persistent_store_delete(SEV_PERSISTENT_SPI_DEV);

end:
    return status;
}

sev_status_t sev_mcmd_platform_status(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_platform_status_t *ps = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(cmd, 0, sizeof(*cmd));
    ps = &cmd->sev_platform_status;
    ps->api_major = SEV_API_MAJOR;
    ps->api_minor = SEV_API_MINOR;
    ps->state = sev->sev.state;
    ps->platform_flags = sev->sev.identity.persistent.is_ext_owned & SEV_PLATFORM_OWNER_FLAG;
    ps->config_flags = sev->sev.config_flags;
    ps->build_id = SEV_BUILD_ID;
    ps->guest_count = sev->sev.guest_count;

    if (sev->sev.state == SEV_STATE_UNINIT)
    {
        /* These values are invalid if we aren't initialized */
        ps->platform_flags &= ~SEV_PLATFORM_OWNER_FLAG;
        ps->config_flags &= ~SEV_CONFIG_ES_FLAG;
        ps->guest_count = 0;
    }

end:
    return status;
}

sev_status_t sev_mcmd_pek_gen(sev_t *sev, sev_mcmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_identity_t *new_identity = (sev_identity_t *)gpSevScratchBuf;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    memcpy(new_identity, &sev->sev.identity, sizeof(*new_identity));

    /* Generate a new OCA key and certificate */
    status = sev_oca_generate(new_identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Generate and sign a new PEK */
    status = sev_pek_generate(new_identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Generate PDH & certificate */
    status = sev_pdh_generate(new_identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Update the persistent storage with the new keys and certificates */
    status = sev_persistent_store_save(sev->sev.init_ex_nv_paddr,
                                       &new_identity->persistent);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the platform identity into place */
    memcpy(&sev->sev.identity, new_identity, sizeof(sev->sev.identity));

end:
    secure_memzero(new_identity, sizeof(*new_identity));  /* Clear the key(s) from scratch space */
    return status;
}

sev_status_t sev_mcmd_pek_csr(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_pek_csr_t *pc = NULL;
    sev_cert_t csr, *pek = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    pc = &cmd->pek_csr;
    if (pc->pek_csr_len < sizeof(csr))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto exit_store_length;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(pc->pek_csr_paddr, pc->pek_csr_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    status = sev_cert_init(&csr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    pek = &sev->sev.identity.persistent.pek_cert;
    memcpy(&csr.body, &pek->body, sizeof(csr.body));

    status = copy_to_x86(pc->pek_csr_paddr, &csr, sizeof(csr));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

exit_store_length:
    pc->pek_csr_len = sizeof(csr);

end:
    return status;
}

sev_status_t sev_mcmd_pek_cert_import(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_pek_cert_import_t *import = NULL;
    import_scratch_t *scratch = (import_scratch_t *)gpSevScratchBuf;
    sev_cert_t *pek = NULL, *oca = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    if (sev->sev.identity.persistent.is_ext_owned)
    {
        status = SEV_STATUS_ALREADY_OWNED;
        goto end;
    }

    import = &cmd->pek_cert_import;

    if (import->pek_cert_len != sizeof(scratch->pek) ||
        import->oca_cert_len != sizeof(scratch->oca))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Import the PEK */
    status = copy_from_x86(import->pek_cert_paddr, &scratch->pek,
                           sizeof(scratch->pek));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Import the OCA */
    status = copy_from_x86(import->oca_cert_paddr, &scratch->oca,
                           sizeof(scratch->oca));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the certificates */
    status = sev_cert_validate(&scratch->oca, &scratch->oca.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_validate(&scratch->pek, &scratch->oca.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Ensure that the PEK wasn't altered outside of the firmware */
    pek = &sev->sev.identity.persistent.pek_cert;
    if (memcmp(&scratch->pek.body, &pek->body, sizeof(pek->body)) != 0)
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* The PEK checks out, so transfer the CEK signature */
    if (pek->sig1.usage == SEV_CERT_USAGE_CEK)
        status = sev_cert_set_sig(&scratch->pek, &pek->sig1);
    else if (pek->sig2.usage == SEV_CERT_USAGE_CEK)
        status = sev_cert_set_sig(&scratch->pek, &pek->sig2);
    else
        status = SEV_STATUS_INVALID_CERTIFICATE;

    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Save a copy of the current persistent state */
    memcpy(&scratch->saved, &sev->sev.identity.persistent, sizeof(scratch->saved));

    /* Store the new certificates */
    oca = &sev->sev.identity.persistent.oca_cert;
    memcpy(pek, &scratch->pek, sizeof(*pek));
    memcpy(oca, &scratch->oca, sizeof(*oca));
    sev->sev.identity.persistent.is_ext_owned |= SEV_PLATFORM_OWNER_FLAG;

    /* Regenerate the PDH and sign with the new certificates */
    status = sev_pdh_generate(&sev->sev.identity);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_restore_state;

    /* Save the new certificates to persistent storage */
    status = sev_persistent_store_save(sev->sev.init_ex_nv_paddr,
                                       &sev->sev.identity.persistent);

exit_restore_state:
    if (status != SEV_STATUS_SUCCESS)
    {
        /* Restore the old state before we exit */
        memcpy(&sev->sev.identity.persistent, &scratch->saved, sizeof(scratch->saved));
    }

end:
    return status;
}

/* Only used in sev_mcmd_pdh_cert_export */
static sev_status_t pdh_cert_chain_init(sev_t *sev, pdh_cert_chain_t *chain)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_t cek_cert;
    sev_cert_pubkey_t cek_pubkey;

    if (!sev || !chain)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Create a dummy CEK certificate without a signature. */
    status = sev_cert_keypair_get_pubkey(&sev->sev.identity.cek, &cek_pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_create(&cek_cert, &cek_pubkey, NULL);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memcpy(&chain->pek, &sev->sev.identity.persistent.pek_cert, sizeof(chain->pek));
    memcpy(&chain->oca, &sev->sev.identity.persistent.oca_cert, sizeof(chain->oca));
    memcpy(&chain->cek, &cek_cert, sizeof(chain->cek));

end:
    return status;
}

/* Only used in sev_mcmd_pdh_cert_export */
static sev_status_t write_pdh_cert_chain(pdh_cert_chain_t *chain,
                                         uint64_t x86_addr, size_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!chain)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (size < sizeof(*chain))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    status = copy_to_x86(x86_addr, chain, sizeof(*chain));

end:
    return status;
}

sev_status_t sev_mcmd_pdh_cert_export(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    pdh_cert_chain_t *chain = (pdh_cert_chain_t *)gpSevScratchBuf;
    sev_mcmd_pdh_cert_export_t *exp = NULL;
    sev_cert_t *pdh = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    exp = &cmd->pdh_cert_export;
    pdh = &sev->sev.identity.persistent.pdh_cert;

    if (exp->pdh_cert_len < sizeof(*pdh) || exp->certs_len < sizeof(*chain))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto exit_store_lengths;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(exp->pdh_cert_paddr, exp->pdh_cert_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = check_page_range_firmware_writable(exp->cert_chain_paddr, exp->certs_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    status = copy_to_x86(exp->pdh_cert_paddr, pdh, sizeof(*pdh));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = pdh_cert_chain_init(sev, chain);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = write_pdh_cert_chain(chain, exp->cert_chain_paddr, exp->certs_len);
    if (status != SEV_STATUS_SUCCESS && status != SEV_STATUS_INVALID_LENGTH)
        goto end;

exit_store_lengths:
    exp->pdh_cert_len = sizeof(*pdh);
    exp->certs_len = sizeof(*chain);

end:
    return status;
}

sev_status_t sev_mcmd_pdh_gen(sev_t *sev, sev_mcmd_t *ignored)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_identity_t *new_identity = (sev_identity_t *)gpSevScratchBuf;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    memcpy(new_identity, &sev->sev.identity, sizeof(*new_identity));

    /* Generate PDH & certificate */
    status = sev_pdh_generate(new_identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Update the persistent storage with the new keys and certificates */
    status = sev_persistent_store_save(sev->sev.init_ex_nv_paddr,
                                       &new_identity->persistent);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the platform identity into place */
    memcpy(&sev->sev.identity, new_identity, sizeof(sev->sev.identity));

end:
    secure_memzero(new_identity, sizeof(*new_identity));  /* Clear the key(s) from scratch space */
    return status;
}

sev_status_t sev_mcmd_df_flush(sev_t *sev, sev_mcmd_t *ignored)
{
    return mcmd_df_flush_common(sev);
}

sev_status_t sev_mcmd_download_firmware(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    SEV_FW_IMAGE_HEADER hdr;

    if (!sev || !cmd)
        return ERR_INVALID_PARAMS;

    /* Both SEV and SNP platform states have to be UNINIT */
    if ((sev->sev.state != SEV_STATE_UNINIT) || (gpDram->perm.snp_state != SNP_STATE_UNINIT))
        return SEV_STATUS_INVALID_PLATFORM_STATE;

    sev_mcmd_download_firmware_t *dlfw = &cmd->download_firmware;
    uint64_t x86_addr = dlfw->firmware_paddr;
    uint32_t size = dlfw->firmware_len;

    /* Make sure reserve field is clear */
    if (!IS_ALIGNED_TO_32_BYTES(x86_addr))
        return SEV_STATUS_INVALID_ADDRESS;

    status = copy_from_x86(x86_addr, &hdr, sizeof(hdr));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_hal_cache_new_image( x86_addr, size, SEV_NEWFW_LOAD_AND_COMMIT );
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Update the CommittedTCB, CommittedVersion from the NEW image */
    update_committed_versions(&hdr);

end:
    return status;
}

sev_status_t sev_mcmd_get_id(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_get_id_t *gi = NULL;

    uint32_t bytes_wrote = 0;

    if (!sev || !cmd)
        return ERR_INVALID_PARAMS;

    gi = &cmd->get_id;

    if (gi->id_len < sizeof(get_id_t))
    {
        gi->id_len = sizeof(get_id_t);
        return SEV_STATUS_INVALID_LENGTH;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(gi->id_paddr, gi->id_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Calculate the GetID and put it in gpSevScratchBuf */
    status = sev_get_id(gi->id_len, gpSevScratchBuf, &bytes_wrote);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    /* Copy the 32-byte x and y values to the ID */
    status = copy_to_x86(gi->id_paddr, gpSevScratchBuf, bytes_wrote);
    if (status != SEV_STATUS_SUCCESS)
    {
        goto end;
    }

    gi->id_len = bytes_wrote;

end:
    return status;
}

sev_status_t sev_mcmd_init_ex(sev_t *sev, sev_mcmd_t *cmd)
{
    return sev_mcmd_init_common(sev, cmd, true); /* is init_ex */
}

sev_status_t sev_mcmd_nop(sev_t *sev, sev_mcmd_t *ignored)
{
    return SEV_STATUS_SUCCESS;
}

sev_status_t sev_mcmd_ring_buffer(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_ring_buffer_t *ring_cmd = NULL;

    sev_rb_tail_t x86_tail;
    sev_rb_head_t sev_head;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ring_cmd = &cmd->ring_buffer;

    /* Must be in SEV INIT or WORKING state or SNP INIT state */
    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING &&
        gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Cannot call the function if it's already enabled */
    if (gpDram->perm.rb_config.rb_enable)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Must be only one page */
    if ((ring_cmd->low_priority_queue_size != 1) ||
        (ring_cmd->high_priority_queue_size != 0 && ring_cmd->high_priority_queue_size != 1))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Pages must be 4K aligned */
    if (!IS_ALIGNED_TO_4KB(ring_cmd->low_priority_cmd_ptr) ||
        !IS_ALIGNED_TO_4KB(ring_cmd->low_priority_status_ptr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }
    if (ring_cmd->high_priority_queue_size != 0)
    {
        if (!IS_ALIGNED_TO_4KB(ring_cmd->high_priority_cmd_ptr) ||
            !IS_ALIGNED_TO_4KB(ring_cmd->high_priority_status_ptr))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }
    }

    /* Make sure all addresses are valid */
    status = validate_address_range(ring_cmd->low_priority_cmd_ptr, PAGE_SIZE_4K*ring_cmd->low_priority_queue_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = validate_address_range(ring_cmd->low_priority_status_ptr, PAGE_SIZE_4K*ring_cmd->low_priority_queue_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (ring_cmd->high_priority_queue_size != 0)
    {
        status = validate_address_range(ring_cmd->high_priority_cmd_ptr, PAGE_SIZE_4K*ring_cmd->high_priority_queue_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = validate_address_range(ring_cmd->high_priority_status_ptr, PAGE_SIZE_4K*ring_cmd->high_priority_queue_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(ring_cmd->low_priority_status_ptr, PAGE_SIZE_4K*ring_cmd->low_priority_queue_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        if (ring_cmd->high_priority_queue_size)
        {
            status = check_page_range_firmware_writable(ring_cmd->high_priority_status_ptr, PAGE_SIZE_4K*ring_cmd->high_priority_queue_size);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

    /* Clear the global config register */
    memset(&gpDram->perm.rb_config, 0, sizeof(sev_rb_config_t));

    /* Save addresses and convert them from C-BIT to the appropriate SME ASID */
    gpDram->perm.rb_config.cmd_ptr_low_priority_addr = ring_cmd->low_priority_cmd_ptr;
    status = convert_x86_address(&gpDram->perm.rb_config.cmd_ptr_low_priority_addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gpDram->perm.rb_config.status_ptr_low_priority_addr = ring_cmd->low_priority_status_ptr;
    gpDram->perm.rb_config.status_ptr_low_priority_reclaim = gpDram->perm.rb_config.status_ptr_low_priority_addr; /* Save address for reclaim */
    status = convert_x86_address(&gpDram->perm.rb_config.status_ptr_low_priority_addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (ring_cmd->high_priority_queue_size != 0)
    {
        gpDram->perm.rb_config.cmd_ptr_high_priority_addr = ring_cmd->high_priority_cmd_ptr;
        status = convert_x86_address(&gpDram->perm.rb_config.cmd_ptr_high_priority_addr);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        gpDram->perm.rb_config.status_ptr_high_priority_addr = ring_cmd->high_priority_status_ptr;
        gpDram->perm.rb_config.status_ptr_high_priority_reclaim = gpDram->perm.rb_config.status_ptr_high_priority_addr; /* Save address for reclaim */
        status = convert_x86_address(&gpDram->perm.rb_config.status_ptr_high_priority_addr);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Save thresholds */
    gpDram->perm.rb_config.low_queue_threshold = ring_cmd->low_q_threshold;
    if (ring_cmd->high_priority_queue_size != 0)
    {
        gpDram->perm.rb_config.high_queue_threshold = ring_cmd->high_q_threshold;
    }
    if (ring_cmd->int_on_empty & 1)
        gpDram->perm.rb_config.int_on_empty = true;
    else
        gpDram->perm.rb_config.int_on_empty = false;

    /* Save queue sizes */
    gpDram->perm.rb_config.low_priority_queue_size = ring_cmd->low_priority_queue_size;
    gpDram->perm.rb_config.high_priority_queue_size = ring_cmd->high_priority_queue_size;

    /* Write Mailboxes */
    sev_head.u.val = 0;
    sev_head.u.field.lo_queue_running = 1;
    if (ring_cmd->high_priority_queue_size == 0)
        sev_head.u.field.hi_queue_running = 0;
    else
        sev_head.u.field.hi_queue_running = 1;

    x86_tail.u.val = 0;
    WriteReg32(SEV_CMD_RB_X86_TAIL, x86_tail.u.val);
    WriteReg32(SEV_CMD_RB_SEV_HEAD, sev_head.u.val);

    /* Store values in gPersistent */
    gpDram->perm.rb_config.state.sev_head.u.val = sev_head.u.val;

    /* Enable Ring Buffer Mode - Note, this would only be active on the next command */
    gpDram->perm.rb_config.rb_enable = true;

end:
    return status;
}

sev_status_t sev_mcmd_decommission(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_decommission_t *dc = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    dc = &cmd->sev_decommission;
    if (!handle_is_valid(dc->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, dc->handle); /* Guest should not be NULL because we validated the handle */

    status = mcmd_decommission_common(sev, guest);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Advance the platform state machine */
    if (sev->sev.guest_count == 0)
        status = sev_state_transition(sev, SEV_MCMD_ID_DECOMMISSION);

end:
    return status;
}

sev_status_t sev_mcmd_activate(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_activate_t *act = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    act = &cmd->sev_activate;
    if (!handle_is_valid(act->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, act->handle); /* Guest should not be NULL because we validated the handle */

    /* This command selects ALL CCXs. */
    status = mcmd_activate_common(sev, guest, act->asid);

end:
    return status;
}

sev_status_t sev_mcmd_deactivate(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_deactivate_t *da = NULL;
    sev_guest_t *guest = NULL;
    uint32_t asid = 0;
    uint32_t ccxs = 0;
    uint32_t tmp_ccxs = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    da = &cmd->sev_deactivate;
    if (!handle_is_valid(da->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, da->handle); /* Guest should not be NULL because we validated the handle */
    asid = guest->asid;
    ccxs = guest->ccxs;

    if (guest_is_inactive(guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    status = sev_guest_deactivate(guest, gpDram->perm.asid_in_use[asid-1]);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    tmp_ccxs = gpDram->perm.asid_allocated[asid-1] & ccxs;
    if (tmp_ccxs)
    {
        /* These CCXs never made it to Running.
           Allocated but never used CCXs: Clean */
        gpDram->perm.asid_allocated[asid-1] &= ~tmp_ccxs;
        gpDram->perm.asid_clean[asid-1] |= tmp_ccxs;
    }
    tmp_ccxs = gpDram->perm.asid_in_use[asid-1] & ccxs;
    if (tmp_ccxs)
    {
        /* Has been Running: InUse CCXs Dirty. */
        gpDram->perm.asid_in_use[asid-1] &= ~tmp_ccxs;
        gpDram->perm.asid_dirty[asid-1] |= tmp_ccxs;
    }

end:
    return status;
}

sev_status_t sev_mcmd_guest_status(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_guest_status_t *gs = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    gs = &cmd->sev_guest_status;
    if (!handle_is_valid(gs->handle))
    {
        gs->state = SEV_GUEST_STATE_INVALID;
        goto end;
    }

    guest = sev_get_guest(sev, gs->handle); /* Guest should not be NULL because we validated the handle */
    gs->state = guest->sev_state;
    gs->asid = guest_has_asid(guest) ? guest->asid : 0;
    gs->policy = guest->policy;

end:
    return status;
}

sev_status_t sev_mcmd_copy(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_guest_t *guest = NULL;
    sev_mcmd_copy_t *cpy = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    cpy = &cmd->sev_copy;
    if (!handle_is_valid(cpy->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, cpy->handle); /* Guest should not be NULL because we validated the handle */
    if (guest_is_inactive(guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    if ((!cpy->length) || (cpy->length % SEV_COPY_LENGTH_MULT))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if ((cpy->src_paddr & SEV_COPY_ALIGN_MBZ_MASK) ||
        (cpy->dst_paddr & SEV_COPY_ALIGN_MBZ_MASK))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(cpy->dst_paddr, cpy->length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    if (ranges_overlap(cpy->src_paddr, cpy->src_paddr + PAGE_SIZE_4K - 1ULL,    /* Immediate success */
                       cpy->dst_paddr, cpy->dst_paddr + PAGE_SIZE_4K - 1ULL))
    {
        status = SEV_STATUS_SUCCESS;
        goto end;
    }

    status = copy_to_x86_encrypted_from_x86_encrypted(cpy->dst_paddr, cpy->src_paddr,
                                                      cpy->length, guest->asid);

end:
    return status;
}

sev_status_t sev_mcmd_activate_ex(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_activate_ex_t *act = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    act = &cmd->sev_activate_ex;

    if (act->ex_len != sizeof(*act))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (!handle_is_valid(act->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, act->handle); /* Guest should not be NULL because we validated the handle */

    status = mcmd_activate_ex_common(sev, guest, act->asid, act->numids, act->ids_paddr, PADDR_INVALID);

end:
    return status;
}

/**
 * Due to alignment requirements for 'ld' in guest array in PSP DRAM,
 * compiler decided that any sev_guest_t must be so aligned, although
 * that is not the case in SRAM. Compiler/linker will not align auto
 * variable beyond 8 byte alignment, so use flexible buffer for 'new_guest'.
 */
sev_status_t sev_mcmd_launch_start(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t new_handle = 0;
    uint8_t tmp_guest_buf[sizeof(sev_guest_t) + GUEST_MIN_ALIGN];
    sev_guest_t *new_guest = (sev_guest_t *)ALIGN_TO_16_BYTES(tmp_guest_buf);
    uint32_t new_policy = 0;
    uint32_t shared_policy = 0;
    uint32_t shared_handle = 0;
    sev_guest_t *free_guest = NULL;
    sev_mcmd_launch_start_t *ls = NULL;
    sev_session_t session;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    ls = &cmd->sev_launch_start;
    memset(new_guest, 0, sizeof(*new_guest));

    /* Initialize the head and tail index */
    new_guest->es.head_index = INVALID_BLOCK;
    new_guest->es.tail_index = INVALID_BLOCK;

    memset(&session, 0, sizeof(session));
    new_policy = ls->policy;
    shared_handle = ls->handle;

    /* Establish transport keys for this channel */
    if (ls->dh_cert_paddr != 0)
    {
        sev_cert_t dh_cert;

        memset(&dh_cert, 0, sizeof(dh_cert));

        /* Validate the session parameters */
        if (ls->session_len != sizeof(session))
        {
            status = SEV_STATUS_INVALID_LENGTH;
            goto end;
        }

        /* Copy the session parameters */
        status = copy_from_x86(ls->session_paddr, &session, ls->session_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Validate the client certificate */
        if (ls->dh_cert_len != sizeof(sev_cert_t))
        {
            status = SEV_STATUS_INVALID_LENGTH;
            goto end;
        }

        /* Copy the client certificate */
        status = copy_from_x86(ls->dh_cert_paddr, &dh_cert, ls->dh_cert_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Establish the trusted channel */
        status = sev_channel_open_server(&sev->sev.identity.persistent.pdh,
                                         &dh_cert, &session, &new_guest->channel);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Integrity check the policy with the MAC. */
        status = sev_guest_verify_policy(new_policy, &session.policy_mac,
                                         &new_guest->channel);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    new_guest->policy = new_policy;

    if (shared_handle == 0)
    {
        /* Generate a new VEK seed */
        status = sev_hal_trng(new_guest->umc_key_seed, sizeof(new_guest->umc_key_seed));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        sev_guest_t *shared_guest = NULL;

        if (!handle_is_valid(shared_handle))
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto end;
        }

        shared_guest = sev_get_guest(sev, shared_handle);
        shared_policy = shared_guest->policy;

        if ((new_policy != shared_policy) ||
            (shared_policy & SEV_GUEST_POLICY_NOKS_FLAG))    /* No key sharing */
        {
            status = SEV_STATUS_POLICY_FAILURE;
            goto end;
        }

        /* Share a key with the specified guest */
        memcpy(&new_guest->umc_key_seed, &shared_guest->umc_key_seed,
               sizeof(new_guest->umc_key_seed));
    }

    /* Allocate a new guest handle */
    status = find_free_guest_handle(sev->sev.guests, SEV_GUEST_COUNT_MAX, &new_handle);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    new_guest->handle = new_handle;
    status = SW_SHA256_Init(&new_guest->sw_sha_ctx);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (new_policy & SEV_GUEST_POLICY_ES_FLAG)
    {
        /* Check if SEV-ES is enabled for this platform */
        if (!sev_es_platform_enabled(sev))
        {
            status = SEV_STATUS_UNSUPPORTED;
            goto end;
        }

        /* Enable SEV-ES for this guest */
        new_guest->guest_flags |= (SEV_GUEST_FLAGS_ES_FLAG | SEV_GUEST_FLAGS_ES_POOL_ALLOC_FLAG);
    }

    /* Generate new Offline Encryption Key */
    status = sev_hal_trng(new_guest->oek, sizeof(new_guest->oek));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Advance the guest and platform state machines */
    status = sev_guest_state_transition(new_guest, SEV_MCMD_ID_LAUNCH_START);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_state_transition(sev, SEV_MCMD_ID_LAUNCH_START);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Now that all checks have passed, commit the new guest state */
    free_guest = sev_get_guest(sev, new_handle);
    memcpy(free_guest, new_guest, sizeof(*free_guest));
    sev->sev.guest_count++;
    ls->handle = new_handle;

end:
    /* Clear any secrets from memory before we exit */
    secure_memzero(&session, sizeof(session));
    secure_memzero(new_guest, sizeof(*new_guest));

    return status;
}

sev_status_t sev_mcmd_launch_update_data(sev_t *sev, sev_mcmd_t *cmd)
{
    return launch_update_common(sev, cmd, false);
}

sev_status_t sev_mcmd_launch_update_vmsa(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_launch_update_t *luv = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    luv = &cmd->sev_launch_update;
    if (luv->length != VMSA_SIZE)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

end:
    return status == SEV_STATUS_SUCCESS ? launch_update_common(sev, cmd, true)
                                        : status;
}

sev_status_t sev_mcmd_launch_measure(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_launch_measure_t *lm = NULL;
    sev_guest_t *guest = NULL;
    digest_sha_t *launch_digest = NULL;
    // size_t ld_len = 0;
    sev_measurement_t measurement;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    lm = &cmd->sev_launch_measure;
    if (!handle_is_valid(lm->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, lm->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_LUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (lm->measure_len < sizeof(measurement))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        lm->measure_len = sizeof(measurement);
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(lm->measure_paddr, lm->measure_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Finalize the launch digest */
    launch_digest = sha_ctx_to_digest(&guest->ld);
    status = SW_SHA256_Final(&guest->sw_sha_ctx, (uint8_t *)launch_digest, sizeof(*launch_digest));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Calculate the measurement */
    memset(&measurement, 0, sizeof(measurement));
    status = sev_guest_measure(guest, &measurement);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Write the measurement to the output buffer */
    status = copy_to_x86(lm->measure_paddr, &measurement, sizeof(measurement));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Store the measurement in the guest so it can be used by launch secret */
    memcpy(&guest->channel.measurement, &measurement.measurement,
           sizeof(measurement.measurement));

    /* Store the launch digest in the guest so it can be used by attestation */
    memcpy(&guest->launch_digest, launch_digest, sizeof(digest_sha_t));

    /* Advance the guest state machine */
    status = sev_guest_state_transition(guest, SEV_MCMD_ID_LAUNCH_MEASURE);

end:
    return status;
}

sev_status_t sev_mcmd_launch_secret(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_transport_t *info = NULL;
    sev_guest_t *guest = NULL;
    uint64_t guest_paddr = 0;
    sev_packet_header_t hdr;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    info = &cmd->sev_launch_secret;
    if (!handle_is_valid(info->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    if (!IS_ALIGNED_TO_16_BYTES(info->guest_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    if (info->hdr_size != sizeof(hdr) ||
        !IS_ALIGNED_TO_16_BYTES(info->guest_len) ||
        info->guest_len == 0 ||
        info->guest_len > SEV_SCRATCH_BUF_LEN ||
        info->guest_len != info->trans_len)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    guest = sev_get_guest(sev, info->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_LSECRET)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (guest_is_inactive(guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(info->guest_paddr, info->guest_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Retrieve the packet header */
    status = copy_from_x86(info->hdr_paddr, &hdr, sizeof(hdr));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    guest_paddr = info->guest_paddr;  /* Make a local variable to not modify the cmd buffer's copy */

    /* Enable rd_sz_wbinvd around copy_from_x86. Page is unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* (CSF-698) Dummy read from guest_paddr (with c-bit) and throw away the result */
    SET_CBIT(guest_paddr);
    status = copy_from_x86(guest_paddr, gpSevScratchBuf, info->trans_len);
    if (status != SEV_STATUS_SUCCESS)
        goto wrbkinvd;

    /* (CSF-698) Dummy read from guest_paddr (without c-bit) and throw away the result */
    CLEAR_CBIT(guest_paddr);
    status = copy_from_x86(guest_paddr, gpSevScratchBuf, info->trans_len);
    if (status != SEV_STATUS_SUCCESS)
        goto wrbkinvd;

    /* Copy the transfer data into the scratch buffer */
    status = copy_from_x86(info->trans_paddr, gpSevScratchBuf, info->trans_len);
    if (status != SEV_STATUS_SUCCESS)
        goto wrbkinvd;

    /* Extract the secret in-place */
    status = sev_channel_extract_secret(gpSevScratchBuf, info->trans_len,
                                        info->guest_len, &guest->channel, &hdr);
    if (status != SEV_STATUS_SUCCESS)
        goto clear;

    /* Copy/inflate the secret to encrypted guest memory */
    if (is_compressed(hdr.flags))
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto clear;
    }

    status = copy_to_x86_encrypted(info->guest_paddr, gpSevScratchBuf,
                                   info->trans_len, guest->asid);

clear:
    secure_memzero(gpSevScratchBuf, info->trans_len);
wrbkinvd:
    /* Clear the rd_sz_wbinvd. Should be done after the dummy reads, but here to handle failure cases */
    set_misc_read_sized_wrbkinvd(false);
end:
    return status;
}

sev_status_t sev_mcmd_launch_finish(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_launch_finish_t *lf = NULL;
    sev_guest_t *guest = NULL;
    uint32_t asid = 0;
    uint32_t ccxs = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    lf = &cmd->sev_launch_finish;
    if (!handle_is_valid(lf->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, lf->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_LSECRET)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    /*
     * Changing to Running state. If guest is pending activation:
     * Clear ASID Invalid for each of the CCXs to be enabled for the guest,
     * and Transition FW state for the guest's ASID on the enabled CCXs from
     * 'clean' to 'in-use'.
     */
    if (guest_is_pending(guest))
    {
        status = sev_guest_finish_pending_activate(guest);
        if (status != SEV_STATUS_SUCCESS)
        {
            status = SEV_STATUS_HARDWARE_UNSAFE;
            goto end;
        }

        asid = guest->asid;
        ccxs = guest->ccxs;

        /* Mark all of the guest's enabled CCXs for its ASID 'In use'. */
        gpDram->perm.asid_in_use[asid-1]    |= ccxs;
        gpDram->perm.asid_allocated[asid-1] &= ~ccxs;
        gpDram->perm.asid_clean[asid-1]     &= ~ccxs;
    }

    /* Do at end in case activate fails */
    sev_channel_close(&guest->channel);
    memset(&guest->ld, 0, sizeof(guest->ld));

    /* Advance the guest state machine */
    status = sev_guest_state_transition(guest, SEV_MCMD_ID_LAUNCH_FINISH);

end:
    return status;
}

sev_status_t sev_mcmd_attestation(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_attestation_t *ar;
    sev_guest_t *guest = NULL;
    sev_mcmd_attestation_report_t report;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    ar = &cmd->attestation;
    if (!handle_is_valid(ar->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, ar->handle);
    if ((guest->sev_state != SEV_GUEST_STATE_LSECRET) && (guest->sev_state != SEV_GUEST_STATE_RUNNING) &&
        (guest->sev_state != SEV_GUEST_STATE_SUPDATE) && (guest->sev_state != SEV_GUEST_STATE_SENT))
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (ar->length < sizeof(sev_mcmd_attestation_report_t))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        ar->length = sizeof(sev_mcmd_attestation_report_t);
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(ar->paddr, ar->length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Populate the report */
    memset(&report, 0, sizeof(report));
    memcpy(report.mnonce, ar->mnonce, sizeof(report.mnonce));
    memcpy(&report.launch_digest, &guest->launch_digest, sizeof(report.launch_digest));
    report.policy = guest->policy;
    report.sig_usage = sev->sev.identity.persistent.pek.usage;  // SEV_CERT_USAGE_PEK
    report.sig_algo = sev->sev.identity.persistent.pek.algo;    // SEV_CERT_ALGO_ECDSA_SHA256;

    /* Sign the report */
    status = ecdsa_sign_msg((ecdsa_sig_t *)&report.sig1, &sev->sev.identity.persistent.pek.keypair.ecdsa,
                            (uint8_t *)&report, offsetof(sev_mcmd_attestation_report_t, sig_usage),
                            sev->sev.identity.persistent.pek.algo);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Write the report to the given address */
    status = copy_to_x86(ar->paddr, &report, sizeof(report));

    /* Store the length */
    ar->length = sizeof(sev_mcmd_attestation_report_t);

end:
    return status;
}

/**
 * Validate the PDH, PEK, CEK, ASK, and ARK
 *
 * Only used in sev_mcmd_send_start
 */
static sev_status_t validate_platform(const sev_mcmd_send_start_t *cmd,
                                      send_start_scratch_t **save)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    amd_cert_t ask, ark;
    send_start_scratch_t *scratch = (send_start_scratch_t *)gpSevScratchBuf;
    pdh_cert_chain_t *chain = &scratch->chain;
    sev_cert_t *pdh = &scratch->pdh;
    uint8_t *amd_chain = scratch->amd_chain;
    uint8_t *ark_start = 0;
    sev_cert_pubkey_t *ask_pubkey = &scratch->ask_pubkey;

    if (!cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (cmd->plat_certs_len != sizeof(*chain))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (cmd->pdh_cert_len != sizeof(*pdh))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (!amd_cert_chain_length_is_valid(cmd->amd_certs_len))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Copy the platform certificates to the scratch buffer */
    status = copy_from_x86(cmd->plat_certs_paddr, chain, sizeof(*chain));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the PDH certificate to the scratch buffer */
    status = copy_from_x86(cmd->pdh_cert_paddr, pdh, sizeof(*pdh));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the AMD certificates to the scratch buffer */
    status = copy_from_x86(cmd->amd_certs_paddr, amd_chain, cmd->amd_certs_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Initialize the AMD certs */
    status = amd_cert_init(&ask, amd_chain, AMD_CERT_MAX_LENGTH);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    ark_start = amd_chain + amd_cert_get_size(&ask);
    status = amd_cert_init(&ark, ark_start, AMD_CERT_MAX_LENGTH);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the ARK */
    status = amd_cert_validate_ark(&ark);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the ASK */
    status = amd_cert_validate_ask(&ask, &ark);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Export the ASK to an SEV cert public key */
    status = amd_cert_export_pubkey(&ask, ask_pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the CEK */
    status = sev_cert_validate(&chain->cek, ask_pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the PEK */
    status = sev_cert_validate(&chain->pek, &chain->cek.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the PDH */
    status = sev_cert_validate(pdh, &chain->pek.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (save)
        *save = scratch;

end:
    return status;
}

/**
 * Validate the PDH, PEK, OCA
 *
 * Only used in sev_mcmd_send_start
 */
static sev_status_t validate_domain(const sev_mcmd_send_start_t *cmd,
                                    send_start_scratch_t **reuse, sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    send_start_scratch_t *scratch = NULL;
    pdh_cert_chain_t *chain = NULL;
    sev_cert_t *pdh = NULL, *oca = NULL;

    if (!cmd || !sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (cmd->plat_certs_len != sizeof(*chain))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (cmd->pdh_cert_len != sizeof(*pdh))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (!reuse || *reuse == NULL)
    {
        /* The scratch buffer is empty, so copy the necessary certs */
        scratch = (send_start_scratch_t *)gpSevScratchBuf;
        chain = &scratch->chain;
        pdh = &scratch->pdh;

        /* Copy the platform certificates to the scratch buffer */
        status = copy_from_x86(cmd->plat_certs_paddr, chain, sizeof(*chain));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Copy the PDH certificate to the scratch buffer */
        status = copy_from_x86(cmd->pdh_cert_paddr, pdh, sizeof(*pdh));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        /* The scratch buffer is already initialized, so re-use the existing certs */
        scratch = *reuse;
        chain = &scratch->chain;
        pdh = &scratch->pdh;
    }

    /* Validate the OCA */
    status = sev_cert_validate(&chain->oca, &chain->oca.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the PEK */
    status = sev_cert_validate(&chain->pek, &chain->oca.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the PDH */
    status = sev_cert_validate(pdh, &chain->pek.body.pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Check that the OCA of the receiving machine matches the platform OCA */
    oca = &sev->sev.identity.persistent.oca_cert;
    if (memcmp(&chain->oca, oca, sizeof(chain->oca)) != 0)
        status = SEV_STATUS_POLICY_FAILURE;

    if (reuse && *reuse == NULL)
        *reuse = scratch;

end:
    return status;
}

sev_status_t sev_mcmd_send_start(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_send_start_t *ss = NULL;
    sev_guest_t *guest = NULL;
    send_start_scratch_t *scratch = NULL;
    sev_cert_t *gdh = NULL;
    sev_session_t session;
    sev_trusted_channel_t channel;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    ss = &cmd->sev_send_start;
    if (!handle_is_valid(ss->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    if (ss->session_len != sizeof(session))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        ss->session_len = sizeof(session);
        goto end;
    }

    guest = sev_get_guest(sev, ss->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (guest->policy & SEV_GUEST_POLICY_NOSEND_FLAG)
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto end;
    }

    if (guest->policy & SEV_GUEST_POLICY_SEV_FLAG)
    {
        uint8_t receiver_major = 0;
        uint8_t receiver_minor = 0;

        /* Validate the platform certificate chain (PDH, PEK, CEK, ASK, ARK) */
        status = validate_platform(ss, &scratch);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Perform version check on receiving platform */
        receiver_major = scratch->chain.pek.body.api_major;
        receiver_minor = scratch->chain.pek.body.api_minor;

        if ((receiver_major < sev_policy_major(guest->policy)) ||
            ((receiver_major == sev_policy_major(guest->policy)) && (receiver_minor < sev_policy_minor(guest->policy))))
        {
            status = SEV_STATUS_POLICY_FAILURE;
            goto end;
        }
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(ss->session_paddr, ss->session_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    if (guest->policy & SEV_GUEST_POLICY_DOMAIN_FLAG)
    {
        /* Validate the domain certificate chain (PDH, PEK, OCA) */
        status = validate_domain(ss, &scratch, sev);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    if (!scratch)
    {
        /* The scratch buffer is empty, so copy the necessary certs */
        scratch = (send_start_scratch_t *)gpSevScratchBuf;
        gdh = &scratch->pdh;

        /* Copy the PDH certificate to the scratch buffer */
        if (ss->pdh_cert_len != sizeof(*gdh))
        {
            status = SEV_STATUS_INVALID_LENGTH;
            goto end;
        }

        status = copy_from_x86(ss->pdh_cert_paddr, gdh, sizeof(*gdh));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        gdh = &scratch->pdh;
    }

    /* Open the trusted channel for sending */
    status = sev_channel_open_client(guest->policy,
                                     &sev->sev.identity.persistent.pdh, gdh,
                                     &session, &channel);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the generated session data to the output */
    status = copy_to_x86(ss->session_paddr, &session, sizeof(session));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the guest policy to the output */
    ss->policy = guest->policy;

    /* Advance the guest state machine */
    status = sev_guest_state_transition(guest, SEV_MCMD_ID_SEND_START);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Store the trusted channel data for this guest */
    memcpy(&guest->channel, &channel, sizeof(guest->channel));

end:
    /* Clear any secrets from memory before we exit */
    secure_memzero(&channel, sizeof(channel));

    return status;
}

static sev_status_t sev_mcmd_send_update(sev_t *sev, sev_mcmd_t *cmd, bool is_vmsa)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_transport_t *su = NULL;
    sev_guest_t *guest = NULL;
    sev_packet_header_t hdr;
    send_receive_update_aad_t aad;
    uint32_t trans_len = 0; // Create local var to modify

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    su = &cmd->sev_send_update;

    if (su->hdr_size < sizeof(hdr))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto exit_store_lengths;
    }

    if (!handle_is_valid(su->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, su->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_SUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (is_vmsa && !sev_es_guest_enabled(guest))    /* Your Guest/Policy must support ES */
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    if (!guest->asid || !asid_is_active(sev, guest->asid))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    if (su->guest_len == 0 || su->guest_len > SEV_SCRATCH_BUF_LEN ||
        !IS_ALIGNED_TO_16_BYTES(su->guest_len) ||
        su->trans_len == 0 || su->trans_len < su->guest_len)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Guest pages are already encrypted by the ASID key, it cannot also be
       encrypted by the SME key, so ignore the C-Bit on this page */
    if (!IS_ALIGNED_TO_16_BYTES(su->guest_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(su->hdr_paddr, su->hdr_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = check_page_range_firmware_writable(su->trans_paddr, su->trans_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Decrypt the guest memory into the scratch buffer */
    status = copy_from_x86_encrypted(su->guest_paddr, gpSevScratchBuf,
                                     su->guest_len, guest->asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (is_vmsa)
    {
        status = sev_es_validate_vmsa(&sev->sev.es, guest, gpSevScratchBuf, su->guest_len);
        if (status != SEV_STATUS_SUCCESS)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }
    }
    memset(&hdr, 0, sizeof(hdr));

    /* Encrypt and integrity protect the guest data for transport */
    memset(&aad, 0, sizeof(aad));

    /* (CSF-832) Since we don't support compression, set trans_len to guest_len
       Don't want to encrypt more data than guest_len worth */
    trans_len = su->guest_len;

    aad.channel_ctx        = SEV_CHANNEL_CTX_DATA;
    aad.header_flags       = hdr.flags;
    aad.uncompressed_size  =
    aad.trans_size         = trans_len;

    status = aesctr_hmac256_encrypt(guest->channel.tek.key, sizeof(guest->channel.tek.key),
                                    guest->channel.tik, sizeof(guest->channel.tik),
                                    &aad.channel_ctx, sizeof(aad) - sizeof(aad.pad),    /* AAD */
                                    gpSevScratchBuf, trans_len,
                                    gpSevScratchBuf,
                                    aad.iv, hdr.mac.hmac);

    memcpy(hdr.iv.iv, aad.iv, sizeof(hdr.iv.iv));   /* copy generated IV */
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the transport packet to the output buffer */
    status = copy_to_x86(su->trans_paddr, gpSevScratchBuf, su->guest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the packet header to the output buffer */
    status = copy_to_x86(su->hdr_paddr, &hdr, sizeof(hdr));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

exit_store_lengths:
    su->hdr_size = sizeof(hdr);

end:
    /* Clear any secrets from memory before we exit */
    secure_memzero(gpSevScratchBuf, PAGE_SIZE_4K);

    return status;
}

sev_status_t sev_mcmd_send_update_data(sev_t *sev, sev_mcmd_t *cmd)
{
    return sev_mcmd_send_update(sev, cmd, false);
}

sev_status_t sev_mcmd_send_update_vmsa(sev_t *sev, sev_mcmd_t *cmd)
{
    return sev_mcmd_send_update(sev, cmd, true);
}

/**
 * Same code as send_cancel but a different guest state transition
 */
sev_status_t sev_mcmd_send_finish(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_send_finish_t *sf = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    sf = &cmd->sev_send_finish;
    if (!handle_is_valid(sf->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, sf->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_SUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    sev_channel_close(&guest->channel);

    /* Advance the guest state machine */
    status = sev_guest_state_transition(guest, SEV_MCMD_ID_SEND_FINISH);

end:
    return status;
}

/**
 * Same code as send_finish but a different guest state transition
 */
sev_status_t sev_mcmd_send_cancel(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_send_cancel_t *sc = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    sc = &cmd->sev_send_cancel;
    if (!handle_is_valid(sc->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, sc->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_SUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    sev_channel_close(&guest->channel);

    /* Advance the guest state machine */
    status = sev_guest_state_transition(guest, SEV_MCMD_ID_SEND_CANCEL);

end:
    return status;
}

/**
 * Due to alignment requirements for 'ld' in guest array in PSP DRAM,
 * compiler decided that any sev_guest_t must be so aligned, although
 * that is not the case in SRAM. Compiler/linker will not align auto
 * variable beyond 8 byte alignment, so use flexible buffer for 'new_guest'.
 */
sev_status_t sev_mcmd_receive_start(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t new_handle = 0;
    uint8_t tmp_guest_buf[sizeof(sev_guest_t) + GUEST_MIN_ALIGN];
    sev_guest_t *new_guest = (sev_guest_t *)ALIGN_TO_16_BYTES(tmp_guest_buf);
    uint32_t new_policy = 0;
    uint32_t shared_policy = 0;
    uint32_t shared_handle = 0;
    sev_guest_t *free_guest = NULL;
    sev_mcmd_receive_start_t *rs = NULL;
    sev_cert_t dh_cert;
    sev_session_t session;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_INIT && sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    rs = &cmd->sev_receive_start;
    memset(new_guest, 0, sizeof(*new_guest));
    memset(&dh_cert, 0, sizeof(dh_cert));

    /* Initialize the head and tail index */
    new_guest->es.head_index = INVALID_BLOCK;
    new_guest->es.tail_index = INVALID_BLOCK;

    memset(&session, 0, sizeof(session));
    new_policy = rs->policy;
    shared_handle = rs->handle;

    /* Validate the session parameters */
    if (rs->session_len != sizeof(session))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Copy the session parameters */
    status = copy_from_x86(rs->session_paddr, &session, rs->session_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the client certificate */
    if (rs->pdh_cert_len != sizeof(sev_cert_t))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Copy the client certificate */
    status = copy_from_x86(rs->pdh_cert_paddr, &dh_cert, rs->pdh_cert_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Establish the trusted channel */
    status = sev_channel_open_server(&sev->sev.identity.persistent.pdh, &dh_cert,
                                     &session, &new_guest->channel);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Integrity check the policy with the MAC. */
    status = sev_guest_verify_policy(rs->policy, &session.policy_mac,
                                     &new_guest->channel);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    new_guest->policy = rs->policy;

    if (shared_handle == 0)
    {
        /* Generate a new VEK seed */
        status = sev_hal_trng(new_guest->umc_key_seed, sizeof(new_guest->umc_key_seed));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        sev_guest_t *shared_guest = NULL;

        if (!handle_is_valid(shared_handle))
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto end;
        }

        shared_guest = sev_get_guest(sev, shared_handle);
        shared_policy = shared_guest->policy;

        if ((new_policy != shared_policy) ||
            (shared_policy & SEV_GUEST_POLICY_NOKS_FLAG))    /* No key sharing */
        {
            status = SEV_STATUS_POLICY_FAILURE;
            goto end;
        }

        /* Share a key with the specified guest */
        memcpy(&new_guest->umc_key_seed, &shared_guest->umc_key_seed,
               sizeof(new_guest->umc_key_seed));
    }

    /* Allocate a new guest handle */
    status = find_free_guest_handle(sev->sev.guests, SEV_GUEST_COUNT_MAX, &new_handle);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    new_guest->handle = new_handle;

    if (new_policy & SEV_GUEST_POLICY_ES_FLAG)
    {
        /* Check if SEV-ES is enabled for this platform */
        if (!sev_es_platform_enabled(sev))
        {
            status = SEV_STATUS_UNSUPPORTED;
            goto end;
        }

        /* Enable SEV-ES for this guest */
        new_guest->guest_flags |= (SEV_GUEST_FLAGS_ES_FLAG | SEV_GUEST_FLAGS_ES_POOL_ALLOC_FLAG);
    }

    /* Generate new Offline Encryption Key */
    status = sev_hal_trng(new_guest->oek, sizeof(new_guest->oek));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Advance the guest and platform state machines */
    status = sev_guest_state_transition(new_guest, SEV_MCMD_ID_RECEIVE_START);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_state_transition(sev, SEV_MCMD_ID_RECEIVE_START);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Now that all checks have passed, commit the new guest state */
    free_guest = sev_get_guest(sev, new_handle);
    memcpy(free_guest, new_guest, sizeof(*free_guest));
    sev->sev.guest_count++;
    rs->handle = new_handle;

end:
    /* Clear any secrets from memory before we exit */
    secure_memzero(&session, sizeof(session));
    secure_memzero(new_guest, sizeof(*new_guest));

    return status;
}

static sev_status_t sev_mcmd_receive_update(sev_t *sev, sev_mcmd_t *cmd,
                                            bool is_vmsa)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_transport_t *ru = NULL;
    sev_guest_t *guest = NULL;
    sev_packet_header_t hdr;
    uint64_t guest_paddr = 0;
    send_receive_update_aad_t aad;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    ru = &cmd->sev_receive_update;
    if (!handle_is_valid(ru->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, ru->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_RUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    if (is_vmsa && !sev_es_guest_enabled(guest))    /* Your Guest/Policy must support ES */
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    if (!guest->asid || !asid_is_active(sev, guest->asid))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    if (ru->trans_len == 0 || ru->trans_len > SEV_SCRATCH_BUF_LEN ||
        ru->guest_len == 0 || ru->guest_len != ru->trans_len ||
        !IS_ALIGNED_TO_16_BYTES(ru->guest_len) ||
        ru->hdr_size < sizeof(hdr))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Guest pages are already encrypted by the ASID key, it cannot also be
       encrypted by the SME key, so ignore the C-Bit on this page */
    if (!IS_ALIGNED_TO_16_BYTES(ru->guest_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(ru->guest_paddr, ru->guest_len);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Copy the packet header */
    status = copy_from_x86(ru->hdr_paddr, &hdr, sizeof(hdr));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Check the packet flags */
    if (is_compressed(hdr.flags))
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    guest_paddr = ru->guest_paddr;  /* Make a local variable to not modify the cmd buffer's copy */

    /* Enable rd_sz_wbinvd around copy_from_x86. Page is unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* (CSF-698) Dummy read from guest_paddr (with c-bit) and throw away the result */
    SET_CBIT(guest_paddr);
    status = copy_from_x86(guest_paddr, gpSevScratchBuf, ru->guest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto wrbkinvd;

    /* (CSF-698) Dummy read from guest_paddr (without c-bit) and throw away the result */
    CLEAR_CBIT(guest_paddr);
    status = copy_from_x86(guest_paddr, gpSevScratchBuf, ru->guest_len);
    if (status != SEV_STATUS_SUCCESS)
        goto wrbkinvd;

    /* Copy the transport packet to the scratch buffer */
    status = copy_from_x86(ru->trans_paddr, gpSevScratchBuf, ru->trans_len);
    if (status != SEV_STATUS_SUCCESS)
        goto wrbkinvd;

    /* Decrypt and integrity check the guest data */
    memset(&aad, 0, sizeof(aad));
    memcpy(aad.iv, hdr.iv.iv, 16);

    aad.channel_ctx        = SEV_CHANNEL_CTX_DATA;
    aad.header_flags       = hdr.flags;
    aad.uncompressed_size  =
    aad.trans_size         = ru->trans_len;

    status = aesctr_hmac256_decrypt(
                guest->channel.tek.key, sizeof(guest->channel.tek.key),
                guest->channel.tik, sizeof(guest->channel.tik),
                &aad.channel_ctx, sizeof(aad) - sizeof(aad.pad),    /* AAD */
                gpSevScratchBuf, ru->trans_len,
                gpSevScratchBuf,
                hdr.iv.iv, hdr.mac.hmac);
    if (status != SEV_STATUS_SUCCESS)
        goto clear;

    if (is_vmsa)
    {
        /* Setup the VMSA for use with SEV-ES */
        status = sev_es_setup_vmsa(&sev->sev.es, guest, gpSevScratchBuf,
                                   ru->trans_len);
        if (status != SEV_STATUS_SUCCESS)
            goto clear;
    }

    /* Copy the data into encrypted guest memory */
    status = copy_to_x86_encrypted(guest_paddr, gpSevScratchBuf,
                                   ru->guest_len, guest->asid);

clear:
    secure_memzero(gpSevScratchBuf, ru->guest_len);
wrbkinvd:
    /* Clear the rd_sz_wbinvd. Should be done after the dummy reads, but here to handle failure cases */
    set_misc_read_sized_wrbkinvd(false);
end:
    return status;
}

sev_status_t sev_mcmd_receive_update_data(sev_t *sev, sev_mcmd_t *cmd)
{
    return sev_mcmd_receive_update(sev, cmd, false);
}

sev_status_t sev_mcmd_receive_update_vmsa(sev_t *sev, sev_mcmd_t *cmd)
{
    return sev_mcmd_receive_update(sev, cmd, true);
}

sev_status_t sev_mcmd_receive_finish(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_receive_finish_t *rf = NULL;
    sev_guest_t *guest = NULL;
    uint32_t asid = 0;
    uint32_t ccxs = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    rf = &cmd->sev_receive_finish;
    if (!handle_is_valid(rf->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, rf->handle); /* Guest should not be NULL because we validated the handle */
    if (guest->sev_state != SEV_GUEST_STATE_RUPDATE)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto end;
    }

    /*
     * Changing to Running state. If guest is pending activation:
     * Clear ASID Invalid for each of the CCXs to be enabled for the guest, and
     * Transition FW state for the guest's ASID on the enabled CCXs from
     * 'clean' to 'in-use'.
     */
    if (guest_is_pending(guest))
    {
        status = sev_guest_finish_pending_activate(guest);
        if (status != SEV_STATUS_SUCCESS)
        {
            status = SEV_STATUS_HARDWARE_UNSAFE;
            goto end;
        }

        asid = guest->asid;
        ccxs = guest->ccxs;

        /* Mark all of the guest's enabled CCXs for its ASID 'In use'. */
        gpDram->perm.asid_in_use[asid-1]    |= ccxs;
        gpDram->perm.asid_allocated[asid-1] &= ~ccxs;
        gpDram->perm.asid_clean[asid-1]     &= ~ccxs;
    }

    /* Do at end in case activate fails */
    sev_channel_close(&guest->channel);

    /* Advance the guest state machine */
    status = sev_guest_state_transition(guest, SEV_MCMD_ID_RECEIVE_FINISH);

end:
    return status;
}

sev_status_t sev_mcmd_dbg_decrypt(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_debug_t *dbg = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    dbg = &cmd->debug;
    if (!IS_ALIGNED_TO_16_BYTES(dbg->src_paddr) ||
        !IS_ALIGNED_TO_16_BYTES(dbg->dst_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    if (!IS_ALIGNED_TO_16_BYTES(dbg->length))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (!handle_is_valid(dbg->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, dbg->handle); /* Guest should not be NULL because we validated the handle */

    if ((guest->policy & SEV_GUEST_POLICY_NODBG_FLAG) != 0)
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(dbg->dst_paddr, dbg->length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    status = debug_crypt_common(sev, guest, false, dbg->src_paddr, dbg->dst_paddr, dbg->length);

end:
    return status;
}

sev_status_t sev_mcmd_dbg_encrypt(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_debug_t *dbg = NULL;
    sev_guest_t *guest = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    dbg = &cmd->debug;
    if (!IS_ALIGNED_TO_16_BYTES(dbg->src_paddr) ||
        !IS_ALIGNED_TO_16_BYTES(dbg->dst_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    if (!IS_ALIGNED_TO_16_BYTES(dbg->length))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    if (!handle_is_valid(dbg->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, dbg->handle); /* Guest should not be NULL because we validated the handle */

    if ((guest->policy & SEV_GUEST_POLICY_NODBG_FLAG) != 0)
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(dbg->dst_paddr, dbg->length);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Enable rd_sz_wbinvd around copy_from_x86. Page is unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = debug_crypt_common(sev, guest, true, dbg->src_paddr, dbg->dst_paddr, dbg->length);

    /* Clear the rd_sz_wbinvd */
    set_misc_read_sized_wrbkinvd(false);

end:
    return status;
}

sev_status_t sev_mcmd_swap_out(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_swap_out_t *so = NULL;
    sev_guest_t *guest = NULL;
    sev_mcmd_swap_io_mdata_t mdata;
    uint8_t local_tag[sizeof(mdata.auth_tag)];
    uint32_t page_size = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    so = &cmd->sev_swap_out;
    page_size = (so->page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* src_paddr, dst_paddr, and mdata_paddr must be valid addresses */
    status  = validate_address_range(so->src_paddr, page_size);
    status |= validate_address_range(so->dst_paddr, page_size);
    status |= validate_address_range(so->mdata_paddr, sizeof(sev_mcmd_swap_io_mdata_t));
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* src_paddr and dst_paddr must be 4K or 2M aligned. mdata_paddr must be 64 byte aligned */
    if (((so->page_size == DRAM_PAGE_SIZE_4K) &&
         (!IS_ALIGNED_TO_4KB(so->src_paddr) || !IS_ALIGNED_TO_4KB(so->dst_paddr))) ||
        ((so->page_size == DRAM_PAGE_SIZE_2M) &&
         (!IS_ALIGNED_TO_2MB(so->src_paddr) || !IS_ALIGNED_TO_2MB(so->dst_paddr))) ||
        !IS_ALIGNED_TO_64_BYTES(so->mdata_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* mdata_paddr must not overlap src_paddr or dst_paddr */
    if (ranges_overlap(so->mdata_paddr, so->mdata_paddr + sizeof(mdata) - 1ULL,
                       so->src_paddr, so->src_paddr + page_size - 1ULL) ||
        ranges_overlap(so->mdata_paddr, so->mdata_paddr + sizeof(mdata) - 1ULL,
                       so->dst_paddr, so->dst_paddr + page_size - 1ULL))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* VMSA pages must be 4K in size */
    if (so->page_type == SWAP_IO_VMSA_PAGE && so->page_size != DRAM_PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (!handle_is_valid(so->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, so->handle); /* Guest should not be NULL because we validated the handle */

    if (!guest->asid || !asid_is_active(sev, guest->asid))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    /* Check for overflow before incrementing the Guest IV */
    if (guest->oek_iv_count == (UINT64_MAX-1))
    {
        status = SEV_STATUS_AEAD_OFLOW;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(so->dst_paddr, page_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = check_page_range_firmware_writable(so->mdata_paddr, sizeof(mdata));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Decrypt the guest memory into the scratch buffer so we can test for VMSA */
    /* Note: VMSA pages can only be 4K */
    status = copy_from_x86_encrypted(so->src_paddr, gpSevScratchBuf,
                                     PAGE_SIZE_4K, guest->asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Make sure VMSA page status matches PAGE_TYPE */
    status = sev_es_validate_vmsa(&sev->sev.es, guest, gpSevScratchBuf, PAGE_SIZE_4K);
    if ((status == SEV_STATUS_SUCCESS && so->page_type != SWAP_IO_VMSA_PAGE) ||
        (status != SEV_STATUS_SUCCESS && so->page_type == SWAP_IO_VMSA_PAGE))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto exit1;
    }

    memset(&mdata, 0, sizeof(mdata));
    mdata.software_data = so->software_data;
    mdata.page_size = so->page_size;
    mdata.page_type = so->page_type;
    mdata.iv = guest->oek_iv_count++;   /* Increment the Guest IV */

    /*
     * If the source is a VMSA page, pass gpSevScratchBuf into the ccp instead
     * of so->src_paddr because that data has already been validated. Passing in
     * so->src_paddr would cause a double fetch and might might lead to an
     * inconsistent VMSA being swapped out.
     * Note: 2M pages can't fit into gpSevScratchBuf so have to use so->src_paddr
     */
    if (so->page_type == SWAP_IO_VMSA_PAGE)
    {
        /* Copies in the ASID encrypted page and copies out a OEK encrypted page */
        status = aes256gcm_authenticated_encrypt(
                                    guest->oek, sizeof(guest->oek),
                                    (uint8_t *)&mdata, sizeof(mdata),  /* AAD */
                                    gpSevScratchBuf, page_size,
                                    gpSevScratchBuf,
                                    (uint8_t *)&mdata.iv, sizeof(mdata.iv),
                                    local_tag);
        if (status != SEV_STATUS_SUCCESS)
            goto exit1;

        /* Copy the encrypted packet to the output buffer */
        status = copy_to_x86(so->dst_paddr, gpSevScratchBuf, page_size);
        if (status != SEV_STATUS_SUCCESS)
            goto exit1;
    }
    else
    {
        /* Copies in the ASID encrypted page and copies out a OEK encrypted page */
        status = aes256gcm_authenticated_encrypt_x86addr(
                                    guest->oek, sizeof(guest->oek),
                                    (uint8_t *)&mdata, sizeof(mdata),  /* AAD */
                                    so->src_paddr, page_size,
                                    so->dst_paddr,
                                    (uint8_t *)&mdata.iv, sizeof(mdata.iv),
                                    local_tag,
                                    guest->asid);
        if (status != SEV_STATUS_SUCCESS)
            goto exit1;
    }

    /*
     * Copy the auth tag from the temp buffer into the metadata page.
     *  There is the possibility of a race condition in the CCP if using the
     *  same buffer for the auth_tag tag as the read and write, so use a
     *  different variable as temp storage
     */
    memcpy(mdata.auth_tag, local_tag, sizeof(mdata.auth_tag));

    /* Copy packet meta-data to the output buffer */
    status = copy_to_x86(so->mdata_paddr, &mdata, sizeof(mdata));

exit1:
    secure_memzero(gpSevScratchBuf, PAGE_SIZE_4K);
end:
    return status;
}

sev_status_t sev_mcmd_swap_in(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_mcmd_swap_in_t *si = NULL;
    sev_guest_t *guest = NULL;
    sev_mcmd_swap_io_mdata_t mdata;
    uint8_t local_tag[sizeof(mdata.auth_tag)];
    uint32_t page_size = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    si = &cmd->sev_swap_in;
    page_size = (si->page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;

    if (sev->sev.state != SEV_STATE_WORKING)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* src_paddr, dst_paddr, and mdata_paddr must be valid addresses */
    status  = validate_address_range(si->src_paddr, page_size);
    status |= validate_address_range(si->dst_paddr, page_size);
    status |= validate_address_range(si->mdata_paddr, sizeof(sev_mcmd_swap_io_mdata_t));
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* src_paddr and dst_paddr must be 4K or 2M aligned
       mdata_paddr must be 64 byte aligned */
    if (((si->page_size == DRAM_PAGE_SIZE_4K) &&
         (!IS_ALIGNED_TO_4KB(si->src_paddr) || !IS_ALIGNED_TO_4KB(si->dst_paddr))) ||
        ((si->page_size == DRAM_PAGE_SIZE_2M) &&
         (!IS_ALIGNED_TO_2MB(si->src_paddr) || !IS_ALIGNED_TO_4KB(si->dst_paddr))) ||
        !IS_ALIGNED_TO_64_BYTES(si->mdata_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* mdata_paddr must not overlap src_paddr or dst_paddr */
    if (ranges_overlap(si->mdata_paddr, si->mdata_paddr + sizeof(mdata) - 1ULL,
                       si->src_paddr, si->src_paddr + page_size - 1ULL) ||
        ranges_overlap(si->mdata_paddr, si->mdata_paddr + sizeof(mdata) - 1ULL,
                       si->dst_paddr, si->dst_paddr + page_size - 1ULL))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Copy in the mdata entry */
    status = copy_from_x86(si->mdata_paddr, &mdata, sizeof(mdata));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * page_size and page_source must match the metadata entry
     * swap_in_place must be 0 if page_type equals VMSA
     * src_paddr and dst_paddr must match if swap_in_place is 1
     */
    if ((si->page_size != mdata.page_size) || (si->page_type != mdata.page_type) ||
        (si->page_type == SWAP_IO_VMSA_PAGE && si->swap_in_place == 1) ||
        ((si->swap_in_place == 1) && (si->src_paddr != si->dst_paddr)))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    if (!handle_is_valid(si->handle))
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    guest = sev_get_guest(sev, si->handle); /* Guest should not be NULL because we validated the handle */

    if (!guest->asid || !asid_is_active(sev, guest->asid))
    {
        status = SEV_STATUS_INACTIVE;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        status = check_page_range_firmware_writable(si->dst_paddr, page_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /*
     * Copy mdata.auth_tag to a local buffer and clear mdata.auth_tag.
     * The entire mdata struct, including auth_tag which was 0, was part if the
     * calculation and mdata.auth_tag (the result) was written in place afterwards
     */
    memcpy(local_tag, mdata.auth_tag, sizeof(mdata.auth_tag));
    memset(mdata.auth_tag, 0, sizeof(mdata.auth_tag));

    /* Enable rd_sz_wbinvd around copy_from_x86. Page is unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* (CSF-698) Dummy read for dst_paddr is performed inside aes256gcm_authenticated_decrypt_x86addr */

    /* Decrypt using Offline Encryption Key */
    /* Copies in the OEK encrypted page and copies out a ASID encrypted page */
    status = aes256gcm_authenticated_decrypt_x86addr(
                                guest->oek, sizeof(guest->oek),
                                (uint8_t *)&mdata, sizeof(mdata),  /* AAD */
                                si->src_paddr, page_size,
                                si->dst_paddr,
                                (uint8_t *)&mdata.iv, sizeof(mdata.iv),
                                local_tag,
                                guest->asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end1;

end1:
    /* Clear the rd_sz_wbinvd */
    set_misc_read_sized_wrbkinvd(false);

end:
    return status;
}

/* Function that tracks whether the SMU FW supports the "Set MSR" functionality */
bool smu_has_set_msr(void)
{
    static enum {
        unknown = 0,
        does_not,
        does
    } smu_has_set_msr = unknown;

    if (smu_has_set_msr == unknown)
    {
        smu_has_set_msr = sev_hal_update_msr(0xC00131e8, 0, BITOP_NOP, 0, BITOP_NOP) == SEV_STATUS_SUCCESS ? does : does_not;
    }

    return smu_has_set_msr == does;
}

/* -------------------------- SNP Functions -------------------------- */
static sev_status_t snp_mcmd_init_common(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool initialize_rmp = true;     /* If x86 is requesting a full RMP init */
    bool init_valid = false;
    bool is_init_ex = false;
    bool rmp_table_initialized = false;
    sev_snp_globals_t snp_globals;
    bool rmp_init_required = false; /* If RMP Init is required due to DLFW tcb change, etc */
    snp_mcmd_init_ex_t *ex = NULL;
    bool cpu_tmr_enabled = false;
    bool iommu_tmr_enabled = false;
    bool tmpm_tmr_enabled = false;
    uint64_t syscfg = 0;
    bool is_same = false;

    BL_RETCODE bl_retcode = BL_OK;

    skip_rmp_addr_check(true);

    if (!sev)
    {
        status = SEV_ERROR(ERR_INVALID_PARAMS, EXT_ERR_002);
        goto end;
    }

    /* If valid command buffer, then it's SNP_INIT_EX (instead of SNP_INIT) */
    if (cmd)
    {
        is_init_ex = true;
        ex = &cmd->snp_init_ex;

        /* Verify the reserved fields are zero */
        if (ex->reserved != 0 || ex->reserved2 != 0 || !is_empty(ex->reserved3, sizeof(ex->reserved3)))
        {
            status = SEV_ERROR(SEV_STATUS_INVALID_PARAM, EXT_ERR_003);
            goto end;
        }
    }

    /* Clear SNP Globals */
    memset(&snp_globals, 0, sizeof(snp_globals));

    status = sev_hal_read_snp_globals(&snp_globals.val[0]);
    if (SEV_ERROR(status, EXT_ERR_004) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    if (snp_globals.f.diag_mode_enabled)
    {
        status = SEV_ERROR(SEV_STATUS_HARDWARE_PLATFORM, EXT_ERR_005);
        goto end;
    }

    /*
     * Check the Platform state. Cannot be run if SNP is already Init'd or if
     * SEV is already Init'd. Must Init SNP first if want to run both.
     */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT || sev->sev.state != SEV_STATE_UNINIT)
    {
        status = SEV_ERROR(SEV_STATUS_INVALID_PLATFORM_STATE, EXT_ERR_006);
        goto end;
    }

    /* (CSF-697) This DFFlush hack was added to avoid hangs after calling SNPInit */
    /* Flush pending writes to the UMC */
    status = sev_hal_df_write_flush();
    if (SEV_ERROR(status, EXT_ERR_007) != SEV_STATUS_SUCCESS)
        goto end;

    /* Flush pending writes on slave dies if any */
    if (gTotalDieNum > 1)
    {
        sev_scmd_t scmd;
        memset(&scmd, 0, sizeof(scmd));
        scmd.id = SEV_SCMD_ID_DF_FLUSH;
        status = sev_hal_master_to_slave(1, &scmd, sizeof(scmd));
        if (SEV_ERROR(status, EXT_ERR_008) != SEV_STATUS_SUCCESS)
            goto end;
    }

    status = sev_init(sev);
    if (SEV_ERROR(status, EXT_ERR_009) != SEV_STATUS_SUCCESS)
        goto end;

    /* Bergamo is not supported in BL versions less than MIN_BL_VERSION_BERGAMO */
    if ((gPersistent.bl_fw_version < MIN_BL_VERSION_BERGAMO) &&
        (gPersistent.soc_version >= RSDN_A0_SOC_VER_VAL))
    {
        status = SEV_STATUS_UNSUPPORTED;
        SEV_ERROR(status, EXT_ERR_010);
        goto end;
    }

    /*
     * We are cleared to do the INIT. Beyond here, goto exit_sev_init_invalid
     * on error. That clears sev_t state back to Shutdown condition.
     * Don't do that above here!
     */

    /* If system is unlocked, DO NOT enable SNP */
    if (snp_globals.f.signal_snp_sdu_unlocked)
    {
        status = SEV_STATUS_HARDWARE_UNSAFE;
        SEV_ERROR(status, EXT_ERR_011);
        goto exit_sev_init_invalid;
    }

    /* If RMP table is currently initialized */
    if (snp_globals.f.rmp_initialized)
    {
        rmp_table_initialized = true;
    }

    if (is_init_ex)
    {
        /* Check if re-init requested by x86 */
        if (ex->init_rmp)
        {
            initialize_rmp = true;
        }
        else
        {
            if (rmp_table_initialized)
            {
                status = require_rmp_reinit(sev, &snp_globals, &rmp_init_required);
                if (SEV_ERROR(status, EXT_ERR_012) != SEV_STATUS_SUCCESS)
                    goto exit_sev_init_invalid;
                if  (!rmp_init_required)
                {
                    /* RMP already initialized, don't need to do it again */
                    initialize_rmp = false;
                }
                else
                {
                    /* Full Init is required (failed security check) */
                    status = SEV_STATUS_RMP_INIT_REQUIRED;
                    SEV_ERROR(status, EXT_ERR_013);
                    goto exit_sev_init_invalid;
                }
            }
            else
            {
                /* RMP has not been initialized and x86 didn't request full Init */
                status = SEV_STATUS_RMP_INIT_REQUIRED;
                SEV_ERROR(status, EXT_ERR_014);
                goto exit_sev_init_invalid;
            }
        }

        if (ex->list_paddr_en)
        {
            if (!initialize_rmp)
            {
                status = SEV_STATUS_INVALID_PARAM;
                SEV_ERROR(status, EXT_ERR_015);
                goto exit_sev_init_invalid;
            }
        }
    }

    /*
     * 0. UMC::CH::DataCtrl::DataEncrEn must be set to 1 across all cores
     * 1. Core::X86::Msr::SYS_CFG[MemoryEncryptionModEn] must be set to 1 across all cores (SEV must be enabled)
     * 2. Core::X86::Msr::SYS_CFG[SecureNestedPagingEn] must be set to 1 across all cores
     * 3. Core::X86::Msr::SYS_CFG[VMPLEn] must be set to 1 across all cores
     * 4. Microcode patch level must be set identically across all cores
     *    - Checked/set in sev_init, just make sure sev_init has been called
     */
    if (!umc_encryption_enabled() || !sme_is_enabled_all_cores() || !snp_is_enabled_all_cores() ||
        !vmpl_is_enabled_all_cores() || gPersistent.smke_enabled)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        SEV_ERROR(status, EXT_ERR_016);
        goto exit_sev_init_invalid;
    }

    /* PLAT-76815: Check certain MSRs to avoid security issues */
    status = sev_hal_check_msrs(NULL);
    if (SEV_ERROR(status, EXT_ERR_017) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* Verify the values in SYS_CFG MSR */
    status = sev_hal_get_msr_value(MSR_SYS_CFG, &syscfg, &is_same);
    if (status != SEV_STATUS_SUCCESS || !is_same ||
        (syscfg & MSR_SYS_CFG_MFDM_EN_FLAG) != MSR_SYS_CFG_MFDM_EN_FLAG)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        SEV_ERROR(status, EXT_ERR_018);
        goto exit_sev_init_invalid;
    }

    /* Verify the values in HWCR MSR */
    uint64_t hwcr;
    status = sev_hal_get_msr_value(MSR_HWCR, &hwcr, &is_same);
    if (status != SEV_STATUS_SUCCESS || !is_same ||
        (hwcr & MSR_HWCR_SMM_LOCK_FLAG) != MSR_HWCR_SMM_LOCK_FLAG)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        SEV_ERROR(status, EXT_ERR_019);
        goto exit_sev_init_invalid;
    }

    /* Get the current SSCB */
    bl_retcode = (BL_RETCODE)Svc_GetSetSystemProperty(PROP_ID_GET_SSCB, (uint8_t *)&gSSCB, sizeof(gSSCB));
    if (bl_retcode != BL_OK)
    {
        status = SEV_STATUS_INVALID_CONFIG; // Xlate BL_RETCODE to sev_status_t
        SEV_ERROR(status, EXT_ERR_020);
        goto exit_sev_init_invalid;
    }

    /*
     * 4. RMP_BASE and RMP_END must be set identically across all cores
     * 5. RMP_BASE must be 1 MB aligned
     * 6. RMP_END - RMP_BASE + 1 must be a multiple of 1 MB
     */
    status = get_rmp_bounds();
    if (SEV_ERROR(status, EXT_ERR_021) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* Ensure TSEG MSRs match SSCB advertised to everyone else */
    status = check_tseg();
    if (status != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* CSF-961: Validate the memory map to make sure RMP doesn't overlap MMIO region */
    status = get_memory_map(&gpDram->mem_map); /* Rebuild memory map now that the MSRs are frozen */
    if (SEV_ERROR(status, EXT_ERR_022) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    status = validate_memory_map(&gpDram->mem_map, gpDram->perm.rmp_base, gpDram->perm.rmp_end);
    if (SEV_ERROR(status, EXT_ERR_023) != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        SEV_ERROR(status, EXT_ERR_024);
        goto exit_sev_init_invalid;
    }

    /*
     * If we are going to initialize the RMP, tell other MPs to protect the RMP from writes.
     * This operation waits for the other MPs to 'ack' that they will not write
     * over the RMP which would cause a system crash after we install the TMR.
     */
    if (initialize_rmp)
    {
        gSSCB.SSCB_Control &= ~(SSCB_RMP_MASK|SSCB_SNP_MASK);
        gSSCB.SSCB_Control |= SSCB_RMP_MASK;
        gSSCB.RMP_Base = gpDram->perm.rmp_base;
        gSSCB.RMP_End = gpDram->perm.rmp_end;

        bl_retcode = (BL_RETCODE)Svc_GetSetSystemProperty(PROP_ID_SET_SNP_STATE, (uint8_t *)&gSSCB, sizeof(gSSCB));
        if (bl_retcode != BL_OK)
        {
            status = SEV_STATUS_HARDWARE_PLATFORM;
            SEV_ERROR(status, EXT_ERR_026);
            goto exit_sev_init_invalid;
        }
    }

    /*
     * Ordering for the next section of code:
     * 1. Enable CPU TMR to allow reads from CPU/PIE.
     *    No IOMMU accesses exist yet because SNP is not enabled on IOMMU
     * 2. Enable IOMMU TMR to allow reads from IOM
     * 3. Check VM_HSAVE_PA to ensure no guests started before TMRs prevented writes.
     * 4. Initialize RMP table (safe now since all write access is blocked)
     * 5. Enable SNP on IOMMU (safe since the TMR allows IOMMU reads)
     * 6. Flush CPU TLBs
     * 7. Enable R/W access from CPU/PIE on their TMR
     * 8. Leave IOMMU TMR as-is
     */

    /* Only enable RMP TMRs if RMP table is not initialized (once per boot, unless ShutdownEX called)
       Must be called before setup_and_validate_initial_rmp_table() */
    if (rmp_table_initialized == false)
    {
        /*
         * Enable RMP TMRs. The second IOMMU TMR is needed until the PSP gains
         * the ability to flush the IOMMU TLBs (PLAT-78075).
         * Note: The CPU is currently needing to read the RMP because SNP is
         *       already enabled there but the IOMMU will not need the RMP until
         *       it gets SNP enabled by PSP in enable_snp_iommu()
         */
        /* Enable RMP CPU TMR. Reads are allowed, writes are not from the x86/microcode */
        status = enable_tmr(SNP_RMP_CPU_TMR, gpDram->perm.rmp_base,
                            gpDram->perm.rmp_end - gpDram->perm.rmp_base + 1, TMR_CTRL_RMP_CPU_DEFAULTS);
        if (SEV_ERROR(status, EXT_ERR_027) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        cpu_tmr_enabled = true;

        /* Set up second TMR to allow only IOMMU reads */
        status = enable_tmr(SNP_RMP_IOMMU_TMR, gpDram->perm.rmp_base,
                            gpDram->perm.rmp_end - gpDram->perm.rmp_base + 1, TMR_CTRL_RMP_IOMMU_DEFAULTS);
        if (SEV_ERROR(status, EXT_ERR_028) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        iommu_tmr_enabled = true;
    }

    /* If INIT_RMP is 0, then VM_HSAVE_PA does not need to be zero, so only
       check if the entire table is to be initialized */
    if (initialize_rmp && !vm_hsave_pa_cleared_all_cores())
    {
        status = SEV_STATUS_INVALID_CONFIG;
        SEV_ERROR(status, EXT_ERR_029);
        goto exit_sev_init_invalid;
    }

    /* Every SNP_INIT or SNP_INIT_EX with init_rmp set */
    if (initialize_rmp)
    {
        /* Initialize the RMP table. This can only be done after the CPU and IOMMU TMRs are setup */
        uint64_t range_list_paddr = (is_init_ex && ex->list_paddr_en != 0) ? ex->list_paddr : PADDR_INVALID;
        if (!configure_rmp(range_list_paddr))
        {
            status = SEV_STATUS_RMP_INITIALIZATION_FAILED;
            SEV_ERROR(status, EXT_ERR_030);
            goto exit_sev_init_invalid;
        }
        rmp_table_initialized = false; /* Make sure we re-init the IOMMU and IOMMU RMP entries */
    }

    /* Only enable IOMMU protection if the table is not currently initialized (once per boot, unless ShutdownEX called) */
    if (rmp_table_initialized == false)
    {
        /* Set any non-enabled IOMMU logs to -1 (unused) */
        status = check_iommu_event_logs();
        if (SEV_ERROR(status, EXT_ERR_031) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /* Enable IOMMU Protection. This is safe since the IOMMU TMR is setup to allow reads */
        status = enable_snp_iommu();
        if (SEV_ERROR(status, EXT_ERR_032) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;
    }

    /* Check SNP IOMMU security regardless of initialization of rmp table */
    status = validate_snp_iommu();
    if (SEV_ERROR(status, EXT_ERR_033) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* If RMP table has been initialized/cleared, re-apply protection */
    if (rmp_table_initialized == false)
    {
        /* Set all IOMMU logs to FIRMWARE_IOMMU state and re-validate all
           non-enabled logs are set to -1 */
        status = set_iommu_table_state(SNP_PAGE_STATE_FIRMWARE_IOMMU);
        if (SEV_ERROR(status, EXT_ERR_034) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /*
         * Immediately after completing RMP initialization, the firmware forces
         * a TLB flush across all cores on all sockets
         * (CSF-603) TLB must be flushed before the TMR is disabled
         */
        /* Flush TLB on master socket */
        status = sev_hal_flush_tlb();
        if (SEV_ERROR(status, EXT_ERR_035) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        /* Flush TLB on slave socket */
        if (gTotalDieNum > 1)
        {
            sev_scmd_t scmd;
            memset(&scmd, 0, sizeof(scmd));
            scmd.id = SEV_SCMD_ID_TLB_FLUSH;
            status = sev_hal_master_to_slave(1, &scmd, sizeof(scmd));
            if (SEV_ERROR(status, EXT_ERR_036) != SEV_STATUS_SUCCESS)
                goto exit_sev_init_invalid;
        }

        /*
         * Set the first RMP TMR to be for CCM/PIE only (remove the IOM flag)
         * and allow (microcode) read and write. Make sure to revoke IOM access
         * before enabling write access so that the IOMMU cannot write to the
         * RMP in the window between the two calls below.
         */
        status = modify_tmr_flags(SNP_RMP_CPU_TMR, TMR_CTRL_SAE_IOM_FLAG, false);
        if (SEV_ERROR(status, EXT_ERR_037) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        status = modify_tmr_flags(SNP_RMP_CPU_TMR, TMR_CTRL_WRITE_EN_FLAG, true);
        if (SEV_ERROR(status, EXT_ERR_038) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        status = enable_tmr(SNP_RMP_TMPM_TMR, gpDram->perm.rmp_base,
                            gpDram->perm.rmp_end - gpDram->perm.rmp_base + 1,
                            TMR_CTRL_RMP_TMPM_DEFAULTS);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;

        tmpm_tmr_enabled = true;
    }

    /* Derive the VCEK unconditionally */
    status = vcek_hash_derive(gpDram->perm.snp_identity.vcek_hash, DIGEST_SHA384_SIZE_BYTES, NULL);
    if (SEV_ERROR(status, EXT_ERR_039) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;
    status = vcek_derive(&gpDram->perm.snp_identity);
    if (SEV_ERROR(status, EXT_ERR_040) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* Synchronize APICID Table between master and slave */
    /* CCX population */
    status = sync_apicid_tables(sev);
    if (SEV_ERROR(status, EXT_ERR_041) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* Mark ASIDs invalid on all the dies */
    status = mark_all_asids_invalid();
    if (SEV_ERROR(status, EXT_ERR_042) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* Clear WBINVD_DONE bits on all dies */
    status = clear_wbinvd_done(gPersistent.ccx_present_bit_mask);
    if (SEV_ERROR(status, EXT_ERR_043) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /*
     * Init state of all ASIDs/CCXs to 'dirty', not 'clean', not 'in-use',
     * and not 'allocated'.
     */
    for (uint32_t i = 0; i < SEV_ASID_ARRAY_SIZE; i++)
    {
        gpDram->perm.asid_dirty[i] = gPersistent.ccx_present_bit_mask;
        gpDram->perm.asid_clean[i] = 0;
        gpDram->perm.asid_allocated[i] = 0;
        gpDram->perm.asid_in_use[i] = 0;
    }

    /* Create the VMSARegProt bitmap */
    sev_es_create_vmsa_bitmap(sev->snp.vmsa_tweak_bitmap);

    /* Tell other MPs to start enforcing SNP semantics */
    if (initialize_rmp)
    {
        gSSCB.SSCB_Control &= ~(SSCB_RMP_MASK|SSCB_SNP_MASK);
        gSSCB.SSCB_Control |= SSCB_SNP_MASK;
        bl_retcode = (BL_RETCODE)Svc_GetSetSystemProperty(PROP_ID_SET_SNP_STATE, (uint8_t *)&gSSCB, sizeof(gSSCB));
        if (bl_retcode != BL_OK)
        {
            status = SEV_STATUS_HARDWARE_PLATFORM;
            SEV_ERROR(status, EXT_ERR_044);
            goto exit_sev_init_invalid;
        }
    }

    /* Advance the platform state machine */
    status = snp_state_transition(sev, SNP_MCMD_ID_INIT);
    if (SEV_ERROR(status, EXT_ERR_045) != SEV_STATUS_SUCCESS)
        goto exit_sev_init_invalid;

    /* Everything has successfully passed, write back to SNP global */
    if (initialize_rmp)
    {
        snp_tcb_version_t current_tcb;

        /* Calculate the current tcb version using the latest uCode SVN */
        get_committed_tcb(&current_tcb);

        snp_globals.f.rmp_initialized = 1;
        /* Signal SDU that SNP has been initialized */
        snp_globals.f.signal_sdu_snp_initialized = 1;
        /* Save the TCB of the code that initialized the RMP */
        snp_globals.f.tcb.val = current_tcb.val;
        status = sev_hal_write_snp_globals(snp_globals.val);
        if (SEV_ERROR(status, EXT_ERR_047) != SEV_STATUS_SUCCESS)
            goto exit_sev_init_invalid;
    }

    /* No errors */
    init_valid = true;
    gpDram->perm.snp_guest_count = 0;
    sev->snp.context_initialized = true;

exit_sev_init_invalid:
    if (init_valid == false)    /* Clear sev state to Shutdown condition. */
    {
        /* TMR, then IOMMU, then CPU (must be last for disable) */
        if (tmpm_tmr_enabled)
            disable_tmr(SNP_RMP_TMPM_TMR);
        if (iommu_tmr_enabled)
            disable_tmr(SNP_RMP_IOMMU_TMR); /* Make sure TMR gets disabled on setup failure  */
        if (cpu_tmr_enabled)
            disable_tmr(SNP_RMP_CPU_TMR);   /* Make sure TMR gets disabled on setup failure */

        if (gSSCB.SSCB_Control & (SSCB_RMP_MASK|SSCB_SNP_MASK))
        {
            gSSCB.SSCB_Control &= ~(SSCB_RMP_MASK|SSCB_SNP_MASK);
            (void)Svc_GetSetSystemProperty(PROP_ID_SET_SNP_STATE, (uint8_t *)&gSSCB, sizeof(gSSCB));
        }

        (void)sev_clear(sev);
    }

end:
    skip_rmp_addr_check(false);
    return status;
}

static sev_status_t snp_mcmd_shutdown_common(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* SNP cannot be shutdown while SEV is running */
    if (sev->sev.state != SEV_STATE_UNINIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* If platform is in UNINIT state, return SUCCESS without taking any further action */
    if (gpDram->perm.snp_state == SNP_STATE_UNINIT)
        goto end;

    /* Check that, for every encryption capable ASID, a DF_FLUSH is not required */
    for (uint32_t i = 0; i < MAX_SEV_ASIDS; i++)
    {
        if (gpDram->perm.asid_clean[i] != gPersistent.ccx_present_bit_mask) /* Make sure every ASID is clean */
        {
            status = SEV_STATUS_DF_FLUSH_REQUIRED;
            goto end;
        }
    }

    /* Shutdown_Ex */
    if (cmd)
    {
        snp_mcmd_shutdown_ex_t *ex = &cmd->snp_shutdown_ex;

        /* Verify the length param is correct */
        if (ex->length != sizeof(*ex))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        /* Verify the reserved fields are zero */
        if (ex->reserved != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        /* X86_SNP_SHUTDOWN requires IOMMU_SNP_SHUTDOWN and SMU support */
        if (ex->x86_snp_shutdown == 1 && (ex->iommu_snp_shutdown != 1 || !smu_has_set_msr()))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }
    }

    /* Transition the platform to UNINIT */
    status = snp_state_transition(sev, SNP_MCMD_ID_SHUTDOWN);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (cmd)
    {
        snp_mcmd_shutdown_ex_t *ex = &cmd->snp_shutdown_ex;

        /* If IOMMU_SNP_SHUTDOWN is set to 1 */
        if (ex->iommu_snp_shutdown == 1)
        {
            /* Record that a full RMP re-initialization is required by the next SNP_INIT invocation */
            sev_snp_globals_t snp_globals;

            rmp_is_uninitialized();
            status = sev_hal_read_snp_globals(&snp_globals.val[0]);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            snp_globals.f.rmp_initialized = 0;

            status = sev_hal_write_snp_globals(snp_globals.val);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            /* Disables SNP enforcement by the IOMMU */
            status = disable_snp_iommu();
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            /* Transition all pages associated with the IOMMU to the Reclaim state and clear GPA state hack
               Use a temp counter (instead of iommu_entry_ctr) to allow trying again on failure */
            uint32_t counter = 0;
            while (counter < gpDram->perm.iommu_entry_ctr)
            {
                status = set_rmp_range_to_reclaim_state(gpDram->perm.iommu_entry_list_start[counter],
                                                           gpDram->perm.iommu_entry_list_end[counter]);
                if (status != SEV_STATUS_SUCCESS)
                    goto end; /* This should never happen... consider FatalError() */

                counter++;
            }

            /* On success, clear the table just to be safe */
            memset(gpDram->perm.iommu_entry_list_start, 0, sizeof(gpDram->perm.iommu_entry_list_start));
            memset(gpDram->perm.iommu_entry_list_end, 0, sizeof(gpDram->perm.iommu_entry_list_end));
            gpDram->perm.iommu_entry_ctr = 0;

            /* Wipe the UMC of all guest keys */
            uint8_t zerokey[CIPHER_AES_KEY_SIZE_BYTES] = {0};
            for (uint32_t asid = 0; asid < MAX_SEV_ASIDS; ++asid)
            {
                if ((status = set_umc_key(asid, zerokey, CIPHER_AES_KEY_SIZE_BYTES)) != SEV_STATUS_SUCCESS)
                    goto end;
                if ((status = set_cnli_key(asid, zerokey, CIPHER_AES_KEY_SIZE_BYTES)) != SEV_STATUS_SUCCESS)
                    goto end;
            }

            if (ex->x86_snp_shutdown)
            {
                BL_RETCODE bl_retcode = BL_OK;
                status = SEV_STATUS_SHUTDOWN_INCOMPLETE;
                sscb_t sscb = {0};

                /* Clear SNPEn in the SYSCFG MSR using a 'hidden' MSR */
                if (sev_hal_update_msr(0xC00131e8, 24, BITOP_CLEAR, 0, BITOP_NOP) != SEV_STATUS_SUCCESS)
                    goto end;

                /* Update other MPs with SSCB that has no RMP protections */
                bl_retcode = (BL_RETCODE)Svc_GetSetSystemProperty(PROP_ID_SET_SNP_STATE, (uint8_t *)&sscb, sizeof(sscb));
                if (bl_retcode != BL_OK)
                    goto end;

                status = SEV_STATUS_SUCCESS;
            }

            /*
             * Disable the RMP CPU/IOMMU/TMPM TMRs.
             * Note: Must tear down TMR & IOMMU TMRs first. If you disable the CPU TMR
             *       first, then the CPUs (which always have SNP MSR enabled and will be
             *       reading the RMP) could fail since they won't match the IOMMU TMR.
             */
            status = disable_tmr(SNP_RMP_TMPM_TMR);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            status = disable_tmr(SNP_RMP_IOMMU_TMR);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            status = disable_tmr(SNP_RMP_CPU_TMR);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            /* Signal SDU that SNP has been non-initialized */
            status = sev_hal_read_snp_globals(&snp_globals.val[0]);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            snp_globals.f.signal_sdu_snp_initialized = 0;

            status = sev_hal_write_snp_globals(snp_globals.val);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            gpDram->perm.magic = ~SEV_PERM_MAGIC; // Next command will re-init gpDram->perm.
        }
    }

    /* Clear non-persistent platform/guest state
     * NOTE: This also effectively resets the platform state to UNINIT */
    status = sev_clear(sev);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_HARDWARE_UNSAFE;
        goto end;
    }

    /* Wipe the VLEK */
    memset(gpDram->perm.vlek, 0, sizeof(gpDram->perm.vlek));
    memset(&gpDram->perm.vlek_key, 0, sizeof(gpDram->perm.vlek_key));

end:
    return status;
}

/**
 * Gets called in snp_decommission and in guest_request -> vm_export
 * Calling function does the map/unmap
 */
static sev_status_t snp_decommission_common(sev_t *sev, guest_context_page_t *gctx)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t asid = 0;
    uint32_t ccxs = 0;
    uint32_t tmp_ccxs = 0;

    asid = gctx->guest.asid;
    ccxs = gctx->guest.ccxs;

    /* Deactivate first, if active */
    if (guest_has_asid(&gctx->guest))
    {
        status = sev_guest_deactivate(&gctx->guest, gpDram->perm.asid_in_use[asid-1]);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        tmp_ccxs = gpDram->perm.asid_allocated[asid-1] & ccxs;
        if (tmp_ccxs)
        {
            /* These CCXs never made it to Running.
            Allocated but never used CCXs: Clean */
            gpDram->perm.asid_allocated[asid-1] &= ~tmp_ccxs;
            gpDram->perm.asid_clean[asid-1] |= tmp_ccxs;
        }
        tmp_ccxs = gpDram->perm.asid_in_use[asid-1] & ccxs;
        if (tmp_ccxs)
        {
            /* Has been Running: InUse CCXs Dirty. */
            gpDram->perm.asid_in_use[asid-1] &= ~tmp_ccxs;
            gpDram->perm.asid_dirty[asid-1] |= tmp_ccxs;
        }
    }

    /* Then decommission */
    status = mcmd_decommission_common(sev, &gctx->guest);

end:
    return status;
}

sev_status_t snp_mcmd_init(sev_t *sev, sev_mcmd_t * ignored)
{
    return snp_mcmd_init_common(sev, NULL);
}

sev_status_t snp_mcmd_shutdown(sev_t *sev, sev_mcmd_t *ignored)
{
    return snp_mcmd_shutdown_common(sev, NULL);
}

sev_status_t snp_mcmd_platform_status(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_platform_status_t *ps = NULL;
    snp_platform_status_buffer_t data;
    uint64_t status_rmp_paddr = 0;
    rmp_entry_t status_rmp_entry;
    snp_page_state_t status_state;
    snp_tcb_version_t tcb;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ps = &cmd->snp_platform_status;

    /* Make sure the address and buffer don't cross a page boundary */
    if (((ps->status_paddr & (PAGE_SIZE_4K-1)) + sizeof(snp_platform_status_buffer_t)) > PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check page state if SNP is initialized  */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        /* Verify that the status context page is in the FIRMWARE or DEFAULT state */
        status = rmp_get_addr_entry_state(ps->status_paddr, &status_rmp_paddr, &status_rmp_entry, &status_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        if (status_state != SNP_PAGE_STATE_FIRMWARE && status_state != SNP_PAGE_STATE_DEFAULT)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        }
    }

    memset(&data, 0, sizeof(data));
    data.api_major = SEV_API_MAJOR;
    data.api_minor = SEV_API_MINOR;
    data.state = gpDram->perm.snp_state;
    data.is_rmp_init = is_rmp_table_initialized();
    data.build_id = SEV_BUILD_ID;
    data.mask_chip_id = gpDram->perm.mask_chip_id;
    data.mask_chip_key = gpDram->perm.mask_chip_key;
    data.vlek_en = vlek_installed();
    data.feature_info = true; /* The FEATURE_INFO command is supported */
    data.guest_count = gpDram->perm.snp_guest_count;

    /* Fetch the running/current tcb version */
    status = get_running_tcb(&tcb, NULL);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    data.tcb_version = tcb.val;

    /* Fetch the reported tcb version */
    get_reported_tcb(&tcb);
    data.reported_tcb = tcb.val;

    /* Write the data to the status page in x86 memory */
    status = copy_to_x86(ps->status_paddr, &data, sizeof(data));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

sev_status_t snp_mcmd_df_flush(sev_t *sev, sev_mcmd_t *ignored)
{
    return mcmd_df_flush_common(sev);
}

sev_status_t snp_mcmd_init_ex(sev_t *sev, sev_mcmd_t *cmd)
{
    return snp_mcmd_init_common(sev, cmd);
}

sev_status_t snp_mcmd_shutdown_ex(sev_t *sev, sev_mcmd_t *cmd)
{
    return snp_mcmd_shutdown_common(sev, cmd);
}

sev_status_t snp_mcmd_decommission(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_decommission_t *dm = NULL;
    uint64_t gctx_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    snp_page_state_t gctx_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    dm = &cmd->snp_decommission;

    /* Verify the reserved fields are zero */
    if (dm->gctx_paddr & SNP_ADDR_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(dm->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(dm->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Actually do the deactivate and decommission */
    status = snp_decommission_common(sev, gctx);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Transition the gctx page from CONTEXT to FIRMWARE state */
    gctx_rmp_entry.q1.f.vmsa = 0;    /* Context -> Firmware */

    /* Write RMP changes back to x86 memory */
    status = rmp_entry_write(gctx_rmp_paddr, &gctx_rmp_entry);

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_activate(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_activate_t *ac = NULL;
    uint64_t gctx_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    snp_page_state_t gctx_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    uint64_t asid_count = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ac = &cmd->snp_activate;

    /* Verify the reserved fields are zero */
    if (ac->gctx_paddr & SNP_ADDR_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(ac->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(ac->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state */
    if ((gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH) &&
        (gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING))
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Check that there are no pages assigned to the ASID in the RMP */
    status = check_rmp_for_asid(ac->asid, &asid_count);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;
    if (asid_count != 0)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto unmap;
    }

    /* If POLICY.SINGLE_SOCKET is 1 and the system has more than 1 socket
       populated, return POLICY_FAILURE */
    if ((gctx->guest.policy_snp & SNP_GUEST_POLICY_SINGLE_SOCKET_FLAG) && (gTotalDieNum > 1))
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto unmap;
    }

    status = mcmd_activate_common(sev, &gctx->guest, ac->asid);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_guest_status(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_guest_status_t *gs = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t status_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t status_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t status_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    snp_guest_status_buffer_t data;     /* Output */

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    gs = &cmd->snp_guest_status;

    /* Verify the reserved fields are zero */
    if (gs->gctx_paddr & SNP_ADDR_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Make sure the address and buffer don't cross a page boundary */
    if (((gs->status_paddr & (PAGE_SIZE_4K-1)) + sizeof(snp_guest_status_buffer_t)) > PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(gs->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Verify that the status page is in FIRMWARE or DEFAULT state */
    status = rmp_get_addr_entry_state(gs->status_paddr, &status_rmp_paddr, &status_rmp_entry, &status_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (status_state != SNP_PAGE_STATE_FIRMWARE && status_state != SNP_PAGE_STATE_DEFAULT)
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(gs->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    memset(&data, 0, sizeof(data));
    data.policy = gctx->guest.policy_snp;
    data.asid = guest_has_asid(&gctx->guest) ? gctx->guest.asid : 0;
    data.state = gctx->guest.snp_state;
    data.vcek_dis = gctx->vcek_dis;

    /* Copy the guest context page from the scratch buffer back to system mem */
    status = copy_to_x86(gs->status_paddr, &data, sizeof(data));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_gctx_create(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_gctx_create_t *gc = NULL;
    uint64_t gctx_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    snp_page_state_t gctx_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    snp_tcb_version_t current_tcb;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    gc = &cmd->snp_gctx_create;

    /* Verify the reserved fields are zero */
    if (gc->gctx_paddr & SNP_ADDR_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the guest context page is in the FIRMWARE state */
    status = rmp_get_addr_entry_state(gc->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_FIRMWARE)
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Verify that the donated page is marked as a 4K page in the RMP */
    if (gctx_rmp_entry.q1.f.page_size != DRAM_PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto end;
    }

    /* CSF-961: Validate the memory map to make sure GCTX page doesn't overlap MMIO region */
    status = validate_memory_map(&gpDram->mem_map, gc->gctx_paddr, gc->gctx_paddr + PAGE_SIZE_4K - 1ULL);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto end;
    }

    /* Calculate the current tcb version using the latest uCode SVN */
    get_committed_tcb(&current_tcb);

    /* Transition the gctx page from FIRMWARE to CONTEXT state */
    gctx_rmp_entry.q1.f.vmsa = 1;    /* Firmware -> Context */

    /* Map to the the gctx page to access its contents */
    status = sev_hal_map_guest_context(gc->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Clear the gctx page */
    memset(gctx_x86_buffer, 0, PAGE_SIZE_4K); /* Clears gctx because it's the same pointer */

    /* Initialize the page with ASID, state, and VEK */
    gctx->guest.asid = 0;   /* Indicating that no ASID has been associated with this guest */
    gctx->guest.snp_state = SNP_GUEST_STATE_INIT;
    gctx->guest.type = SEV_GUEST_TYPE_SNP;
    status = sev_hal_trng(gctx->guest.umc_key_seed, sizeof(gctx->guest.umc_key_seed));  /* Generate a new VEK seed */
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;
    gctx->guest.oek_iv_count = 0;
    gctx->launch_tcb.val = current_tcb.val;
    gctx->current_build_id = SEV_BUILD_ID;
    gctx->current_api_minor = SEV_API_MINOR;
    gctx->current_api_major = SEV_API_MAJOR;
    gctx->psp_tsc_offset = 0;

    /* Write RMP changes back to x86 memory */
    status = rmp_entry_write(gctx_rmp_paddr, &gctx_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

/**
 * Note: If the checks in SNP_GUEST_REQUEST fail, that results in an error code
 *       returned at the mailbox protocol. If the checks in Chapter 8 fail, that
 *       results in a valid return message (that can be decrypted and a Guest
 *       Request mailbox protocol response of SUCCESS) with the given status code
 *       in the response payload. That's because in the first case, it's the
 *       hypervisor who messed up, whereas in the second case, the guest messed up.
 */
sev_status_t snp_mcmd_guest_request(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_guest_request_t *gr = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t request_rmp_paddr = 0;
    uint64_t response_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t request_rmp_entry;
    rmp_entry_t response_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t request_state;
    snp_page_state_t response_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    snp_guest_message_header_t *ReqHdr = NULL;
    snp_guest_message_header_t *RspHdr = NULL;
    uint8_t vmpck[32];
    uint8_t *pAlignedPTReqPayload = NULL;
    uint8_t *pAlignedPTRspPayload = NULL;
    uint64_t *pMsgCounter = NULL;

    uint64_t msg_gctx_paddr = 0;           /* gctx for the Export, Import, */
    uint64_t msg_gctx_rmp_paddr = 0;       /* Absorb, and VMRK messages    */
    rmp_entry_t msg_gctx_rmp_entry;
    snp_page_state_t msg_gctx_state;
    void *msg_gctx_x86_buffer = NULL;
    guest_context_page_t *msg_gctx = NULL;
    uint8_t iv[12];

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    gr = &cmd->snp_guest_request;

    /* Verify the reserved fields are zero */
    if (gr->gctx_paddr & SNP_ADDR_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state and the
       response page is in Firmware */
    status = rmp_get_addr_entry_state(gr->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(gr->request_paddr, &request_rmp_paddr, &request_rmp_entry, &request_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(gr->response_paddr, &response_rmp_paddr, &response_rmp_entry, &response_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }
    if (response_state != SNP_PAGE_STATE_FIRMWARE)
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Check that request and response pages are 4K in RMP */
    if (request_rmp_entry.q1.f.page_size != DRAM_PAGE_SIZE_4K ||
        response_rmp_entry.q1.f.page_size != DRAM_PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto end;
    }

    /* Map the guest context page so we can read */
    status = sev_hal_map_guest_context(gr->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state. Must be in Running */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Copy the Request Header to PSP private memory after validating no page
       boundary crossing */
    if ((((uint32_t)gr->request_paddr) & (PAGE_SIZE_4K-1)) > (PAGE_SIZE_4K - GUEST_REQUEST_HEADER_SIZE))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto unmap;
    }

    status = copy_from_x86(gr->request_paddr, gpSevScratchBuf, GUEST_REQUEST_HEADER_SIZE);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Validate the Request Header by checking that when HDR_VERSION is 1h, then HDR_SIZE must be 60h,
       that HDR_VERSION is supported by this ABI version, and the message size is aligned to 16B */
    ReqHdr = (snp_guest_message_header_t *)gpSevScratchBuf;
    if (ReqHdr->hdr_version != 1 || ReqHdr->hdr_size != GUEST_REQUEST_HEADER_SIZE ||
        ReqHdr->algo != 1 || ReqHdr->msg_size == 0 || !IS_ALIGNED_TO_16_BYTES(ReqHdr->msg_size))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto unmap;
    }

    /* Copy the Request Payload to PSP private memory after validating no page
       boundary crossing */
    if (((gr->request_paddr & (PAGE_SIZE_4K-1)) + GUEST_REQUEST_HEADER_SIZE) + (uint64_t)ReqHdr->msg_size > PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto unmap;
    }
    status = copy_from_x86(gr->request_paddr + GUEST_REQUEST_HEADER_SIZE, gpSevScratchBuf + GUEST_REQUEST_HEADER_SIZE, ReqHdr->msg_size);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Unwrap the message */
    RspHdr = (snp_guest_message_header_t *)(gpSevScratchBuf+PAGE_SIZE_4K);
    pAlignedPTReqPayload = /*(uint8_t *)(ALIGN_TO_16_BYTES*/(gpSevScratchBuf+(PAGE_SIZE_4K*2));
    pAlignedPTRspPayload = /*(uint8_t *)(ALIGN_TO_16_BYTES*/(gpSevScratchBuf+(PAGE_SIZE_4K*3));

    /* Determine which vmpck was used. We copy into a local buffer because the
       vmpck can change in absorb_noma and we want the rsp message to use the
       same key as the req message */
    if (ReqHdr->msg_vmpck == 0)
        memcpy(vmpck, gctx->vmpck0, sizeof(vmpck)), pMsgCounter = &gctx->msg_count0;
    else if (ReqHdr->msg_vmpck == 1)
        memcpy(vmpck, gctx->vmpck1, sizeof(vmpck)), pMsgCounter = &gctx->msg_count1;
      else if (ReqHdr->msg_vmpck == 2)
        memcpy(vmpck, gctx->vmpck2, sizeof(vmpck)), pMsgCounter = &gctx->msg_count2;
    else if (ReqHdr->msg_vmpck == 3)
        memcpy(vmpck, gctx->vmpck3, sizeof(vmpck)), pMsgCounter = &gctx->msg_count3;
    else
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto unmap;
    }

    /* Create the IV from the msg_seqno */
    memset(iv, 0, sizeof(iv));  // Clear all 12 bytes
    memcpy(iv, (uint8_t *)&ReqHdr->msg_seqno, sizeof(ReqHdr->msg_seqno));   // Copy the last 8 bytes

    /*
     * pKey = K param in spec = The guest's VMPCK identified by MSG_VMPCK
     * pAAD = A in the spec. is the metadata 0x30h to 0x5F of the request message
     * pMsg = C in spec = PAYLOAD
     * pOut = output cyphertext
     * pTag = T = AUTHTAG in spec
     * pIV = IV in spec
     */
    status = aes256gcm_authenticated_decrypt(vmpck, sizeof(vmpck),
                                             &ReqHdr->algo, SNP_GMSG_HDR_AAD_SIZE,
                                             &ReqHdr->payload, ReqHdr->msg_size,
                                             pAlignedPTReqPayload, iv, 12,
                                             ReqHdr->auth_tag);
    if (status != SEV_STATUS_SUCCESS)
        goto clear;

    /*
     * Check that the guest's message count of the VMPCK used to unwrap this
     * message will not overflow by processing this message.
     * Note: Odd message numbers come in and we store even counts here
     *       so the max we store before an overflow is (UINT64_MAX-1)
     */
    /* Check that MSG_SEQNO is one greater than the guest's message count for
       the VMPCK used to unwrap this message */
    if (*pMsgCounter == (UINT64_MAX-1) || ReqHdr->msg_seqno != *pMsgCounter+1)
    {
        status = SEV_STATUS_AEAD_OFLOW;
        goto clear;
    }

    /* Check that MSG_VERSION is supported by this ABI */
    if ((ReqHdr->msg_version == 0) ||
        (ReqHdr->msg_type == SNP_MSG_CPUID_REQ)  && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_CPUID_REQ)  ||
        (ReqHdr->msg_type == SNP_MSG_KEY_REQ)    && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_KEY_REQ)    ||
        (ReqHdr->msg_type == SNP_MSG_REPORT_REQ) && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_REPORT_REQ) ||
        (ReqHdr->msg_type == SNP_MSG_EXPORT_REQ) && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_EXPORT_REQ) ||
        (ReqHdr->msg_type == SNP_MSG_IMPORT_REQ) && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_IMPORT_REQ) ||
        (ReqHdr->msg_type == SNP_MSG_ABSORB_REQ) && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_ABSORB_REQ) ||
        (ReqHdr->msg_type == SNP_MSG_VMRK_REQ)   && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_VMRK_REQ)   ||
        (ReqHdr->msg_type == SNP_MSG_ABSORB_NOMA_REQ) && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_ABSORB_NOMA_REQ) ||
        (ReqHdr->msg_type == SNP_MSG_TSC_INFO_REQ)    && (ReqHdr->msg_version > SNP_GMSG_MAX_MSG_VERSION_TSC_INFO_REQ))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto clear;
    }

    /* Check that MSG_TYPE is a valid message type then check that MSG_SIZE is large
       enough to hold the indicated message type at the indicated message version */
    switch (ReqHdr->msg_type) {
    case SNP_MSG_CPUID_REQ: {
        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_CPUID_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_CPUID_RSP;
        RspHdr->msg_size = ReqHdr->msg_size;

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_cpuid_req_t *cpuid_req = (snp_msg_cpuid_req_t *)pAlignedPTReqPayload;
        snp_msg_cpuid_rsp_t *cpuid_rsp = (snp_msg_cpuid_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(cpuid_rsp, 0, sizeof(snp_msg_cpuid_rsp_t));  /* Clear the max size */

        /* Verify the reserved fields are zero */
        if ((cpuid_req->reserved != 0) || (cpuid_req->reserved2 != 0))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto cpuid_status;
        }

        if (cpuid_req->count > SNP_CPUID_COUNT_MAX)
        {
            /* Must be less than or equal to MAX_CPUIDs */
            status = SEV_STATUS_INVALID_PARAM;
            cpuid_rsp->count = 0;
            goto cpuid_status;
        }

        /* Copy the number of CPUID functions to the response message */
        memcpy(cpuid_rsp->cpuid_function, cpuid_req->cpuid_function, (cpuid_req->count * sizeof(snp_cpuid_function_t)));

        cpuid_rsp->count = 0;
        status = sanitize_cpuid_list(cpuid_rsp->cpuid_function, cpuid_req->count, &cpuid_rsp->count);
        if (status != SEV_STATUS_SUCCESS)
            goto cpuid_status;

cpuid_status:
        cpuid_rsp->status = status;
        break;
    }
    case SNP_MSG_KEY_REQ: {
        snp_mix_data_t mix_data;
        snp_identity_t vcek;

        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_KEY_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_KEY_RSP;
        RspHdr->msg_size = sizeof(snp_msg_key_rsp_t);

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_key_req_t *key_req = (snp_msg_key_req_t *)pAlignedPTReqPayload;
        snp_msg_key_rsp_t *key_rsp = (snp_msg_key_rsp_t *)pAlignedPTRspPayload;
        uint8_t *key = NULL;
        size_t key_size = 0;

        /* Create the response message */
        memset(key_rsp, 0, RspHdr->msg_size);
        memset(&mix_data, 0, sizeof(snp_mix_data_t));

        /* Verify the reserved fields are zero */
        if ((key_req->reserved != 0) || (key_req->reserved2 != 0))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_key_status;
        }

        /* Check that we are allowed to access the chip key. */
        if (key_req->root_key_select == 0 && gpDram->perm.mask_chip_key == 1)
        {
            status = SEV_STATUS_INVALID_KEY;
            goto set_key_status;
        }

        if (key_req->root_key_select == 0 &&
            ((key_req->key_sel == KEY_SEL_RESERVED) ||
             (key_req->key_sel == KEY_SEL_VLEK_ONLY && !vlek_installed()) ||
             (key_req->key_sel == KEY_SEL_VCEK_ONLY && gctx->vcek_dis) ||
             (key_req->key_sel == KEY_SEL_VLEK_VCEK && gctx->vcek_dis && !vlek_installed())))
        {
            status = SEV_STATUS_INVALID_KEY;
            goto set_key_status;
        }

        /* Copy the VCEK, used to sign the msg, to a local var so it can be
           overwritten if optional TCB flag is set */
        memcpy(&vcek, &gpDram->perm.snp_identity, sizeof(snp_identity_t));

        /* Populate the mix data struct. These are not known by the user */
        mix_data.root_key_select = key_req->root_key_select;
        if (gctx->author_key_en == 1)
            mix_data.idblock_key_select = 2;
        else if (gctx->id_block_en == 1)
            mix_data.idblock_key_select = 1;
        else
            mix_data.idblock_key_select = 0;

        /* Make sure VMPL is not greater than current VMPL. If mix_data is requesting
           more a secure VMPL/VMPCK than what it used to sign the message */
        if (key_req->vmpl < ReqHdr->msg_vmpck)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_key_status;
        }

        /* Check that no guest_field_select bits are set that don't correspond to a flag */
        if ((key_req->guest_field_select & (~SNP_GUEST_FIELD_ALL)) != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_key_status;
        }

        /* Always */
        /* VCEK/VMRK gets mixed in during the kdf */
        mix_data.vmpl = key_req->vmpl;
        memcpy(&mix_data.host_data, &gctx->host_data, sizeof(mix_data.host_data));
        if (mix_data.idblock_key_select == 1)
            memcpy(&mix_data.idblock_key, &gctx->id_key_digest, sizeof(mix_data.idblock_key));
        else if (mix_data.idblock_key_select == 2)
            memcpy(&mix_data.idblock_key, &gctx->author_key_digest, sizeof(mix_data.idblock_key));
        else
            memset(&mix_data.idblock_key, 0, sizeof(mix_data.idblock_key));
        mix_data.gfs = key_req->guest_field_select;

        /* Optional fields */
        if ((key_req->guest_field_select & SNP_GUEST_FIELD_TCB_VERSION_FLAG) == SNP_GUEST_FIELD_TCB_VERSION_FLAG)
        {
            snp_tcb_version_t current_tcb;

            /* Calculate the current tcb version using the latest uCode SVN */
            get_committed_tcb(&current_tcb);

            /* x86 provided TCB must not exceed the current TCB version */
            if (key_req->tcb_version.f.boot_loader > current_tcb.f.boot_loader ||
                key_req->tcb_version.f.tee         > current_tcb.f.tee         ||
                key_req->tcb_version.f.reserved[0] != 0                        ||
                key_req->tcb_version.f.reserved[1] != 0                        ||
                key_req->tcb_version.f.reserved[2] != 0                        ||
                key_req->tcb_version.f.reserved[3] != 0                        ||
                key_req->tcb_version.f.snp         > current_tcb.f.snp         ||
                key_req->tcb_version.f.microcode   > current_tcb.f.microcode)
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto set_key_status;
            }

            /* If TCB is less (older) than the current TCB, re-calculate.
               Use a local var to not modify the sev_t 'current' copy */
            status = vcek_hash_derive(vcek.vcek_hash, DIGEST_SHA384_SIZE_BYTES, &key_req->tcb_version);
            if (status != SEV_STATUS_SUCCESS)
                goto set_key_status;

            mix_data.tcb_version.val = key_req->tcb_version.val;
        }
        if ((key_req->guest_field_select & SNP_GUEST_FIELD_GUEST_SVN_FLAG) == SNP_GUEST_FIELD_GUEST_SVN_FLAG)
        {
            if (key_req->guest_svn > gctx->id_block.guest_svn)
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto set_key_status;
            }
            mix_data.guest_svn = key_req->guest_svn;
        }
        if ((key_req->guest_field_select & SNP_GUEST_FIELD_MEASUREMENT_FLAG) == SNP_GUEST_FIELD_MEASUREMENT_FLAG)
        {
            memcpy(mix_data.measurement, gctx->measurement, sizeof(mix_data.measurement));
        }
        if ((key_req->guest_field_select & SNP_GUEST_FIELD_FAMILY_ID_FLAG) == SNP_GUEST_FIELD_FAMILY_ID_FLAG)
        {
            memcpy(&mix_data.family_id, gctx->id_block.family_id, sizeof(mix_data.family_id));
        }
        if ((key_req->guest_field_select & SNP_GUEST_FIELD_IMAGE_ID_FLAG) == SNP_GUEST_FIELD_IMAGE_ID_FLAG)
        {
            memcpy(&mix_data.image_id, gctx->id_block.image_id, sizeof(mix_data.image_id));
        }
        if ((key_req->guest_field_select & SNP_GUEST_FIELD_GUEST_POLICY_FLAG) == SNP_GUEST_FIELD_GUEST_POLICY_FLAG)
        {
            mix_data.guest_policy = gctx->guest.policy_snp;
        }

        /* Actually do the KDF based on the root_key_select for VCEK/VLEK/VMRK */
        if (key_req->root_key_select == 0)  /* VCEK or VLEK */
        {
            if (key_req->key_sel == KEY_SEL_VLEK_VCEK)
            {
                if (vlek_installed())
                {
                    key = &gpDram->perm.vlek[7][0];
                    key_size = sizeof(gpDram->perm.vlek[0]);
                } else {
                    key = &vcek.vcek_hash[0];
                    key_size = sizeof(vcek.vcek_hash);
                }
            }
            if (key_req->key_sel == KEY_SEL_VCEK_ONLY)
            {
                key = &vcek.vcek_hash[0];
                key_size = sizeof(vcek.vcek_hash);
            }
            if (key_req->key_sel == KEY_SEL_VLEK_ONLY && vlek_installed())
            {
                key = &gpDram->perm.vlek[7][0];
                key_size = sizeof(gpDram->perm.vlek[0]);
            }
        }
        else                                /* VMRK */
        {
            key = &gctx->vmrk[0];
            key_size = sizeof(gctx->vmrk);
        }

        if (key == NULL)
        {
            status = SEV_STATUS_INVALID_KEY;
            goto set_key_status;
        }

        status = nist_kdf(key_rsp->derived_key, sizeof(key_rsp->derived_key),
                    key, key_size,
                    KEY_REQ_LABEL, sizeof(KEY_REQ_LABEL)-1,
                    (uint8_t *)&mix_data, sizeof(mix_data));

        if (status != SEV_STATUS_SUCCESS) /* Hardware error in nist_kdf */
            secure_memzero(key_rsp->derived_key, sizeof(key_rsp->derived_key));

set_key_status:
        secure_memzero(&vcek, sizeof(snp_identity_t));
        key_rsp->status = status;
        key = NULL;
        break;
    }
    case SNP_MSG_REPORT_REQ: {
        uint32_t chip_id_length = 0;
        uint32_t tsme_en = false;
        snp_tcb_version_t tcb;
        ecc_keypair_t *key = NULL;

        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_REPORT_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_REPORT_RSP;
        RspHdr->msg_size = sizeof(snp_msg_report_rsp_t);

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_report_req_t *report_req = (snp_msg_report_req_t *)pAlignedPTReqPayload;
        snp_msg_report_rsp_t *report_rsp = (snp_msg_report_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(report_rsp, 0, RspHdr->msg_size);
        report_rsp->report_size = sizeof(snp_attestation_report_t);

        /* Verify the reserved fields are zero */
        if (!is_empty(report_req->reserved, sizeof(report_req->reserved)) ||
            report_req->reserved_bits != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_report_status;
        }

        if ((report_req->key_sel == KEY_SEL_RESERVED) ||
            (report_req->key_sel == KEY_SEL_VLEK_ONLY && !vlek_installed()) ||
            (report_req->key_sel == KEY_SEL_VCEK_ONLY && gctx->vcek_dis) ||
            (report_req->key_sel == KEY_SEL_VLEK_VCEK && gctx->vcek_dis && !vlek_installed()))
        {
            status = SEV_STATUS_INVALID_KEY;
            goto set_report_status;
        }

        /* Make sure VMPL is not greater than current VMPL - if report is requesting
           more a secure VMPL/VMPCK than what it used to sign the message */
        if (report_req->vmpl < ReqHdr->msg_vmpck)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_report_status;
        }

        report_rsp->report.version = SNP_GMSG_MAX_REPORT_VERSION;
        report_rsp->report.guest_svn = gctx->id_block.guest_svn; /* Pass through from LaunchFinish */
        report_rsp->report.policy = gctx->guest.policy_snp;      /* Matches gctx->id_block.policy if set */
        memcpy(&report_rsp->report.family_id, gctx->id_block.family_id, sizeof(report_rsp->report.family_id)); /* Pass through from LaunchFinish */
        memcpy(&report_rsp->report.image_id, gctx->id_block.image_id, sizeof(report_rsp->report.image_id));    /* Pass through from LaunchFinish */
        report_rsp->report.vmpl = report_req->vmpl;
        report_rsp->report.signature_algo = SNP_SIGNATURE_ALGO_ECDSA_P384_SHA384;
        /* Calculate the current tcb version using the latest uCode SVN */
        status = get_running_tcb(&tcb, NULL);
        if (status != SEV_STATUS_SUCCESS)
            goto clear;
        report_rsp->report.tcb_version.val = tcb.val;
        report_rsp->report.platform_info.smt_en = (uint32_t)gPersistent.smt_enabled;
        report_rsp->report.author_key_en = gctx->author_key_en;
        report_rsp->report.mask_chip_key = gpDram->perm.mask_chip_key;
        memcpy(report_rsp->report.report_data, report_req->report_data, sizeof(report_rsp->report.report_data));
        memcpy(report_rsp->report.measurement, gctx->measurement, DIGEST_SHA384_SIZE_BYTES);                /* Set in LaunchUpdate */
        memcpy(report_rsp->report.host_data, gctx->host_data, sizeof(report_rsp->report.host_data));        /* Pass through from LaunchFinish */
        memcpy(report_rsp->report.id_key_digest, gctx->id_key_digest, DIGEST_SHA384_SIZE_BYTES);            /* Set in LaunchFinish */
        memcpy(report_rsp->report.author_key_digest, gctx->author_key_digest, DIGEST_SHA384_SIZE_BYTES);    /* Set in LaunchFinish */
        memcpy(report_rsp->report.report_id, gctx->report_id, sizeof(report_rsp->report.report_id));        /* Set in LaunchStart */
        memcpy(report_rsp->report.report_id_ma, gctx->report_id_ma, sizeof(report_rsp->report.report_id_ma));  /* Set in LaunchStart */
        /* Calculate the current tcb version using the latest uCode SVN */
        get_reported_tcb(&tcb);
        report_rsp->report.reported_tcb.val = tcb.val;
        get_committed_tcb(&tcb);
        report_rsp->report.committed_tcb.val = tcb.val;
        report_rsp->report.current_build_id = SEV_BUILD_ID;
        report_rsp->report.current_api_minor = SEV_API_MINOR;
        report_rsp->report.current_api_major = SEV_API_MAJOR;
        report_rsp->report.committed_build_id = gpDram->perm.committed_build_id;
        report_rsp->report.committed_api_minor = gpDram->perm.committed_api_minor;
        report_rsp->report.committed_api_major = gpDram->perm.committed_api_major;
        report_rsp->report.launch_tcb.val = gctx->launch_tcb.val;

        /* Populate the GetID for P0 */
        if (!gpDram->perm.mask_chip_id)
        {
            status = sev_get_id(sizeof(get_id_t), (uint8_t *)&report_rsp->report.chip_id, &chip_id_length);
            if (status != SEV_STATUS_SUCCESS)
            {
                goto set_report_status;
            }
            if (chip_id_length != sizeof(report_rsp->report.chip_id)) /* Make sure length is 64B */
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto set_report_status;
            }
        }

        /* Populate TSME_EN */
        status = sev_hal_get_misc_tsme_enable(&tsme_en);
        if (status != SEV_STATUS_SUCCESS)
        {
            goto set_report_status;
        }
        report_rsp->report.platform_info.tsme_en = tsme_en;
        report_rsp->report.signing_key = SIGNING_KEY_NONE;

        if (report_req->key_sel == KEY_SEL_VLEK_VCEK)
        {
            if (vlek_installed())
            {
                key = &gpDram->perm.vlek_key;
                report_rsp->report.signing_key = SIGNING_KEY_VLEK;
            } else if (!gpDram->perm.mask_chip_key) {
                key = &gpDram->perm.snp_identity.vcek.keypair.ecdsa;
                report_rsp->report.signing_key = SIGNING_KEY_VCEK;
            }
        }
        if (report_req->key_sel == KEY_SEL_VCEK_ONLY && !gpDram->perm.mask_chip_key)
        {
            key = &gpDram->perm.snp_identity.vcek.keypair.ecdsa;
            report_rsp->report.signing_key = SIGNING_KEY_VCEK;
        }
        if (report_req->key_sel == KEY_SEL_VLEK_ONLY && vlek_installed())
        {
            key = &gpDram->perm.vlek_key;
            report_rsp->report.signing_key = SIGNING_KEY_VLEK;
        }

        /* Sign the report, unless we are not supposed to */
        if (key != NULL)
            status = ecdsa_sign_msg((ecdsa_sig_t *)&report_rsp->report.signature,
                                key,
                                (uint8_t *)&report_rsp->report,
                                offsetof(snp_attestation_report_t, signature),
                                SEV_CERT_ALGO_ECDSA_SHA384);

set_report_status:
        report_rsp->status = status;
        break;
    }
    case SNP_MSG_EXPORT_REQ: {
        bool is_ma_export = false;
        bool is_self_export = false;

        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_EXPORT_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_EXPORT_RSP;
        RspHdr->msg_size = PAGE_SIZE_4K - ReqHdr->hdr_size;     /* Payload size */

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_export_req_t *export_req = (snp_msg_export_req_t *)pAlignedPTReqPayload;
        snp_msg_export_rsp_t *export_rsp = (snp_msg_export_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(export_rsp, 0, RspHdr->msg_size);
        export_rsp->gctx_size = sizeof(snp_msg_gctx_t);
        export_rsp->gctx_version = SNP_GMSG_MAX_XPORT_GCTX_VERSION;

        /* Verify the reserved fields are zero */
        if ((export_req->gctx_paddr & SNP_ADDR_RESERVED_MASK) ||
            (export_req->reserved != 0) || (export_req->reserved2 != 0))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_export_status;
        }

        msg_gctx_paddr = SNP_PAGE_ADDR(export_req->gctx_paddr);

        /* Verify that the Guest context page is in the CONTEXT state */
        status = rmp_get_addr_entry_state(msg_gctx_paddr, &msg_gctx_rmp_paddr, &msg_gctx_rmp_entry, &msg_gctx_state);
        if (status != SEV_STATUS_SUCCESS)
            goto set_export_status;
        if (msg_gctx_state != SNP_PAGE_STATE_CONTEXT)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto set_export_status;
        }

        /* Map the guest context page so we can read/write */
        status = sev_hal_map_guest_context(msg_gctx_paddr, &msg_gctx_x86_buffer, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto set_export_status;
        msg_gctx = (guest_context_page_t *)msg_gctx_x86_buffer;

        /* Check the guest state */
        if (msg_gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
        {
            status = SEV_STATUS_INVALID_GUEST_STATE;
            goto unmap_export_guest;
        }

        /* MA export: The guest sending the message is the migration agent of the exported guest.
           Self Export: The guest sending the message has no migration agent and is exporting itself.
           In the spec: requesting = gctx_paddr, provided = ma_gctx_paddr */
        is_ma_export = ((msg_gctx->migration_agent_paddr == gr->gctx_paddr) &&
                        (memcmp(gctx->report_id, msg_gctx->report_id_ma, sizeof(gctx->report_id)) == 0));
        is_self_export = (gr->gctx_paddr == msg_gctx_paddr) && (gctx->migration_agent_paddr == PADDR_INVALID);
        if (!(is_self_export || is_ma_export))
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto unmap_export_guest;
        }

        /* If the gest is exporting itself, the firmware checks that the guest
           message was encrypted with VMPCK0. That is, only VMPL0 can self-export.
           If not, the firmware returns a status of INVALID_GUEST. */
        if (is_self_export && ReqHdr->msg_vmpck != 0)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto unmap_export_guest;
        }

        /* Set the payload */
        memcpy(export_rsp->gctx.ld, msg_gctx->measurement, DIGEST_SHA384_SIZE_BYTES);
        memcpy(export_rsp->gctx.oek, msg_gctx->guest.oek, sizeof(export_rsp->gctx.oek));
        memcpy(export_rsp->gctx.vmpck0, msg_gctx->vmpck0, sizeof(export_rsp->gctx.vmpck0));
        memcpy(export_rsp->gctx.vmpck1, msg_gctx->vmpck1, sizeof(export_rsp->gctx.vmpck1));
        memcpy(export_rsp->gctx.vmpck2, msg_gctx->vmpck2, sizeof(export_rsp->gctx.vmpck2));
        memcpy(export_rsp->gctx.vmpck3, msg_gctx->vmpck3, sizeof(export_rsp->gctx.vmpck3));
        memcpy(export_rsp->gctx.vmrk, msg_gctx->vmrk, sizeof(export_rsp->gctx.vmrk));
        memcpy(export_rsp->gctx.host_data, msg_gctx->host_data, sizeof(export_rsp->gctx.host_data));
        memcpy(export_rsp->gctx.id_key_digest, msg_gctx->id_key_digest, DIGEST_SHA384_SIZE_BYTES);
        memcpy(export_rsp->gctx.author_key_digest, msg_gctx->author_key_digest, DIGEST_SHA384_SIZE_BYTES);
        memcpy(export_rsp->gctx.report_id, msg_gctx->report_id, sizeof(export_rsp->gctx.report_id));
        memcpy(export_rsp->gctx.imd, msg_gctx->imd, sizeof(export_rsp->gctx.imd));
        export_rsp->gctx.msg_count0 = msg_gctx->msg_count0;
        export_rsp->gctx.msg_count1 = msg_gctx->msg_count1;
        export_rsp->gctx.msg_count2 = msg_gctx->msg_count2;
        export_rsp->gctx.msg_count3 = msg_gctx->msg_count3;
        memcpy(&export_rsp->gctx.root_md_entry, &msg_gctx->root_md_entry, sizeof(snp_metadata_page_t));
        export_rsp->gctx.author_key_en = msg_gctx->author_key_en;
        export_rsp->gctx.id_block_en = msg_gctx->id_block_en;
        export_rsp->gctx.policy = msg_gctx->guest.policy_snp;
        export_rsp->gctx.state = msg_gctx->guest.snp_state;
        export_rsp->gctx.oek_iv_count = msg_gctx->guest.oek_iv_count;
        memcpy((uint8_t *)&export_rsp->gctx.id_block, (uint8_t *)&msg_gctx->id_block, sizeof(export_rsp->gctx.id_block));
        memcpy(export_rsp->gctx.gosvw, msg_gctx->gosvw, sizeof(export_rsp->gctx.gosvw));
        export_rsp->gctx.desired_tsc_freq = msg_gctx->desired_tsc_freq;
        export_rsp->gctx.psp_tsc_offset = msg_gctx->psp_tsc_offset;
        export_rsp->gctx.launch_tcb = msg_gctx->launch_tcb.val;
        export_rsp->gctx.vcek_dis = msg_gctx->vcek_dis;

        /* If IMI_EN is 0, make the exported guest unable to run on this platform
           If IMI_EN is 1, allow the exported guest to continue running on this platform */
        if (export_req->imi_en == 0)
        {
            status = snp_decommission_common(sev, msg_gctx);      /* Decommission the guest */
            if (status != SEV_STATUS_SUCCESS)
                goto unmap_export_guest;

            /* Transition the gctx page from CONTEXT to FIRMWARE state */
            msg_gctx_rmp_entry.q1.f.vmsa = 0;    /* Context -> Firmware */

            /* Write RMP changes back to x86 memory */
            status = rmp_entry_write(msg_gctx_rmp_paddr, &msg_gctx_rmp_entry);
        }
        else /* If IMI_EN is 1, do not export the RootMDEntry. Instead, write 0h to the RootMDEntry field. */
        {
            memset(&export_rsp->gctx.root_md_entry, 0, sizeof(snp_metadata_page_t));
        }

unmap_export_guest:
        /* Unmap the gctx_page mem */
        sev_hal_unmap_guest_context(msg_gctx_x86_buffer, PAGE_SIZE_4K);

set_export_status:
        export_rsp->status = status;
        break;
    }
    case SNP_MSG_IMPORT_REQ: {
        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_IMPORT_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_IMPORT_RSP;
        RspHdr->msg_size = sizeof(snp_msg_import_rsp_t);  /* Payload size */

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_import_req_t *import_req = (snp_msg_import_req_t *)pAlignedPTReqPayload;
        snp_msg_import_rsp_t *import_rsp = (snp_msg_import_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(import_rsp, 0, RspHdr->msg_size);

        /* Verify the reserved fields are zero */
        if ((import_req->gctx_paddr & SNP_ADDR_RESERVED_MASK) ||
            (!is_empty(import_req->reserved, sizeof(import_req->reserved))))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_import_status;
        }

        /* Verify the gctx_size and gctx_version are correct */
        if ((import_req->in_gctx_size != sizeof(snp_msg_gctx_t)) ||
            (import_req->in_gctx_version != SNP_GMSG_MAX_XPORT_GCTX_VERSION))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_import_status;
        }

        msg_gctx_paddr = SNP_PAGE_ADDR(import_req->gctx_paddr);

        /* Verify that the Guest context page is in the CONTEXT state */
        status = rmp_get_addr_entry_state(msg_gctx_paddr, &msg_gctx_rmp_paddr, &msg_gctx_rmp_entry, &msg_gctx_state);
        if (status != SEV_STATUS_SUCCESS)
            goto set_import_status;
        if (msg_gctx_state != SNP_PAGE_STATE_CONTEXT)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto set_import_status;
        }

        /* Map the guest context page so we can read/write */
        status = sev_hal_map_guest_context(msg_gctx_paddr, &msg_gctx_x86_buffer, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto set_import_status;
        msg_gctx = (guest_context_page_t *)msg_gctx_x86_buffer;

        /* Check that the guest is in the INIT state */
        if (msg_gctx->guest.snp_state != SNP_GUEST_STATE_INIT)
        {
            status = SEV_STATUS_INVALID_GUEST_STATE;
            goto unmap_import_guest;
        }

        /* Check that RootMDEntry of the incoming guest context has its VALID
           field set to 1. Gets set in SwapOut */
        if (import_req->incoming_gctx.root_md_entry.mdata_entry.f.valid != 1)
        {
            status = SEV_STATUS_INVALID_MDATA_ENTRY;
            goto unmap_import_guest;
        }

        /* Import all of the data into the guest */
        memcpy(msg_gctx->measurement, import_req->incoming_gctx.ld, DIGEST_SHA384_SIZE_BYTES);
        memcpy(msg_gctx->guest.oek, import_req->incoming_gctx.oek, sizeof(msg_gctx->guest.oek));
        memcpy(msg_gctx->vmpck0, import_req->incoming_gctx.vmpck0, sizeof(import_req->incoming_gctx.vmpck0));
        memcpy(msg_gctx->vmpck1, import_req->incoming_gctx.vmpck1, sizeof(import_req->incoming_gctx.vmpck1));
        memcpy(msg_gctx->vmpck2, import_req->incoming_gctx.vmpck2, sizeof(import_req->incoming_gctx.vmpck2));
        memcpy(msg_gctx->vmpck3, import_req->incoming_gctx.vmpck3, sizeof(import_req->incoming_gctx.vmpck3));
        memcpy(msg_gctx->vmrk, import_req->incoming_gctx.vmrk, sizeof(import_req->incoming_gctx.vmrk));
        memcpy(msg_gctx->host_data, import_req->incoming_gctx.host_data, sizeof(import_req->incoming_gctx.host_data));

        memcpy(msg_gctx->id_key_digest, import_req->incoming_gctx.id_key_digest, DIGEST_SHA384_SIZE_BYTES);
        memcpy(msg_gctx->author_key_digest, import_req->incoming_gctx.author_key_digest, DIGEST_SHA384_SIZE_BYTES);
        memcpy(msg_gctx->imd, import_req->incoming_gctx.imd, sizeof(msg_gctx->imd));
        msg_gctx->msg_count0 = import_req->incoming_gctx.msg_count0;
        msg_gctx->msg_count1 = import_req->incoming_gctx.msg_count1;
        msg_gctx->msg_count2 = import_req->incoming_gctx.msg_count2;
        msg_gctx->msg_count3 = import_req->incoming_gctx.msg_count3;
        memcpy(&msg_gctx->root_md_entry, &import_req->incoming_gctx.root_md_entry, sizeof(snp_metadata_page_t));
        msg_gctx->author_key_en = import_req->incoming_gctx.author_key_en;
        msg_gctx->id_block_en = import_req->incoming_gctx.id_block_en;
        msg_gctx->guest.policy_snp = import_req->incoming_gctx.policy;
        // msg_gctx->guest.snp_state = (snp_guest_state_t)import_req->incoming_gctx.state;  /* Set in snp_guest_state_transition */
        msg_gctx->guest.oek_iv_count = import_req->incoming_gctx.oek_iv_count;
        memcpy((uint8_t *)&msg_gctx->id_block, (uint8_t *)&import_req->incoming_gctx.id_block, sizeof(msg_gctx->id_block));
        memcpy(msg_gctx->gosvw, import_req->incoming_gctx.gosvw, sizeof(msg_gctx->gosvw));
        msg_gctx->desired_tsc_freq = import_req->incoming_gctx.desired_tsc_freq;
        msg_gctx->psp_tsc_offset = import_req->incoming_gctx.psp_tsc_offset;
        msg_gctx->launch_tcb.val = import_req->incoming_gctx.launch_tcb;

        /* Initialize the guest context with the MSG_IMPORT_REQ contents */
        msg_gctx->migration_agent_paddr = gr->gctx_paddr;
        msg_gctx->imi_en = 0;
        memcpy(msg_gctx->report_id_ma, gctx->report_id, sizeof(msg_gctx->report_id_ma));
        status = sev_hal_trng(msg_gctx->report_id, sizeof(msg_gctx->report_id));
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_import_guest;

        msg_gctx->guest.es.head_index = INVALID_BLOCK;
        msg_gctx->guest.es.tail_index = INVALID_BLOCK;
        /* Enable SEV-ES for this guest */
        msg_gctx->guest.guest_flags |= SEV_GUEST_FLAGS_ES_FLAG;

        /* Transition the guest to the RUNNING state */
        status = snp_guest_state_transition(&msg_gctx->guest, SNP_MCMD_ID_GUEST_REQUEST);   /* No way to specify which GMSG */
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_import_guest;

unmap_import_guest:
        /* Unmap the gctx_page mem */
        sev_hal_unmap_guest_context(msg_gctx_x86_buffer, PAGE_SIZE_4K);

set_import_status:
        /* Create the response message */
        import_rsp->status = status;
        break;
    }
    case SNP_MSG_ABSORB_REQ: {
        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_ABSORB_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_ABSORB_RSP;
        RspHdr->msg_size = sizeof(snp_msg_absorb_rsp_t);  /* Payload size */

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_absorb_req_t *absorb_req = (snp_msg_absorb_req_t *)pAlignedPTReqPayload;
        snp_msg_absorb_rsp_t *absorb_rsp = (snp_msg_absorb_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(absorb_rsp, 0, RspHdr->msg_size);

        /* Verify the reserved fields are zero */
        if ((absorb_req->gctx_paddr & SNP_ADDR_RESERVED_MASK) ||
            (!is_empty(absorb_req->reserved, sizeof(absorb_req->reserved))))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_absorb_status;
        }

        msg_gctx_paddr = SNP_PAGE_ADDR(absorb_req->gctx_paddr);

        /* Verify that the Guest context page is in the CONTEXT state */
        status = rmp_get_addr_entry_state(msg_gctx_paddr, &msg_gctx_rmp_paddr, &msg_gctx_rmp_entry, &msg_gctx_state);
        if (status != SEV_STATUS_SUCCESS)
            goto set_absorb_status;
        if (msg_gctx_state != SNP_PAGE_STATE_CONTEXT)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto set_absorb_status;
        }

        /* Map the guest context page so we can read/write */
        status = sev_hal_map_guest_context(msg_gctx_paddr, &msg_gctx_x86_buffer, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto set_absorb_status;
        msg_gctx = (guest_context_page_t *)msg_gctx_x86_buffer;

        /* Check the guest state and that GCTX.IMIEn is 1 */
        if (msg_gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH || msg_gctx->imi_en != 1)
        {
            status = SEV_STATUS_INVALID_GUEST_STATE;
            goto unmap_absorb_guest;
        }

        /* Check that RootMDEntry of the incoming guest context has its VALID
           field set to 0 */
        if (msg_gctx->root_md_entry.mdata_entry.f.valid != 0)
        {
            status = SEV_STATUS_INVALID_MDATA_ENTRY;
            goto unmap_absorb_guest;
        }

        /* Check that the IN_GCTX.IMD (exported Guest) is equal to GCTX.LD (empty Guest) */
        if (memcmp(absorb_req->incoming_gctx.imd, msg_gctx->measurement, DIGEST_SHA384_SIZE_BYTES) != 0)
        {
            status = SEV_STATUS_BAD_MEASUREMENT;
            goto unmap_absorb_guest;
        }

        /* Check the IN_GCTX_VERSION and the IN_GCTX_SIZE */
        if (absorb_req->in_gctx_version != SNP_GMSG_MAX_XPORT_GCTX_VERSION ||
            absorb_req->in_gctx_size != sizeof(snp_msg_gctx_t))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto unmap_absorb_guest;
        }

        /* Overwrite the guest context at GCTX_PADDR with the guest context in the
           INCOMING_GCTX field but preserve the report_id generated during LaunchStart */
        memcpy(msg_gctx->measurement, absorb_req->incoming_gctx.ld, DIGEST_SHA384_SIZE_BYTES);
        memcpy(msg_gctx->guest.oek, absorb_req->incoming_gctx.oek, sizeof(msg_gctx->guest.oek));
        memcpy(msg_gctx->vmpck0, absorb_req->incoming_gctx.vmpck0, sizeof(absorb_req->incoming_gctx.vmpck0));
        memcpy(msg_gctx->vmpck1, absorb_req->incoming_gctx.vmpck1, sizeof(absorb_req->incoming_gctx.vmpck1));
        memcpy(msg_gctx->vmpck2, absorb_req->incoming_gctx.vmpck2, sizeof(absorb_req->incoming_gctx.vmpck2));
        memcpy(msg_gctx->vmpck3, absorb_req->incoming_gctx.vmpck3, sizeof(absorb_req->incoming_gctx.vmpck3));
        memcpy(msg_gctx->vmrk, absorb_req->incoming_gctx.vmrk, sizeof(absorb_req->incoming_gctx.vmrk));
        memcpy(msg_gctx->host_data, absorb_req->incoming_gctx.host_data, sizeof(absorb_req->incoming_gctx.host_data));
        memcpy(msg_gctx->id_key_digest, absorb_req->incoming_gctx.id_key_digest, DIGEST_SHA384_SIZE_BYTES);
        memcpy(msg_gctx->author_key_digest, absorb_req->incoming_gctx.author_key_digest, DIGEST_SHA384_SIZE_BYTES);
        memcpy(msg_gctx->imd, absorb_req->incoming_gctx.imd, sizeof(msg_gctx->imd));
        msg_gctx->msg_count0 = absorb_req->incoming_gctx.msg_count0;
        msg_gctx->msg_count1 = absorb_req->incoming_gctx.msg_count1;
        msg_gctx->msg_count2 = absorb_req->incoming_gctx.msg_count2;
        msg_gctx->msg_count3 = absorb_req->incoming_gctx.msg_count3;
        memcpy(&msg_gctx->root_md_entry, &absorb_req->incoming_gctx.root_md_entry, sizeof(snp_metadata_page_t));
        msg_gctx->author_key_en = absorb_req->incoming_gctx.author_key_en;
        msg_gctx->id_block_en = absorb_req->incoming_gctx.id_block_en;
        msg_gctx->guest.policy_snp = absorb_req->incoming_gctx.policy;
        // msg_gctx->guest.snp_state = (snp_guest_state_t)absorb_req->incoming_gctx.state;  /* Set in snp_guest_state_transition */
        msg_gctx->guest.oek_iv_count = absorb_req->incoming_gctx.oek_iv_count;
        memcpy((uint8_t *)&msg_gctx->id_block, (uint8_t *)&absorb_req->incoming_gctx.id_block, sizeof(msg_gctx->id_block));
        memcpy(msg_gctx->gosvw, absorb_req->incoming_gctx.gosvw, sizeof(msg_gctx->gosvw));
        msg_gctx->desired_tsc_freq = absorb_req->incoming_gctx.desired_tsc_freq;
        msg_gctx->psp_tsc_offset = absorb_req->incoming_gctx.psp_tsc_offset;
        msg_gctx->launch_tcb.val = absorb_req->incoming_gctx.launch_tcb;
        msg_gctx->migration_agent_paddr = gr->gctx_paddr;
        memcpy(msg_gctx->report_id_ma, gctx->report_id, sizeof(msg_gctx->report_id_ma));

        /* The guest has already been launched (LaunchStart), so do not need to
           initialize the guest context with the MSG_ABSORB_REQ contents */

        msg_gctx->guest.es.head_index = INVALID_BLOCK;
        msg_gctx->guest.es.tail_index = INVALID_BLOCK;
        /* Enable SEV-ES for this guest */
        msg_gctx->guest.guest_flags |= SEV_GUEST_FLAGS_ES_FLAG;

        /* Transition the guest to the RUNNING state */
        status = snp_guest_state_transition(&msg_gctx->guest, SNP_MCMD_ID_GUEST_REQUEST);   /* No way to specify which GMSG */
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_absorb_guest;

unmap_absorb_guest:
        /* Unmap the gctx_page mem */
        sev_hal_unmap_guest_context(msg_gctx_x86_buffer, PAGE_SIZE_4K);

set_absorb_status:
        /* Create the response message */
        absorb_rsp->status = status;
        break;
    }
    case SNP_MSG_VMRK_REQ: {
        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_VMRK_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_VMRK_RSP;
        RspHdr->msg_size = sizeof(snp_msg_vmrk_rsp_t);  /* Payload size */

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_vmrk_req_t *vmrk_req = (snp_msg_vmrk_req_t *)pAlignedPTReqPayload;
        snp_msg_vmrk_rsp_t *vmrk_rsp = (snp_msg_vmrk_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(vmrk_rsp, 0, RspHdr->msg_size);

        /* The message must be encrypted with the migration agent's VMPCK0 */
        if (ReqHdr->msg_vmpck != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_vmrk_status;
        }

        /* Verify the reserved fields are zero */
        if ((vmrk_req->gctx_paddr & SNP_ADDR_RESERVED_MASK) ||
            (!is_empty(vmrk_req->reserved, sizeof(vmrk_req->reserved))))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_vmrk_status;
        }

        msg_gctx_paddr = SNP_PAGE_ADDR(vmrk_req->gctx_paddr);

        /* Verify that the Guest context page is in the CONTEXT state */
        status = rmp_get_addr_entry_state(msg_gctx_paddr, &msg_gctx_rmp_paddr, &msg_gctx_rmp_entry, &msg_gctx_state);
        if (status != SEV_STATUS_SUCCESS)
            goto set_vmrk_status;
        if (msg_gctx_state != SNP_PAGE_STATE_CONTEXT)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto set_vmrk_status;
        }

        /* Map the guest context page so we can read/write */
        status = sev_hal_map_guest_context(msg_gctx_paddr, &msg_gctx_x86_buffer, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto set_vmrk_status;
        msg_gctx = (guest_context_page_t *)msg_gctx_x86_buffer;

        /* Check the guest state and that GCTX.IMIEn is 0 */
        if (msg_gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH || msg_gctx->imi_en != 0)
        {
            status = SEV_STATUS_INVALID_GUEST_STATE;
            goto unmap_vmrk_guest;
        }

        /* Check that GCTX.MA of the guest matches the GCTX_PADDR of the migration
           agent - that is, the guest sending the MSG_VMRK_REQ message */
        if (msg_gctx->migration_agent_paddr != gr->gctx_paddr ||
            memcmp(msg_gctx->report_id_ma, gctx->report_id, sizeof(gctx->report_id)) != 0)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto unmap_vmrk_guest;
        }

        /* Install the VMRK into the guest's GCTX.VMRK */
        memcpy(msg_gctx->vmrk, vmrk_req->vmrk, sizeof(msg_gctx->vmrk));

unmap_vmrk_guest:
        /* Unmap the gctx_page mem */
        sev_hal_unmap_guest_context(msg_gctx_x86_buffer, PAGE_SIZE_4K);

set_vmrk_status:
        /* Create the response message */
        vmrk_rsp->status = status;
        break;
    }
    case SNP_MSG_ABSORB_NOMA_REQ: {
        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_ABSORB_NOMA_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_ABSORB_NOMA_RSP;
        RspHdr->msg_size = sizeof(snp_msg_absorb_noma_rsp_t);  /* Payload size */

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_absorb_noma_req_t *absorb_req = (snp_msg_absorb_noma_req_t *)pAlignedPTReqPayload;
        snp_msg_absorb_noma_rsp_t *absorb_rsp = (snp_msg_absorb_noma_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(absorb_rsp, 0, RspHdr->msg_size);

        /* Verify the reserved fields are zero */
        if ((absorb_req->reserved != 0) ||
            (!is_empty(absorb_req->reserved2, sizeof(absorb_req->reserved2))))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_absorb_noma_status;
        }

        /* Check that GCTX.MA is PADDR_INVALID */
        if (gctx->migration_agent_paddr != PADDR_INVALID)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto set_absorb_noma_status;
        }

        /* Check that the IN_GCTX.IMD is equal to GCTX.LD and IN_GCTX.IMD is
           equal to GCTX.IMD */
        if ((memcmp(absorb_req->incoming_gctx.imd, gctx->measurement, DIGEST_SHA384_SIZE_BYTES) != 0) ||
            (memcmp(absorb_req->incoming_gctx.imd, gctx->imd, DIGEST_SHA384_SIZE_BYTES) != 0))
        {
            status = SEV_STATUS_BAD_MEASUREMENT;
            goto set_absorb_noma_status;
        }

        /* Check the IN_GCTX_VERSION and the IN_GCTX_SIZE */
        if (absorb_req->in_gctx_version != SNP_GMSG_MAX_XPORT_GCTX_VERSION ||
            absorb_req->in_gctx_size != sizeof(snp_msg_gctx_t))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_absorb_noma_status;
        }

        /* Overwrite the guest context at GCTX_PADDR with the guest context in the INCOMING_GCTX field */
        memcpy(gctx->measurement, absorb_req->incoming_gctx.ld, DIGEST_SHA384_SIZE_BYTES);
        memcpy(gctx->guest.oek, absorb_req->incoming_gctx.oek, sizeof(gctx->guest.oek));
        memcpy(gctx->vmpck0, absorb_req->incoming_gctx.vmpck0, sizeof(absorb_req->incoming_gctx.vmpck0));
        memcpy(gctx->vmpck1, absorb_req->incoming_gctx.vmpck1, sizeof(absorb_req->incoming_gctx.vmpck1));
        memcpy(gctx->vmpck2, absorb_req->incoming_gctx.vmpck2, sizeof(absorb_req->incoming_gctx.vmpck2));
        memcpy(gctx->vmpck3, absorb_req->incoming_gctx.vmpck3, sizeof(absorb_req->incoming_gctx.vmpck3));
        memcpy(gctx->vmrk, absorb_req->incoming_gctx.vmrk, sizeof(absorb_req->incoming_gctx.vmrk));
        memcpy(gctx->host_data, absorb_req->incoming_gctx.host_data, sizeof(absorb_req->incoming_gctx.host_data));
        memcpy(gctx->imd, absorb_req->incoming_gctx.imd, sizeof(gctx->imd));
        gctx->msg_count0 = absorb_req->incoming_gctx.msg_count0;
        gctx->msg_count1 = absorb_req->incoming_gctx.msg_count1;
        gctx->msg_count2 = absorb_req->incoming_gctx.msg_count2;
        gctx->msg_count3 = absorb_req->incoming_gctx.msg_count3;
        memcpy(&gctx->root_md_entry, &absorb_req->incoming_gctx.root_md_entry, sizeof(snp_metadata_page_t));
        gctx->guest.policy_snp = absorb_req->incoming_gctx.policy;
        gctx->guest.oek_iv_count = absorb_req->incoming_gctx.oek_iv_count;
        memcpy(gctx->gosvw, absorb_req->incoming_gctx.gosvw, sizeof(gctx->gosvw));
        gctx->desired_tsc_freq = absorb_req->incoming_gctx.desired_tsc_freq;
        gctx->psp_tsc_offset = absorb_req->incoming_gctx.psp_tsc_offset;
        gctx->launch_tcb.val = absorb_req->incoming_gctx.launch_tcb;

        gctx->guest.es.head_index = INVALID_BLOCK;
        gctx->guest.es.tail_index = INVALID_BLOCK;
        /* Enable SEV-ES for this guest */
        gctx->guest.guest_flags |= SEV_GUEST_FLAGS_ES_FLAG;

set_absorb_noma_status:
        /* Create the response message */
        absorb_rsp->status = status;
        break;
    }
    case SNP_MSG_TSC_INFO_REQ: {
        /* No matter what, we return a valid response */
        RspHdr->msg_type = SNP_MSG_TSC_INFO_RSP;
        RspHdr->msg_version = SNP_GMSG_MAX_MSG_VERSION_TSC_INFO_RSP;
        RspHdr->msg_size = sizeof(snp_msg_tsc_info_rsp_t);  /* Payload size */

        /* Point the message structure at the decrypted payload in the header */
        snp_msg_tsc_info_req_t *tsc_req = (snp_msg_tsc_info_req_t *)pAlignedPTReqPayload;
        snp_msg_tsc_info_rsp_t *tsc_rsp = (snp_msg_tsc_info_rsp_t *)pAlignedPTRspPayload;

        /* Create the response message */
        memset(tsc_rsp, 0, RspHdr->msg_size);

        /* Verify the reserved fields are zero */
        if (!is_empty(tsc_req->reserved, sizeof(tsc_req->reserved)))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto set_tsc_info_status;
        }

        /* Populate the response message */
        tsc_rsp->guest_tsc_scale = calc_tsc_scale(gctx->desired_tsc_freq, REF_CLK_GENOA);
        tsc_rsp->guest_tsc_offset = gctx->psp_tsc_offset;
        tsc_rsp->tsc_factor = TSC_FACTOR_GENOA;

set_tsc_info_status:
        /* Create the response message */
        tsc_rsp->status = status;
        break;
    }
    default: {
        status = SEV_STATUS_INVALID_PARAM;
        goto clear;
    }
    }

    /*
     * Create a message in response to the guest's message. Set MSG_SEQNO of the
     * response message to one greater than the MSG_SEQNO of the request message
     */
    RspHdr->algo = AEAD_ALGO_AES_256_GCM;
    RspHdr->hdr_version = SNP_GMSG_MAX_HDR_VERSION;
    RspHdr->hdr_size = sizeof(snp_guest_message_header_t)-1;
    RspHdr->msg_seqno = ReqHdr->msg_seqno+1; /* Bump the msg_seqno/iv */
    RspHdr->msg_vmpck = ReqHdr->msg_vmpck;

    /* Now that we know the length of the response message */
    /* Make sure the address and buffer don't cross a page boundary */
    if (((gr->response_paddr & (PAGE_SIZE_4K-1)) + RspHdr->hdr_size + RspHdr->msg_size) > PAGE_SIZE_4K)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto clear;
    }

    /* Create the IV from the msg_seqno */
    memset(iv, 0, sizeof(iv));  // Clear all 12 bytes
    memcpy(iv, (uint8_t *)&RspHdr->msg_seqno, sizeof(RspHdr->msg_seqno));   // Copy the last 8 bytes

     /*
      * pKey = K param in spec = The guest's VMPCK identified by MSG_VMPCK
      * pAAD = A in the spec. is the metadata 0x30h to 0x5F of the request message
      * pMsg = P in spec = PAYLOAD plaintext
      * pOut = output cyphertext
      * pTag = T = AUTHTAG in spec
      * pIV = IV in spec = bits 95:0 of the IV
      */
    status = aes256gcm_authenticated_encrypt(vmpck, sizeof(vmpck),
                                             &RspHdr->algo, SNP_GMSG_HDR_AAD_SIZE,
                                             pAlignedPTRspPayload, RspHdr->msg_size,
                                             &RspHdr->payload, iv, 12,
                                             RspHdr->auth_tag);
    if (status != SEV_STATUS_SUCCESS)
        goto clear;

    /* Increment the guest's message count for the VMPCK count by two to account
       for both the request message and the firmware's response message */
    *pMsgCounter += 2;

    /* Write the data to the Response page in x86 memory */
    status = copy_to_x86(gr->response_paddr, RspHdr, RspHdr->hdr_size + RspHdr->msg_size);
    if (status != SEV_STATUS_SUCCESS)
        goto clear;

clear:
    /* Clear any secrets that may be stored in the scratch buffer */
    secure_memzero(pAlignedPTReqPayload, PAGE_SIZE_4K);
    secure_memzero(pAlignedPTRspPayload, PAGE_SIZE_4K);
unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);
    /* Clear any secrets that may be stored on the stack */
    secure_memzero(vmpck, sizeof(vmpck));
end:
    return status;
}

sev_status_t snp_mcmd_activate_ex(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_activate_ex_t *act = NULL;
    uint64_t gctx_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    snp_page_state_t gctx_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    uint64_t asid_count = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    act = &cmd->snp_activate_ex;

    if (act->ex_len != sizeof(*act))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Verify the reserved fields are zero */
    if ((act->reserved != 0) || (act->gctx_paddr & SNP_ADDR_RESERVED_MASK))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(act->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(act->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state. Can either be in Launch or in Running */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH &&
        gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* If the guest is not activated, check that there are no pages assigned to the ASID in the RMP */
    if (guest_is_inactive(&gctx->guest))
    {
        status = check_rmp_for_asid(act->asid, &asid_count);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
        if (asid_count != 0)
        {
            status = SEV_STATUS_INVALID_CONFIG;
            goto unmap;
        }
    }

    status = mcmd_activate_ex_common(sev, &gctx->guest, act->asid, act->numids,
                                     act->ids_paddr, gctx->migration_agent_paddr);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

/**
 * Why gctx is aligned here:
 *  Due to alignment requirements for 'ld' in guest array in PSP DRAM,
 *  compiler decided that any sev_guest_t must be so aligned, although
 *  that is not the case in SRAM. Compiler/linker will not align auto
 *  variable beyond 8 byte alignment, so use flexible buffer for 'new_guest'.
 */
sev_status_t snp_mcmd_launch_start(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_launch_start_t *ls = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t ma_gctx_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t ma_gctx_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t ma_gctx_state;
    void *gctx_x86_buffer = NULL;
    void *ma_gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    guest_context_page_t *ma_gctx = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ls = &cmd->snp_launch_start;

    /* Verify the reserved fields are zero */
    if ((ls->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (ls->reserved != 0) ||
        (ls->ma_gctx_paddr & SNP_ADDR_RESERVED_MASK))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(ls->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(ls->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Copy over the contents of the Migration Agent */
    if (ls->ma_en)
    {
        /* Verify that the MA guest context page is in the CONTEXT state */
        status = rmp_get_addr_entry_state(ls->ma_gctx_paddr, &ma_gctx_rmp_paddr, &ma_gctx_rmp_entry, &ma_gctx_state);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
        if (ma_gctx_state != SNP_PAGE_STATE_CONTEXT)
        {
            status = SEV_STATUS_INVALID_GUEST;
            goto unmap;
        }

        /* Map the guest context page so we can read/write */
        status = sev_hal_map_guest_context(ls->ma_gctx_paddr, &ma_gctx_x86_buffer, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        ma_gctx = (guest_context_page_t *)ma_gctx_x86_buffer;
    }

    /* Initialize the head and tail index */
    gctx->guest.es.head_index = INVALID_BLOCK;
    gctx->guest.es.tail_index = INVALID_BLOCK;

    /* Enable SEV-ES for this guest */
    gctx->guest.guest_flags |= SEV_GUEST_FLAGS_ES_FLAG;

    /*
     * 1. If MA_EN is 1h, POLICY.MIGRATE_MA must be 1h
     * 2. If MA_EN is 1h, then the migration agent must not be migratable-that is,
     *    the migration agent itself must not be bound to another migration agent
     * 3. POLICY.VMPL must be 1h
     * 4. If POLICY.SMT is 0h, then SMT must be disabled
     * 5. POLICY.ABI_MAJOR must be 1h, the major version of this ABI
     * 6. POLICY.ABI_MINOR must be 1h, the minor version of this ABI
     * 7. If POLICY.SINGLE_SOCKET is 1 and MA_EN is 1, then the migration agent's
     *    POLICY.SINGLE_SOCKET must be 1
     */
    if ((ls->ma_en && !(ls->policy & SNP_GUEST_POLICY_MIGRATE_MA_FLAG))  ||
        (ls->ma_en && (ma_gctx->migration_agent_paddr != PADDR_INVALID)) ||
        (!(ls->policy & SNP_GUEST_POLICY_VMPL_FLAG))                     ||
        (!(ls->policy & SNP_GUEST_POLICY_SMT_FLAG) && gPersistent.smt_enabled) ||
        (SEV_API_MAJOR < snp_policy_major(ls->policy))                   ||
        ((SEV_API_MAJOR == snp_policy_major(ls->policy)) && (SEV_API_MINOR < snp_policy_minor(ls->policy))) ||
        (ls->policy & SNP_GUEST_POLICY_RESERVED_MASK) ||
        ((ls->ma_en && (ls->policy & SNP_GUEST_POLICY_SINGLE_SOCKET_FLAG)) && !(ma_gctx->guest.policy_snp & SNP_GUEST_POLICY_SINGLE_SOCKET_FLAG)))
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto unmap_all;
    }

    /* Initialize the gctx page. (Zero'd out in gctx_create) */
    gctx->guest.policy_snp = ls->policy;
    gctx->migration_agent_paddr = (ls->ma_en) ? ls->ma_gctx_paddr : PADDR_INVALID;
    status = sev_hal_trng(gctx->guest.oek, sizeof(gctx->guest.oek));    /* Generate new Offline Encryption Key */
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    status = sev_hal_trng(gctx->vmpck0, sizeof(gctx->vmpck0));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    status = sev_hal_trng(gctx->vmpck1, sizeof(gctx->vmpck1));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    status = sev_hal_trng(gctx->vmpck2, sizeof(gctx->vmpck2));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    status = sev_hal_trng(gctx->vmpck3, sizeof(gctx->vmpck3));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    status = sev_hal_trng(gctx->vmrk, sizeof(gctx->vmrk));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    status = sev_hal_trng(gctx->report_id, sizeof(gctx->report_id));
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;
    if (ls->ma_en)
        memcpy(gctx->report_id_ma, ma_gctx->report_id, sizeof(gctx->report_id_ma));
    else
        memset(gctx->report_id_ma, (uint8_t)PADDR_INVALID, sizeof(gctx->report_id_ma));
    gctx->imi_en = ls->imi_en;
    memcpy(gctx->gosvw, ls->gosvw, sizeof(gctx->gosvw));
    gctx->desired_tsc_freq = ls->desired_tsc_freq;

    gpDram->perm.snp_guest_count++;

    /* Advance the guest state machine. Platform stays INIT */
    status = snp_guest_state_transition(&gctx->guest, SNP_MCMD_ID_LAUNCH_START);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_all;

unmap_all:
    if (ma_gctx_x86_buffer)        /* Unmap the ma_gctx_page mem */
    {
        sev_hal_unmap_guest_context(ma_gctx_x86_buffer, PAGE_SIZE_4K);
    }
unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

/**
 * launch_update uses the scratch buffer to decrypt the data, so offset our gctx
 * so they don't overrun. We only support 4K lengths for SNP, so offsetting
 * gctx by 4K should be safe
 */
sev_status_t snp_mcmd_launch_update(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_launch_update_t *lu = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t page_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t page_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t page_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    uint32_t size = PAGE_SIZE_4K;
    uint32_t bytes_remaining = 0;
    uint64_t x86_addr = 0;
    uint64_t sha_gpa  = 0;
    snp_launch_update_secrets_page_t *secrets_page = NULL;
    digest_sha_t launch_digest;
    size_t ld_len = DIGEST_SHA384_SIZE_BYTES;
    snp_mcmd_launch_update_page_info_t page_info;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    lu = &cmd->snp_launch_update;

    /* Verify the reserved fields are zero */
    if ((lu->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (lu->page_paddr & SNP_ADDR_RESERVED_MASK) ||
        (lu->reserved != 0 )|| (lu->reserved2 != 0) || (lu->reserved3 != 0) || (lu->reserved4 != 0))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(lu->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Need the RMP entry for page to access GPA and to confirm the page size */
    x86_addr = lu->page_paddr;

    /* Verify that the Page is in the PRE_GUEST state */
    status = rmp_get_addr_entry_state(x86_addr, &page_rmp_paddr, &page_rmp_entry, &page_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (page_state != SNP_PAGE_STATE_PRE_GUEST)
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Check that the dest page size in the RMP matches the page size input param */
    if (page_rmp_entry.q1.f.page_size != lu->page_size)
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto end;
    }

    /* If PAGE_SIZE is 1, then PAGE_PADDR is 2MB aligned */
    if (page_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_2M && !IS_ALIGNED_TO_2MB(lu->page_paddr))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* Check page_type and page_size */
    switch (lu->page_type) {
    case SNP_PAGE_TYPE_NORMAL:
    case SNP_PAGE_TYPE_ZERO:
    case SNP_PAGE_TYPE_UNMEASURED: {
        /* Nothing special */
        break;
    }
    case SNP_PAGE_TYPE_VMSA:
    case SNP_PAGE_TYPE_SECRETS:
    case SNP_PAGE_TYPE_CPUID: {         /* Page must be 4K */
        if (page_rmp_entry.q1.f.page_size != DRAM_PAGE_SIZE_4K)
        {
            status = SEV_STATUS_INVALID_PAGE_SIZE;
            goto end;
        }
        break;
    }
    case SNP_PAGE_TYPE_RESERVED:
    default: {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(lu->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Check ASID to make sure the page is owned by the guest */
    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap;
    }

    /* Check that the ASID of the destination page in the RMP matches the ASID of the guest */
    if (page_rmp_entry.q1.f.asid != gctx->guest.asid)
    {
        status = SEV_STATUS_INVALID_PAGE_OWNER;
        goto unmap;
    }

    /* Check that if GCTX.IMIEn is 1, then IMI_PAGE is also 1 */
    if (gctx->imi_en == 1 && lu->imi_page != 1)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto unmap;
    }

    sha_gpa = RMP_GPA_TO_PADDR(page_rmp_entry.q1.f.gpa);

    /* Construct a page_info structure. Set the static values of page_info */
    memset(&page_info, 0, sizeof(page_info));
    page_info.length = sizeof(page_info);
    page_info.page_type = lu->page_type;
    page_info.imi_page = lu->imi_page;
    page_info.vmpl3_perms = lu->vmpl3_perms;
    page_info.vmpl2_perms = lu->vmpl2_perms;
    page_info.vmpl1_perms = lu->vmpl1_perms;

    /*
     * Problem (CSF-689):
     *   If the x86 writes with key0 (unencrypted) and another x86 core
     *   writes with key1 then the fabric will evict the key0 lines;
     *   but if the PSP does the write with key1 then the fabric does not.
     * Note:
     *   SNPLaunchUpdate ZERO pages are affected because they don't read the
     *   src page at all. LaunchUpdateData, LaunchUpdateVMSA, and LaunchSecret
     *   are not affected because they read from the src page before writing.
     * Solutions (currently doing 1):
     *  (Always) First, set the RdSzWrBkInvd bit and then
     *   1. Always call copy_from_x86, even for ZERO pages (which just calls
     *      memset) which don't need it so that the fabric evicts the key0 lines
     *   2. Write the buffer as unencrypted and then write the buffer again
     *      as encrypted, since PSP writes would cause an x86 cache eviction
     */
    /* Enable rd_sz_wbinvd around copy_from_x86. Reading in unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Use the scratch buffer as an intermediate buffer for the encryption operation */
    bytes_remaining = (lu->page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;
    do
    {
        /* Solution 1 from CSF-689 comment above */
        /* Copy the data to PSP private memory */
        status = copy_from_x86(x86_addr, gpSevScratchBuf, size);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_and_clear_wrbkinvd;

        /* Measure the (unaltered) guest data */
        if (lu->page_type == SNP_PAGE_TYPE_NORMAL || lu->page_type == SNP_PAGE_TYPE_VMSA || lu->page_type == SNP_PAGE_TYPE_UNMEASURED)
        {
            digest_sha_t data_ld_digest;    /* Digest */
            size_t data_ld_len = DIGEST_SHA384_SIZE_BYTES;

            if (lu->page_type != SNP_PAGE_TYPE_UNMEASURED)  /* NORMAL/VMSA */
            {
                uint64_t tsc_scale = 0, tsc_offset = 0;

                /* If VMSA page, ignore the values of GUEST_TSC_SCALE and GUEST_TSC_OFFSET
                   and measure the VMSA as if those fields contained zero */
                if (lu->page_type == SNP_PAGE_TYPE_VMSA)
                {
                    tsc_scale = *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_SCALE);
                    tsc_offset = *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_OFFSET);
                    *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_SCALE) = 0;
                    *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_OFFSET) = 0;
                }

                /* Create the SHA384 digest of the 4K chunk */
                status = digest_sha(gpSevScratchBuf, size, &data_ld_digest,
                                    &data_ld_len, SHA_TYPE_384);
                if (status != SEV_STATUS_SUCCESS)
                    goto unmap_and_clear_wrbkinvd;

                /* Copy the SHA384 digest of the 4K chunk into the page_info struct */
                memcpy(&page_info.contents, &data_ld_digest, data_ld_len);

                /* After the measurement is taken, apply the XOR tweak to the VMSA */
                if (lu->page_type == SNP_PAGE_TYPE_VMSA)
                {
                    /* Put the tsc scale and offset back before copying the page back to x86 */
                    *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_SCALE) = tsc_scale;
                    *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_OFFSET) = tsc_offset;

                    status = sev_es_vmsa_xor_tweak((uint8_t *)gpSevScratchBuf, sev->snp.vmsa_tweak_bitmap);
                    if (status != SEV_STATUS_SUCCESS)
                        goto unmap_and_clear_wrbkinvd;

                    /* If SecureTsc in the SEV_FEATURES field of the VMSA is 1,
                       set the guest_tsc_scale and guest_tsc_offset in the vmsa */
                    if (VMSA_SEV_FEATURES_SECURE_TSC_ENABLED(gpSevScratchBuf))
                    {
                        *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_SCALE) = calc_tsc_scale(gctx->desired_tsc_freq, REF_CLK_GENOA);
                        *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_OFFSET) = 0;
                    }
                }
            }
        }
        if (lu->page_type == SNP_PAGE_TYPE_VMSA)
        {
            /* Setup the VMSA for use with SEV-ES. Note: VMSA is only one 4K page */
            /* SNP doesn't use sev->sev.es, but we need to pass something into this
               function so we can setup/clear the VMSA */
            status = sev_es_setup_vmsa(&sev->sev.es, &gctx->guest, gpSevScratchBuf, size);
            if (status != SEV_STATUS_SUCCESS)
                goto unmap_and_clear_wrbkinvd;
        }

        /* Zero and Secret pages do something special with the data first */
        if (lu->page_type == SNP_PAGE_TYPE_ZERO || lu->page_type == SNP_PAGE_TYPE_SECRETS)
        {
            memset(gpSevScratchBuf, 0, size);
        }
        if (lu->page_type == SNP_PAGE_TYPE_SECRETS)
        {
            /* Set up the secrets page */
            secrets_page = (snp_launch_update_secrets_page_t *)gpSevScratchBuf; /* Point the buffer to the input page */
            memset(secrets_page, 0, sizeof(snp_launch_update_secrets_page_t));
            secrets_page->version = SNP_LAUNCH_UPDATE_SECRETS_PAGE_VERSION;
            secrets_page->imi_en = gctx->imi_en;
            secrets_page->tsc_factor = TSC_FACTOR_GENOA;
            status = get_fms(&secrets_page->fms);
            if (status != SEV_STATUS_SUCCESS)
                goto unmap_and_clear_wrbkinvd;
            memcpy(secrets_page->gosvw, gctx->gosvw, sizeof(secrets_page->gosvw));
            memcpy(secrets_page->vmpck0, &gctx->vmpck0, 4*sizeof(gctx->vmpck0));    /* Copy all 4 keys at once */
            memcpy(secrets_page->vmsa_tweak_bitmap, sev->snp.vmsa_tweak_bitmap, sizeof(sev->snp.vmsa_tweak_bitmap));
        }

        if (lu->page_type == SNP_PAGE_TYPE_CPUID)
        {
            snp_launch_update_cpuid_page_t *cpuid_page = (snp_launch_update_cpuid_page_t *)gpSevScratchBuf;
            uint32_t dummy = 0;

            /* Verify the reserved fields are zero */
            if ((cpuid_page->reserved != 0) || (cpuid_page->reserved2 != 0))
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto unmap_and_clear_wrbkinvd;
            }

            if (cpuid_page->count > SNP_CPUID_COUNT_MAX)
            {
                /* Must be less than or equal to MAX_CPUIDs */
                status = SEV_STATUS_INVALID_PARAM;
                goto unmap_and_clear_wrbkinvd;
            }

            status = sanitize_cpuid_list(cpuid_page->cpuids, cpuid_page->count, &dummy);
            if (status != SEV_STATUS_SUCCESS)
            {
                /* If CPUID has failures, copy the right values back to the buffer and exit without encryption */
                copy_to_x86(x86_addr, gpSevScratchBuf, size);
                goto unmap_and_clear_wrbkinvd;
            }
        }

        /* Finish constructing the page_info structure */
        /* page_info.contents was cleared to 0 and (possibly) set to data_ld_digest */
        memcpy(page_info.digest_cur, gctx->measurement, DIGEST_SHA384_SIZE_BYTES); /* ld_cur */
        page_info.gpa = sha_gpa;

        /* Calculate the digest of page_info */
        status = digest_sha(&page_info, sizeof(page_info), &launch_digest,
                            &ld_len, SHA_TYPE_384);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_and_clear_wrbkinvd;

        /* Unconditionally update GCTX.LD and GCTX.Measurement
         * Set the Guest launch digest to the new digest */
        memcpy(gctx->measurement, &launch_digest, DIGEST_SHA384_SIZE_BYTES);

        /* If IMI_PAGE is 1h, update the GCTX.IMD using the current GCTX.IMD value */
        if (lu->imi_page == 1)
        {
            memcpy(&page_info.digest_cur, &gctx->imd, sizeof(page_info.digest_cur));

            status = digest_sha(&page_info, sizeof(page_info), &launch_digest,
                                &ld_len, SHA_TYPE_384);
            if (status != SEV_STATUS_SUCCESS)
                goto unmap_and_clear_wrbkinvd;

            /* Update the Guest IMD value
             * Set the Guest launch digest to the new digest */
            memcpy(gctx->imd, &launch_digest, ld_len);
        }

        /* Encrypt the data using the UMC */
        status = copy_to_x86_encrypted(x86_addr, gpSevScratchBuf, size, gctx->guest.asid);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_and_clear_wrbkinvd;

        bytes_remaining -= size;
        x86_addr += size;
        sha_gpa += size;
    } while (bytes_remaining > 0);

    /* Set the VMPL permissions for the page */
    page_rmp_entry.q2.f.vmpl3.val = lu->vmpl3_perms;
    page_rmp_entry.q2.f.vmpl2.val = lu->vmpl2_perms;
    page_rmp_entry.q2.f.vmpl1.val = lu->vmpl1_perms;

    if (lu->page_type == SNP_PAGE_TYPE_VMSA)     /* Set the RMP.VMSA of the page to 1h */
        page_rmp_entry.q1.f.vmsa = 1;

    /* The firmware transitions the page from Pre-Guest to Guest-Valid */
    page_rmp_entry.q1.f.validated = 1;
    page_rmp_entry.q1.f.immutable = 0;
    page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;

    status = rmp_entry_write(page_rmp_paddr, &page_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_and_clear_wrbkinvd;

unmap_and_clear_wrbkinvd:
    /* Clear the rd_sz_wbinvd */
    set_misc_read_sized_wrbkinvd(false);

    /* Clear at least the secrets out of the scratch buf */
    if (lu->page_type == SNP_PAGE_TYPE_SECRETS)
        memset(gpSevScratchBuf, 0, sizeof(snp_launch_update_secrets_page_t));

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_launch_finish(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_launch_finish_t *lf = NULL;
    uint64_t gctx_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    snp_page_state_t gctx_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    uint32_t asid = 0;
    uint32_t ccxs = 0;
    snp_mcmd_launch_finish_id_block_t *id_block = NULL;
    snp_mcmd_launch_finish_id_auth_page_t *id_auth = NULL;
    digest_sha_t launch_digest;
    size_t ld_len = DIGEST_SHA384_SIZE_BYTES;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    lf = &cmd->snp_launch_finish;

    /* Verify the reserved fields are zero */
    if ((lf->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (lf->reserved != 0))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state */
    status = rmp_get_addr_entry_state(lf->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(lf->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state and that GCTX.IMIEn is 0 */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH || gctx->imi_en != 0)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap_gctx;
    }

    /* Check that the guest is activated/pending */
    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap_gctx;
    }

    if (lf->id_block_en)
    {
        ecc_pubkey_t *ecc_pubkey = NULL;
        ecdsa_sig_t *ecc_sig = NULL;

        /* Copy the id_block data to PSP private memory */
        status = copy_from_x86(lf->id_block_paddr, gpSevScratchBuf, sizeof(snp_mcmd_launch_finish_id_block_t));
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_gctx;
        id_block = (snp_mcmd_launch_finish_id_block_t *)gpSevScratchBuf;

        /* Copy the id_auth data to PSP private memory */
        status = copy_from_x86(lf->id_auth_paddr, gpSevScratchBuf+PAGE_SIZE_4K, sizeof(snp_mcmd_launch_finish_id_auth_page_t));
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_gctx;
        id_auth = (snp_mcmd_launch_finish_id_auth_page_t *)(gpSevScratchBuf+PAGE_SIZE_4K);

        /* Check that the LD field of the ID block is equal to GCTX.LD  */
        if (memcmp(&gctx->measurement, &id_block->ld, DIGEST_SHA384_SIZE_BYTES) != 0)
        {
            status = SEV_STATUS_BAD_MEASUREMENT;
            goto unmap_gctx;
        }

        /* Check that the POLICY field of the ID block is equal to GCTX.Policy */
        if (id_block->policy != gctx->guest.policy_snp)
        {
            status = SEV_STATUS_POLICY_FAILURE;
            goto unmap_gctx;
        }

        /* Check that the id_key_algo and auth_key_algo are correct algorithms */
        if ((id_auth->id_key_algo != SNP_SIGNATURE_ALGO_ECDSA_P384_SHA384) ||
            (lf->auth_key_en == 1 && id_auth->auth_key_algo != SNP_SIGNATURE_ALGO_ECDSA_P384_SHA384))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto unmap_gctx;
        }

        /* Validate the signature of the ID block using the ID public key */
        /* id_block_sig is the signature over the contents of the ID block
           pointed at by id_block_paddr by the id_key */
        ecc_pubkey = (ecc_pubkey_t *)id_auth->id_key;
        ecc_sig = (ecdsa_sig_t *)id_auth->id_block_sig;

        /* Verify the point is on the curve then verify the message */
        if (ecc_pubkey->curve != ECC_CURVE_NAME_SECP384R1 || !ecc_pubkey_is_valid(ecc_pubkey))
        {
            status = SEV_STATUS_BAD_SIGNATURE;
            goto unmap_gctx;
        }
        status = ecdsa_verify_msg(ecc_sig, ecc_pubkey, (uint8_t *)id_block,
                                  sizeof(snp_mcmd_launch_finish_id_block_t),
                                  SEV_CERT_ALGO_ECDSA_SHA384);
        if (status != SEV_STATUS_SUCCESS)
        {
            status = SEV_STATUS_BAD_SIGNATURE;
            goto unmap_gctx;
        }

        /* Calculate the digest of the id_key */
        status = digest_sha(&id_auth->id_key, sizeof(id_auth->id_key),
                            &launch_digest, &ld_len, SHA_TYPE_384);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_gctx;

        /* Store the id_block and id_key_digest into the Guest context.
           Guest params are already zero'd out otherwise */
        memcpy(&gctx->id_block, id_block, sizeof(snp_mcmd_launch_finish_id_block_t));
        memcpy(&gctx->id_key_digest, &launch_digest, ld_len);

        /* Validate the signature of the ID key using the Author public key */
        /* id_key_sig is the signature over the id_key by the author_key */
        if (lf->auth_key_en)
        {
            ecc_pubkey = (ecc_pubkey_t *)id_auth->author_key;
            ecc_sig = (ecdsa_sig_t *)id_auth->id_key_sig;

            /* Verify the point is on the curve then verify the message */
            if (ecc_pubkey->curve != ECC_CURVE_NAME_SECP384R1 || !ecc_pubkey_is_valid(ecc_pubkey))
            {
                status = SEV_STATUS_BAD_SIGNATURE;
                goto unmap_gctx;
            }
            status = ecdsa_verify_msg(ecc_sig, ecc_pubkey, (uint8_t *)id_auth->id_key,
                            sizeof(id_auth->id_key),
                            SEV_CERT_ALGO_ECDSA_SHA384);
            if (status != SEV_STATUS_SUCCESS)
            {
                status = SEV_STATUS_BAD_SIGNATURE;
                goto unmap_gctx;
            }

            /* Calculate the digest of the author_key */
            status = digest_sha(&id_auth->author_key, sizeof(id_auth->author_key),
                                &launch_digest, &ld_len, SHA_TYPE_384);
            if (status != SEV_STATUS_SUCCESS)
                goto unmap_gctx;

            /* Store the author_key_digest into the Guest context.
               Guest param is already zero'd out otherwise */
            memcpy(&gctx->author_key_digest, &launch_digest, ld_len);
        }
    }

    /* Initialize the Guest. id_block, id_key_digest, and author_key_digest
       are already 0 if not set above */
    memcpy(&gctx->host_data, lf->host_data, sizeof(gctx->host_data));
    gctx->id_block_en = lf->id_block_en;
    gctx->author_key_en = lf->auth_key_en;
    gctx->vcek_dis = lf->vcek_dis;

    /*
     * Clear the INVALID_ASID bit for the GCTX.SID
     * Changing to Running state. If guest is pending activation:
     * Clear ASID Invalid for each of the CCXs to be enabled for the guest,
     * and transition FW state for the guest's ASID on the enabled CCXs from
     * 'clean' to 'in-use'.
     */
    if (guest_is_pending(&gctx->guest))
    {
        status = sev_guest_finish_pending_activate(&gctx->guest);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap_gctx;

        asid = gctx->guest.asid;
        ccxs = gctx->guest.ccxs;

        /* Mark all of the guest's enabled CCXs for its ASID 'In use'. */
        gpDram->perm.asid_in_use[asid-1]    |= ccxs;
        gpDram->perm.asid_allocated[asid-1] &= ~ccxs;
        gpDram->perm.asid_clean[asid-1]     &= ~ccxs;
    }

    /* Advance the guest and platform state machines */
    status = snp_guest_state_transition(&gctx->guest, SNP_MCMD_ID_LAUNCH_FINISH);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_gctx;

unmap_gctx:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

/**
 * dbg_crypt uses the scratch buffer to decrypt the data, so offset our gctx
 * so they don't overrun. We only support 4K lengths for SNP, so offsetting
 * gctx by 4K should be safe
 */
sev_status_t snp_mcmd_dbg_decrypt(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_dbg_decrypt_t *dd = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t src_rmp_paddr = 0;
    uint64_t dst_rmp_paddr = 0;
    uint64_t two_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t src_rmp_entry;
    rmp_entry_t dst_rmp_entry;
    rmp_entry_t two_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t src_state;
    snp_page_state_t dst_state;
    snp_page_state_t two_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    dd = &cmd->snp_dbg_decrypt;

    /* Verify the reserved fields are zero */
    if ((dd->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (dd->src_paddr & SNP_ADDR_RESERVED_MASK) ||
        (dd->dst_paddr & SNP_ADDR_RESERVED_MASK))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state, the src page
     * is in (below) state, and dest page is in FIRMWARE state */
    status = rmp_get_addr_entry_state(dd->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(dd->src_paddr, &src_rmp_paddr, &src_rmp_entry, &src_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(dd->dst_paddr, &dst_rmp_paddr, &dst_rmp_entry, &dst_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Note that this command always operates on 4K regions despite the page
     *   size indicated by the RMP entries.
     * There are 3 cases that this command handles
     *   1. Normal 4K page. page_size=4K and asid=? (Firmware pages = 0)
     *   2. Subpage[0] in 2M page. page_size=2M and asid=x (not 0)
     *   3. Subpage[1 to 511] in a 2M page. page_size=4K and asid=0
     * So, read the RMP entry of the given 4K page. If the page_size=4K and
     *   asid is 0, assume it's Option 3 and mask off and check the Subpage[0]
     *   RMP entry (Option 2) for the correct state/asid. If an asid is 0, it's
     *   either because it's Option 3 or the page isn't associated with a guest
     *   (which would get caught later).
     * Do NOT change src_paddr or dst_paddr here, that's what actually get decrypted,
     *   but DO change src_rmp_entry and dst_rmp_entry
     */
    if (src_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K && src_rmp_entry.q1.f.asid == 0)
    {
        /* Determine if it's Option 1 or 2. Option 2 will have a 2M size page at the 2M aligned address */
        /* Get the rmp entry for the 2M aligned address */
        status = rmp_get_addr_entry_state(dd->src_paddr & ~(PAGE_SIZE_2M-1), &two_rmp_paddr, &two_rmp_entry, &two_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* If Option 2, use 2M aligned RMP entry, else, it's Option 1 and just continue */
        if (two_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_2M)
        {
            src_rmp_paddr = two_rmp_paddr;
            memcpy(&src_rmp_entry, &two_rmp_entry, sizeof(rmp_entry_t));
            src_state = two_state;
        }
    }
    if (dst_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K && dst_rmp_entry.q1.f.asid == 0)
    {
        /* Determine if it's Option 1 or 2. Option 2 will have a 2M size page at the 2M aligned address */
        /* Get the rmp entry for the 2M aligned address */
        status = rmp_get_addr_entry_state(dd->dst_paddr & ~(PAGE_SIZE_2M-1), &two_rmp_paddr, &two_rmp_entry, &two_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* If Option 2, use 2M aligned RMP entry, else, it's Option 1 and just continue */
        if (two_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_2M)
        {
            dst_rmp_paddr = two_rmp_paddr;
            memcpy(&dst_rmp_entry, &two_rmp_entry, sizeof(rmp_entry_t));
            dst_state = two_state;
        }
    }

    /* Now we can do the state checks */
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)           /* Check page state */
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }
    if ((src_state != SNP_PAGE_STATE_PRE_GUEST && src_state != SNP_PAGE_STATE_PRE_SWAP &&
         src_state != SNP_PAGE_STATE_GUEST_INVALID && src_state != SNP_PAGE_STATE_GUEST_VALID) ||
        (dst_state != SNP_PAGE_STATE_FIRMWARE))
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(dd->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check that the page containing the 4KB region is owned by the indicated guest */
    if (src_rmp_entry.q1.f.asid != gctx->guest.asid)
    {
        status = SEV_STATUS_INVALID_PAGE_OWNER;
        goto unmap;
    }

    /* The firmware checks that the guest's policy allows debugging. */
    if (!(gctx->guest.policy_snp & SNP_GUEST_POLICY_DEBUG_FLAG))
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto unmap;
    }

    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap;
    }

    /* If VMSA page, apply the XOR tweak if necessary, otherwise, follow the normal process */
    if (src_rmp_entry.q1.f.vmsa)   /* If RMP.VMSA of the source page is set */
    {
        /* Re-implement decrypt_memory() here */
        status = copy_from_x86_encrypted(dd->src_paddr, gpSevScratchBuf, PAGE_SIZE_4K, gctx->guest.asid);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        if (VMSA_SEV_FEATURES_VMSA_REG_PROT_ENABLED(gpSevScratchBuf))
        {
            /* Retrieve the 8B tweak value from offset 300h and apply it using
               the stored bitmap to the dest page */
            sev_es_apply_vmsa_bitmap(gpSevScratchBuf, sev->snp.vmsa_tweak_bitmap);
        }

        status = copy_to_x86(dd->dst_paddr, gpSevScratchBuf, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
    }
    else
    {
        /* Don't need to check for guest state, being active covers it
        * Even if the src/dst pages are 4K or 2M, always write 4K */
        status = debug_crypt_common(sev, &gctx->guest, false, dd->src_paddr, dd->dst_paddr, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
    }

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

/**
 * dbg_crypt uses the scratch buffer to decrypt the data, so offset our gctx
 * so they don't overrun. We only support 4K lengths for SNP, so offsetting
 * gctx by 4K should be safe
 */
sev_status_t snp_mcmd_dbg_encrypt(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_dbg_encrypt_t *de = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t src_rmp_paddr = 0;
    uint64_t dst_rmp_paddr = 0;
    uint64_t two_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t src_rmp_entry;
    rmp_entry_t dst_rmp_entry;
    rmp_entry_t two_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t src_state;
    snp_page_state_t dst_state;
    snp_page_state_t two_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    de = &cmd->snp_dbg_encrypt;

    /* Verify the reserved fields are zero */
    if ((de->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (de->src_paddr & SNP_ADDR_RESERVED_MASK) ||
        (de->dst_paddr & SNP_ADDR_RESERVED_MASK))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state and the dst
       page is in (below) state */
    status = rmp_get_addr_entry_state(de->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(de->src_paddr, &src_rmp_paddr, &src_rmp_entry, &src_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(de->dst_paddr, &dst_rmp_paddr, &dst_rmp_entry, &dst_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Note that this command always operates on 4K regions despite the page
     *   size indicated by the RMP entries.
     * There are 3 cases that this command handles
     *   1. Normal 4K page. page_size=4K and asid=x (not 0)
     *   2. Subpage[0] in 2M page. page_size=2M and asid=x (not 0)
     *   3. Subpage[1 to 511] in a 2M page. page_size=4K and asid=0
     * So, read the RMP entry of the given 4K page. If the page_size=4K and
     *   asid is 0, assume it's Option 3 and mask off and check the Subpage[0]
     *   RMP entry (Option 2) for the correct state/asid. If an asid is 0, it's
     *   either because it's Option 3 or the page isn't associated with a guest
     *   (which would get caught later).
     * Do NOT change src_paddr or dst_paddr here, that's what actually get decrypted,
     *   but DO change src_rmp_entry and dst_rmp_entry
     */
    if (src_state != SNP_PAGE_STATE_DEFAULT &&   /* Default pages don't have RMP entries */
        src_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K && src_rmp_entry.q1.f.asid == 0)
    {
        /* Determine if it's Option 1 or 2. Option 2 will have a 2M size page at the 2M aligned address */
        /* Get the rmp entry for the 2M aligned address */
        status = rmp_get_addr_entry_state(de->src_paddr & ~(PAGE_SIZE_2M-1), &two_rmp_paddr, &two_rmp_entry, &two_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* If Option 2, use 2M aligned RMP entry, else, it's Option 1 and just continue */
        if (two_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_2M)
        {
            src_rmp_paddr = two_rmp_paddr;
            memcpy(&src_rmp_entry, &two_rmp_entry, sizeof(rmp_entry_t));
            src_state = two_state;
        }
    }
    if (dst_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K && dst_rmp_entry.q1.f.asid == 0)
    {
        /* Determine if it's Option 1 or 2. Option 2 will have a 2M size page at the 2M aligned address */
        /* Get the rmp entry for the 2M aligned address */
        status = rmp_get_addr_entry_state(de->dst_paddr & ~(PAGE_SIZE_2M-1), &two_rmp_paddr, &two_rmp_entry, &two_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* If Option 2, use 2M aligned RMP entry, else, it's Option 1 and just continue */
        if (two_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_2M)
        {
            dst_rmp_paddr = two_rmp_paddr;
            memcpy(&dst_rmp_entry, &two_rmp_entry, sizeof(rmp_entry_t));
            dst_state = two_state;
        }
    }

    /* Now we can do the state checks */
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)           /* Check page state */
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }
    if (dst_state != SNP_PAGE_STATE_PRE_SWAP && dst_state != SNP_PAGE_STATE_PRE_GUEST)
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(de->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check that the destination page is owned by the indicated guest */
    if (dst_rmp_entry.q1.f.asid != gctx->guest.asid)
    {
        status = SEV_STATUS_INVALID_PAGE_OWNER;
        goto unmap;
    }

    /* The firmware checks that the guest's policy allows debugging. */
    if (!(gctx->guest.policy_snp & SNP_GUEST_POLICY_DEBUG_FLAG))
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto unmap;
    }

    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap;
    }

    /* Enable rd_sz_wbinvd around copy_from_x86. Page is unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* If VMSA page, apply the XOR tweak if necessary, otherwise, follow the normal process */
    if (dst_rmp_entry.q1.f.vmsa)   /* If RMP.VMSA of the source page is set */
    {
        /* Re-implement encrypt_memory() here */
        /* (CSF-698) Dummy read from x86_dest (with c-bit) and throw away the result */
        SET_CBIT(de->dst_paddr);
        status = copy_from_x86(de->dst_paddr, gpSevScratchBuf, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        /* (CSF-698) Dummy read from x86_dest (without c-bit) and throw away the result */
        CLEAR_CBIT(de->dst_paddr);
        status = copy_from_x86(de->dst_paddr, gpSevScratchBuf, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        status = copy_from_x86(de->src_paddr, gpSevScratchBuf, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        if (VMSA_SEV_FEATURES_VMSA_REG_PROT_ENABLED(gpSevScratchBuf))
        {
            /* Retrieve the 8B tweak value from offset 300h and apply it using
               the stored bitmap to the dest page */
            sev_es_apply_vmsa_bitmap(gpSevScratchBuf, sev->snp.vmsa_tweak_bitmap);
        }

        status = copy_to_x86_encrypted(de->dst_paddr, gpSevScratchBuf, PAGE_SIZE_4K, gctx->guest.asid);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
    }
    else
    {
        /* Don't need to check for guest state, being active covers it
        * Even if the src/dst pages are 4K or 2M, always write 4K */
        status = debug_crypt_common(sev, &gctx->guest, true, de->src_paddr, de->dst_paddr, PAGE_SIZE_4K);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
    }

unmap:
    /* Clear the rd_sz_wbinvd */
    set_misc_read_sized_wrbkinvd(false);

    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_swap_out(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_swap_out_t *so = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t src_rmp_paddr = 0;
    uint64_t dst_rmp_paddr = 0;
    uint64_t mdata_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t src_rmp_entry;
    rmp_entry_t dst_rmp_entry;
    rmp_entry_t mdata_rmp_entry;
    snp_metadata_page_t mdata_mdata_page;
    snp_page_state_t gctx_state;
    snp_page_state_t src_state;
    snp_page_state_t dst_state;
    snp_page_state_t mdata_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    uint32_t page_size = 0;
    uint32_t asid_for_gcm = 0;

    /* Clear the metadata page */
    memset(&mdata_mdata_page, 0, sizeof(snp_metadata_page_t));

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    so = &cmd->snp_swap_out;
    page_size = (so->page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;

    /* Verify the reserved fields are zero */
    if ((so->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (so->src_paddr & SNP_ADDR_RESERVED_MASK) ||
        (so->dst_paddr & SNP_ADDR_RESERVED_MASK) || (so->reserved != 0) || (so->reserved2 != 0))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Get RMP address/state of the guest context/src/dst pages */
    status = rmp_get_addr_entry_state(so->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(so->src_paddr, &src_rmp_paddr, &src_rmp_entry, &src_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(so->dst_paddr, &dst_rmp_paddr, &dst_rmp_entry, &dst_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify that guest context page is in CONTEXT state */
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Get RMP address/state of the metadata page */
    if (so->root_mdata_en == 0)
    {
        status = rmp_get_addr_entry_state(so->mdata_paddr, &mdata_rmp_paddr, &mdata_rmp_entry, &mdata_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Check that MDATA_PADDR is a valid sPA and is aligned to the size of
         * an MDATA structure (64B) */
        if (so->mdata_paddr % SNP_METADATA_ENTRY_SIZE)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        /* The MDATA_PADDR sPA must not overlap the source or destination pages */
        if (ranges_overlap(so->mdata_paddr, so->mdata_paddr + SNP_METADATA_ENTRY_SIZE - 1ULL,
                           so->src_paddr, so->src_paddr + page_size - 1ULL) ||
            ranges_overlap(so->mdata_paddr, so->mdata_paddr + SNP_METADATA_ENTRY_SIZE - 1ULL,
                           so->dst_paddr, so->dst_paddr + page_size - 1ULL))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        /* Verify that the metadata page is in METADATA state */
        if (mdata_state != SNP_PAGE_STATE_METADATA)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        }

        /* Check that the RMP.GPA of the page containing MDATA_ENTRY matches GCTX_PADDR */
        if (RMP_GET_GPA(mdata_rmp_entry.q1.f.gpa) != PADDR_GET_GPA(so->gctx_paddr))
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto end;
        }
    }

    /* Checks that the source and dest page sizes indicated by the RMP match
     * the page size param */
    if ((src_rmp_entry.q1.f.page_size != so->page_size) ||
        (dst_state != SNP_PAGE_STATE_DEFAULT && dst_rmp_entry.q1.f.page_size != so->page_size))
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto end;
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(so->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH && gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Check that the guest is activated/pending */
    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap;
    }

    /* Based off PAGE_TYPE, the page can be a source, data, or Metadata page */
    switch (so->page_type) {
    case SWAP_IO_DATA_PAGE: {
        /* Check the src and dst page states */
        if ((src_state != SNP_PAGE_STATE_PRE_SWAP && src_state != SNP_PAGE_STATE_PRE_GUEST) ||
            (dst_state != SNP_PAGE_STATE_FIRMWARE && dst_state != SNP_PAGE_STATE_DEFAULT))
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto unmap;
        }

        /* The RMP.ASID of the source page must equal the ASID of the guest */
        if (src_rmp_entry.q1.f.asid != gctx->guest.asid)
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        /* Construct an MData structure */
        mdata_mdata_page.software_data = so->software_data;
        mdata_mdata_page.mdata_entry.f.page_size = src_rmp_entry.q1.f.page_size;
        mdata_mdata_page.mdata_entry.f.valid = 1;
        mdata_mdata_page.mdata_entry.f.metadata = 0;
        mdata_mdata_page.mdata_entry.f.vmsa = 0;
        mdata_mdata_page.mdata_entry.f.gpa = src_rmp_entry.q1.f.gpa;
        mdata_mdata_page.mdata_entry.f.page_validated = src_rmp_entry.q1.f.validated;
        mdata_mdata_page.vmpl.val = src_rmp_entry.q2.val;

        break;
    }
    case SWAP_IO_METADATA_PAGE: {
        /* Check the src and dst page states */
        if ((src_state != SNP_PAGE_STATE_METADATA) ||
            (dst_state != SNP_PAGE_STATE_FIRMWARE && dst_state != SNP_PAGE_STATE_DEFAULT))
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto unmap;
        }

        /* Check that the RMP.GPA of the source page matches GCTX_PADDR */
        if (RMP_GET_GPA(src_rmp_entry.q1.f.gpa) != PADDR_GET_GPA(so->gctx_paddr))
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        /* Write the produced ciphertext into the destination page */
        mdata_mdata_page.software_data = so->software_data;
        mdata_mdata_page.mdata_entry.f.page_size = src_rmp_entry.q1.f.page_size;
        mdata_mdata_page.mdata_entry.f.valid = 1;
        mdata_mdata_page.mdata_entry.f.metadata = 1;
        mdata_mdata_page.mdata_entry.f.vmsa = 0;
        mdata_mdata_page.mdata_entry.f.gpa = PADDR_INVALID; /* truncated to 52 bits */
        mdata_mdata_page.mdata_entry.f.page_validated = 0;
        mdata_mdata_page.vmpl.val = 0;

        break;
    }
    case SWAP_IO_VMSA_PAGE: {
        /* Check the src and dst page states */
        if ((src_state != SNP_PAGE_STATE_PRE_SWAP && src_state != SNP_PAGE_STATE_PRE_GUEST) ||
            (dst_state != SNP_PAGE_STATE_FIRMWARE && dst_state != SNP_PAGE_STATE_DEFAULT))
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto unmap;
        }

        /* The RMP.ASID of the source page must equal the ASID of the guest */
        if (src_rmp_entry.q1.f.asid != gctx->guest.asid)
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        /* Write the produced ciphertext into the destination page */
        mdata_mdata_page.software_data = so->software_data;
        mdata_mdata_page.mdata_entry.f.page_size = src_rmp_entry.q1.f.page_size;
        mdata_mdata_page.mdata_entry.f.valid = 1;
        mdata_mdata_page.mdata_entry.f.metadata = 0;
        mdata_mdata_page.mdata_entry.f.vmsa = 1;
        mdata_mdata_page.mdata_entry.f.gpa = src_rmp_entry.q1.f.gpa;
        mdata_mdata_page.mdata_entry.f.page_validated = src_rmp_entry.q1.f.validated;
        mdata_mdata_page.vmpl.val = src_rmp_entry.q2.val;

        break;
    }
    default: {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto unmap;
    }
    }

    /* Check for overflow and increment the iv */
    if (gctx->guest.oek_iv_count == (UINT64_MAX-1))
    {
        status = SEV_STATUS_AEAD_OFLOW;
        goto unmap;
    }
    mdata_mdata_page.iv = gctx->guest.oek_iv_count++;   /* Increment the Guest IV */

    /* Metadata pages aren't encrypted, so change the asid we're passing in to 0 */
    if (so->page_type == SWAP_IO_METADATA_PAGE)
        asid_for_gcm = 0;
    else
        asid_for_gcm = gctx->guest.asid;

    /* Use the guest's VEK to decrypt the contents of the source page and
        use the guest's OEK to wrap the contents with Aead_Wrap() without AAD */
    /* Populate the auth_tag with the output tag of Aead encrypt */
    /* Copies in the ASID encrypted page and copies out a OEK encrypted page */
    status = aes256gcm_authenticated_encrypt_x86addr(
                        gctx->guest.oek, sizeof(gctx->guest.oek),
                        NULL, 0,  /* AAD */
                        so->src_paddr, page_size,
                        so->dst_paddr,
                        (uint8_t *)&mdata_mdata_page.iv, sizeof(mdata_mdata_page.iv),
                        mdata_mdata_page.auth_tag,
                        asid_for_gcm);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Transition the source page state */
    if (so->page_type == SWAP_IO_DATA_PAGE ||
        so->page_type == SWAP_IO_VMSA_PAGE)
    {
        src_rmp_entry.q1.f.validated = 0;  /* Pre-Guest/Pre-Swap -> Pre-Guest */
    }
    else if (so->page_type == SWAP_IO_METADATA_PAGE)
    {
        /* Clear the firmware state hack */
        src_rmp_entry.q1.f.gpa = 0;        /* Metadata -> Firmware */
        src_rmp_entry.q1.f.vmsa = 0;
    }

    /* Write all our RMP changes back to x86 memory */
    status = rmp_entry_write(src_rmp_paddr, &src_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Copy packet metadata to the output buffer */
    if (so->root_mdata_en == 0)
    {
        status = mdata_entry_write(so->mdata_paddr, &mdata_mdata_page);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
    }
    else
    {
        memcpy(&gctx->root_md_entry, &mdata_mdata_page, sizeof(snp_metadata_page_t));
    }

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_swap_in(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_swap_in_t *si = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t src_rmp_paddr = 0;
    uint64_t dst_rmp_paddr = 0;
    uint64_t mdata_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t src_rmp_entry;
    rmp_entry_t dst_rmp_entry;
    rmp_entry_t mdata_rmp_entry;
    snp_metadata_page_t mdata_mdata_page;
    snp_page_state_t gctx_state;
    snp_page_state_t src_state;
    snp_page_state_t dst_state;
    snp_page_state_t mdata_state;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;
    uint8_t page_type = 0;
    uint32_t page_size = 0;
    uint32_t asid_for_gcm = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    si = &cmd->snp_swap_in;
    page_size = (si->page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;

    /* Verify the reserved fields are zero */
    if ((si->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (si->src_paddr & SNP_ADDR_RESERVED_MASK) ||
        (si->dst_paddr & SNP_ADDR_RESERVED_MASK) || (si->reserved != 0) || (si->reserved2 != 0))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Get RMP address/state of the guest context/src/dst pages */
    status = rmp_get_addr_entry_state(si->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(si->src_paddr, &src_rmp_paddr, &src_rmp_entry, &src_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(si->dst_paddr, &dst_rmp_paddr, &dst_rmp_entry, &dst_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify that guest context page is in CONTEXT state */
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Get RMP address/state of the metadata page */
    if (si->root_mdata_en == 0)
    {
        status = rmp_get_addr_entry_state(si->mdata_paddr, &mdata_rmp_paddr, &mdata_rmp_entry, &mdata_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Check that MDATA_PADDR is a valid sPA and is aligned to the size of
        an MDATA structure (64B) */
        if (si->mdata_paddr % SNP_METADATA_ENTRY_SIZE)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        /* The MDATA_PADDR sPA must not overlap the source or destination pages */
        if (ranges_overlap(si->mdata_paddr, si->mdata_paddr + SNP_METADATA_ENTRY_SIZE - 1ULL,
                           si->src_paddr, si->src_paddr + page_size - 1ULL) ||
            ranges_overlap(si->mdata_paddr, si->mdata_paddr + SNP_METADATA_ENTRY_SIZE - 1ULL,
                           si->dst_paddr, si->dst_paddr + page_size - 1ULL))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        /* Verify that the metadata page is in METADATA state */
        if (mdata_state != SNP_PAGE_STATE_METADATA)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        }

        /* Check that the RMP.GPA of the page containing MDATA_ENTRY matches GCTX_PADDR */
        if (RMP_GET_GPA(mdata_rmp_entry.q1.f.gpa) != PADDR_GET_GPA(si->gctx_paddr))
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto end;
        }
    }

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(si->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH && gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Check that the guest is activated/pending */
    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap;
    }

    /*
     * If ROOT_MDATA_EN is set, use the metadata entry in GCTX.RootMDEntry
     * If ROOT_MDATA_EN is clear, use the metadata entry at MDATA_PADDR
     * Needs to be after the guest checks because this uses root_md_entry
     */
    if (si->root_mdata_en == 1)
        memcpy(&mdata_mdata_page, &gctx->root_md_entry, sizeof(snp_metadata_page_t));
    else
    {
        status = mdata_entry_read(si->mdata_paddr, &mdata_mdata_page); /* Do x86 copy to pull metadata entry into readable memory */
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;
    }

    /* Determine command operation based off metadata entry */
    if (mdata_mdata_page.mdata_entry.f.metadata == 0 && mdata_mdata_page.mdata_entry.f.vmsa == 0)
    {
        page_type = SWAP_IO_DATA_PAGE;
    }
    else if (mdata_mdata_page.mdata_entry.f.metadata == 1 && mdata_mdata_page.mdata_entry.f.vmsa == 0)
    {
        page_type = SWAP_IO_METADATA_PAGE;
    }
    else if (mdata_mdata_page.mdata_entry.f.metadata == 0 && mdata_mdata_page.mdata_entry.f.vmsa == 1)
    {
        page_type = SWAP_IO_VMSA_PAGE;
    }
    else
    {
        status = SEV_STATUS_INVALID_MDATA_ENTRY;
        goto unmap;
    }

    /* Check that the page type indicated by the metadata entry matches PAGE_TYPE
       and that that the VALID bit in the metadata entry is set */
    if ((page_type != si->page_type) || (mdata_mdata_page.mdata_entry.f.valid != 1))
    {
        status = SEV_STATUS_INVALID_MDATA_ENTRY;
        goto unmap;
    }

    /* Checks that the source and dest page sizes indicated by the RMP match
       the page size param */
    if ((src_state != SNP_PAGE_STATE_DEFAULT && src_rmp_entry.q1.f.page_size != si->page_size) ||
        (dst_rmp_entry.q1.f.page_size != si->page_size) ||
        (mdata_mdata_page.mdata_entry.f.page_size != si->page_size))
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto unmap;
    }

    /* Based off PAGE_TYPE, the page can be a source, data, or Metadata page */
    switch (page_type) {
    case SWAP_IO_DATA_PAGE: {
        /* Check the src page state */
        if (si->swap_in_place == 0)
        {
            if (dst_state != SNP_PAGE_STATE_PRE_GUEST)
            {
                status = SEV_STATUS_INVALID_PAGE_STATE;
                goto unmap;
            }
        }
        else if (si->swap_in_place == 1)
        {
            if (si->src_paddr != si->dst_paddr)
            {
                status = SEV_STATUS_INVALID_ADDRESS;
                goto unmap;
            }
            if (src_state != SNP_PAGE_STATE_PRE_GUEST || dst_state != SNP_PAGE_STATE_PRE_GUEST) /* Same page */
            {
                status = SEV_STATUS_INVALID_PAGE_STATE;
                goto unmap;
            }
        }

        /* The RMP.ASID of the dest page must equal the ASID of the guest */
        if (dst_rmp_entry.q1.f.asid != gctx->guest.asid)
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        break;
    }
    case SWAP_IO_METADATA_PAGE: {
        /* SWAP_IN_PLACE must be 0h */
        if (si->swap_in_place != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto unmap;
        }

        /* Check the page states */
        if (dst_state != SNP_PAGE_STATE_FIRMWARE)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto unmap;
        }

        break;
    }
    case SWAP_IO_VMSA_PAGE: {
        /* SWAP_IN_PLACE must be 0h */
        if (si->swap_in_place != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto unmap;
        }

        /* PAGE_SIZE must indicate a 4KB page size */
        if (si->page_size != DRAM_PAGE_SIZE_4K)
        {
            status = SEV_STATUS_INVALID_PAGE_SIZE;
            goto unmap;
        }

        /* Check the page states */
        if (dst_state != SNP_PAGE_STATE_PRE_GUEST)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto unmap;
        }

        /* The RMP.ASID of the dest page must equal the ASID of the guest */
        if (dst_rmp_entry.q1.f.asid != gctx->guest.asid)
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        break;
    }
    default: {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto unmap;
    }
    }

    /* Metadata pages aren't encrypted, so change the asid we're passing in to 0 */
    if (si->page_type == SWAP_IO_METADATA_PAGE)
        asid_for_gcm = 0;
    else
        asid_for_gcm = gctx->guest.asid;

    /* Enable rd_sz_wbinvd around copy_from_x86. Reading in unencrypted and writing out encrypted */
    status = set_misc_read_sized_wrbkinvd(true);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* (CSF-698) Dummy read for dst_paddr is performed inside aes256gcm_authenticated_decrypt_x86addr */

    /* Decrypt using Offline Encryption Key */
    /* Check that the produced auth tag is equal to AUTH_TAG in the metadata entry */
    /* Copies in the OEK encrypted page and copies out a ASID encrypted page */
    status = aes256gcm_authenticated_decrypt_x86addr(
                        gctx->guest.oek, sizeof(gctx->guest.oek),
                        NULL, 0,  /* AAD */
                        si->src_paddr, page_size,
                        si->dst_paddr,
                        (uint8_t *)&mdata_mdata_page.iv, sizeof(mdata_mdata_page.iv),
                        mdata_mdata_page.auth_tag,
                        asid_for_gcm);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap1;

    /* Clear the VALID flag in the metadata entry */
    mdata_mdata_page.mdata_entry.f.valid = 0;

    if (page_type == SWAP_IO_DATA_PAGE)
    {
        /*
         * Update the RMP of the destination page as follows:
         *   Sets the RMP.GPA to GPA in the metadata entry
         *   Sets the RMP.VMSA to 0
         *   Sets the VMPL permission masks in the RMP entry
         *     to the VMPL permission masks in the metadata entry
         */
        dst_rmp_entry.q1.f.gpa = mdata_mdata_page.mdata_entry.f.gpa;
        dst_rmp_entry.q1.f.vmsa = 0;
        dst_rmp_entry.q2.val = mdata_mdata_page.vmpl.val;

        /* If page_validated in the metadata entry is 1, transition dest page into a Pre-Swap page */
        if (mdata_mdata_page.mdata_entry.f.page_validated == 1)
            dst_rmp_entry.q1.f.validated = 1;  /* Pre-Guest -> Pre-Swap */
    }
    else if (page_type == SWAP_IO_METADATA_PAGE)
    {
        /* Transition dest page into a Metadata page and apply the GPA state hack */
        dst_rmp_entry.q1.f.gpa = PADDR_TO_GPA_FIELD(si->gctx_paddr, RMP_GPA_STATE_METADATA);   /* Firmware -> Metadata */
    }
    else if (page_type == SWAP_IO_VMSA_PAGE)
    {
        /*
         * Update the RMP of the destination page as follows:
         *   Sets the RMP.GPA to GPA in the metadata entry
         *   Sets the RMP.VMSA to 1
         *   Sets the VMPL permission masks in the RMP entry
         *     to the VMPL permission masks in the metadata entry
         */
        dst_rmp_entry.q1.f.gpa = mdata_mdata_page.mdata_entry.f.gpa;
        dst_rmp_entry.q1.f.vmsa = 1;
        dst_rmp_entry.q2.val = mdata_mdata_page.vmpl.val;

        /* If SecureTsc in the SEV_FEATURES field of the VMSA is 1,
            set the guest_tsc_scale and guest_tsc_offset in the vmsa */
        if (VMSA_SEV_FEATURES_SECURE_TSC_ENABLED(gpSevScratchBuf))
        {
            status = copy_from_x86_encrypted(si->dst_paddr, gpSevScratchBuf, PAGE_SIZE_4K, asid_for_gcm);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_SCALE) = calc_tsc_scale(gctx->desired_tsc_freq, REF_CLK_GENOA);
            *(uint64_t *)((uint8_t *)gpSevScratchBuf + VMSA_GUEST_TSC_OFFSET) = gctx->psp_tsc_offset;

            status = copy_to_x86_encrypted(si->dst_paddr, gpSevScratchBuf, PAGE_SIZE_4K, asid_for_gcm);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }

        /* If page_validated in the metadata entry is 1, transition the dest page into a Pre-Swap page */
        if (mdata_mdata_page.mdata_entry.f.page_validated == 1)
            dst_rmp_entry.q1.f.validated = 1;  /* Pre-Guest -> Pre-Swap */
    }

    /* Write all our RMP changes back to x86 memory */
    status = rmp_entry_write(dst_rmp_paddr, &dst_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap1;

    /* Write the metadata entry changes to memory */
    if (si->root_mdata_en == 0)
    {
        status = mdata_entry_write(si->mdata_paddr, &mdata_mdata_page);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap1;
    }
    else
    {
        memcpy(&gctx->root_md_entry, &mdata_mdata_page, sizeof(snp_metadata_page_t));
    }

unmap1:
    /* Clear the rd_sz_wbinvd */
    set_misc_read_sized_wrbkinvd(false);

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_page_move(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_page_move_t *pm = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t src_rmp_paddr = 0;
    uint64_t dst_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t src_rmp_entry;
    rmp_entry_t dst_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t src_state;
    snp_page_state_t dst_state;
    size_t move_page_size = 0;
    void *gctx_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    pm = &cmd->snp_page_move;

    /* Verify the reserved fields are zero */
    if ((pm->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (pm->src_paddr & SNP_ADDR_RESERVED_MASK) ||
        (pm->dst_paddr & SNP_ADDR_RESERVED_MASK) || (pm->reserved != 0) || (pm->reserved2 != 0))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Get RMP entries for gctx/src/dst */
    status = rmp_get_addr_entry_state(pm->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(pm->src_paddr, &src_rmp_paddr, &src_rmp_entry, &src_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(pm->dst_paddr, &dst_rmp_paddr, &dst_rmp_entry, &dst_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify the gctx page is in the correct state */
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }

    /* Verify that the pages are the same size and match the input param */
    if (src_rmp_entry.q1.f.page_size != pm->page_size ||
        dst_rmp_entry.q1.f.page_size != pm->page_size )
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto end;
    }
    move_page_size = (dst_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;

    /* Map the guest context page so we can read/write */
    status = sev_hal_map_guest_context(pm->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH && gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap;
    }

    /* Check that the guest is activated */
    if (guest_is_inactive(&gctx->guest))
    {
        status = SEV_STATUS_INACTIVE;
        goto unmap;
    }

    /* src/dst pages can either be Guest or Metadata pages */
    if ((src_state == SNP_PAGE_STATE_PRE_SWAP || src_state == SNP_PAGE_STATE_PRE_GUEST) &&
        (dst_state == SNP_PAGE_STATE_PRE_GUEST))        /* Guest page */
    {
        /* Check that RMP.ASID of src and dst pages are equal to ASID of the guest */
        if (src_rmp_entry.q1.f.asid != (gctx->guest.asid) ||
            dst_rmp_entry.q1.f.asid != (gctx->guest.asid))
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        /* Copy the contents of src into dst page data */
        status = copy_to_x86_encrypted_from_x86_encrypted(pm->dst_paddr, pm->src_paddr,
                                                          move_page_size, gctx->guest.asid);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        /* Set the RMP.GPA and RMP.VMSA fields of the dst page to match the source page */
        dst_rmp_entry.q1.f.gpa = src_rmp_entry.q1.f.gpa;
        dst_rmp_entry.q1.f.vmsa = src_rmp_entry.q1.f.vmsa;

        /* Set the dst VMPL permission masks equal to the src VMPL permission masks */
        dst_rmp_entry.q2.val = src_rmp_entry.q2.val;

        /* If src page is Pre-Guest, turn dst page into Guest-Invalid */
        /* If src page is Pre-Swap, turn dst page into Guest-Valid */
        if (src_state == SNP_PAGE_STATE_PRE_GUEST)
        {
            dst_rmp_entry.q1.f.immutable = 0;      /* Pre-Guest -> Guest-Invalid */
            dst_rmp_entry.q1.f.lock = dst_rmp_entry.q1.f.immutable;
        }
        else if (src_state == SNP_PAGE_STATE_PRE_SWAP)
        {
            dst_rmp_entry.q1.f.validated = 1;      /* Pre-Guest -> Guest-Valid */
            dst_rmp_entry.q1.f.immutable = 0;
            dst_rmp_entry.q1.f.lock = dst_rmp_entry.q1.f.immutable;
        }
        /* Transition the src page into a Guest-Invalid page */
        src_rmp_entry.q1.f.validated = 0;          /* Pre-Swap/Pre-Guest -> Guest-Invalid */
        src_rmp_entry.q1.f.immutable = 0;
        src_rmp_entry.q1.f.lock = src_rmp_entry.q1.f.immutable;
    }
    else if (src_state == SNP_PAGE_STATE_METADATA && dst_state == SNP_PAGE_STATE_FIRMWARE)  /* Metadata Page */
    {
        /* Check that RMP.GPA of src is equal to sPA of Guest */
        if (RMP_GET_GPA(src_rmp_entry.q1.f.gpa) != PADDR_GET_GPA(pm->gctx_paddr))
        {
            status = SEV_STATUS_INVALID_PAGE_OWNER;
            goto unmap;
        }

        /* Copy the plaintext data of src into dst */
        if (!ranges_overlap(pm->src_paddr, pm->src_paddr + PAGE_SIZE_4K - 1ULL,  /* Skip copy if addrs the same */
                            pm->dst_paddr, pm->dst_paddr + PAGE_SIZE_4K - 1ULL))
        {
            status = copy_to_x86_from_x86(pm->dst_paddr, pm->src_paddr, move_page_size);
            if (status != SEV_STATUS_SUCCESS)
                goto unmap;
        }

        /* Transition the dst page into a Metadata page by setting the RMP.GPA
         * to the sPA of the guest context and apply the GPA state hack */
        dst_rmp_entry.q1.f.gpa = PADDR_TO_GPA_FIELD(pm->gctx_paddr, RMP_GPA_STATE_METADATA);   /* Firmware -> Metadata */

        /* Transition the src page into a Firmware page and clear the GPA state hack */
        src_rmp_entry.q1.f.gpa = 0;                /* Metadata -> Firmware */
        src_rmp_entry.q1.f.vmsa = 0;
    }
    else
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto unmap;
    }

    /* Write all our RMP changes back to x86 memory */
    status = rmp_entry_write(src_rmp_paddr, &src_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;
    status = rmp_entry_write(dst_rmp_paddr, &dst_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

unmap:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_guest_context(gctx_x86_buffer, PAGE_SIZE_4K);

end:
    return status;
}

sev_status_t snp_mcmd_md_init(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_md_init_t *mi = NULL;
    uint64_t gctx_rmp_paddr = 0;
    uint64_t page_rmp_paddr = 0;
    rmp_entry_t gctx_rmp_entry;
    rmp_entry_t page_rmp_entry;
    snp_page_state_t gctx_state;
    snp_page_state_t page_state;
    size_t page_size = 0;
    void *gctx_x86_buffer = NULL;
    void *page_x86_buffer = NULL;
    guest_context_page_t *gctx = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    mi = &cmd->snp_md_init;

    /* Verify the reserved fields are zero */
    if ((mi->gctx_paddr & SNP_ADDR_RESERVED_MASK) || (mi->page_paddr & SNP_ADDR_RESERVED_MASK))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify that the Guest context page is in the CONTEXT state and page is in FIRMWARE state */
    status = rmp_get_addr_entry_state(mi->gctx_paddr, &gctx_rmp_paddr, &gctx_rmp_entry, &gctx_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = rmp_get_addr_entry_state(mi->page_paddr, &page_rmp_paddr, &page_rmp_entry, &page_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    if (gctx_state != SNP_PAGE_STATE_CONTEXT)
    {
        status = SEV_STATUS_INVALID_GUEST;
        goto end;
    }
    if (page_state != SNP_PAGE_STATE_FIRMWARE)
    {
        status = SEV_STATUS_INVALID_PAGE_STATE;
        goto end;
    }

    /* Map the guest context page so we can read */
    status = sev_hal_map_guest_context(mi->gctx_paddr, &gctx_x86_buffer, PAGE_SIZE_4K);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    gctx = (guest_context_page_t *)gctx_x86_buffer;

    /* Check the guest state. Can either be in Launch or in Running */
    if (gctx->guest.snp_state != SNP_GUEST_STATE_LAUNCH &&
        gctx->guest.snp_state != SNP_GUEST_STATE_RUNNING)
    {
        status = SEV_STATUS_INVALID_GUEST_STATE;
        goto unmap_gctx;
    }

    /* Map the page so we can write */
    page_size = (page_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;
    status = sev_hal_map_memory_ccp(mi->page_paddr, &page_x86_buffer, page_size);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_gctx;

    /* The firmware zeroes the page */
    memset(page_x86_buffer, 0, page_size);

    /* Transition the page to Metadata page by setting the RMP.GPA of the page
     * to the sPA of the guest context and apply the GPA state hack */
    page_rmp_entry.q1.f.gpa = PADDR_TO_GPA_FIELD(mi->gctx_paddr, RMP_GPA_STATE_METADATA);  /* Firmware -> Metadata */

    /* Write all our RMP changes back to x86 memory */
    status = rmp_entry_write(page_rmp_paddr, &page_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap_page;

unmap_page:
    /* Unmap the page mem */
    sev_hal_unmap_memory(page_x86_buffer);

unmap_gctx:
    /* Unmap the gctx_page mem */
    sev_hal_unmap_memory(gctx_x86_buffer);

end:
    return status;
}

sev_status_t snp_mcmd_page_set_state(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_page_set_state_t *ps = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    ps = &cmd->snp_page_set_state;

    /* Make sure length param matches expected buffer length */
    if (ps->length != sizeof(snp_mcmd_page_set_state_t))
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* Make sure reserved bits are 0 */
    if (ps->reserved != 0 || ps->list_paddr & SNP_ADDR_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Check and transition the pages from FIRMWARE to HV_FIXED */
    status = page_set_hv_fixed(ps->list_paddr);

end:
    return status;
}

sev_status_t snp_mcmd_page_reclaim(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_page_reclaim_t *pr = NULL;
    uint64_t page_rmp_paddr = 0;
    uint64_t page_addr = 0;
    uint32_t page_size = 0;
    rmp_entry_t page_rmp_entry;
    snp_page_state_t page_state;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    pr = &cmd->snp_page_reclaim;

    /* Make sure reserved bits are 0 */
    if (pr->page_paddr_size & SNP_ADDR_PAGE_RECLAIM_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    page_addr = SNP_PAGE_ADDR(pr->page_paddr_size);
    page_size = SNP_PAGE_SIZE(pr->page_paddr_size);

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* Verify the page is valid and not an active TMR, etc */
    status = validate_address_range(page_addr, (page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify that the provided page is in Metadata, Firmware, Pre-Guest, or Pre-Swap */
    status = rmp_get_addr_entry_state(page_addr, &page_rmp_paddr, &page_rmp_entry, &page_state);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Check that page_size equals RMP.PageSize */
    if (page_rmp_entry.q1.f.page_size != page_size)
    {
        status = SEV_STATUS_INVALID_PAGE_SIZE;
        goto end;
    }

    /* If the page size is 2M, then page_paddr must be 2M aligned */
    if (page_rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_2M)
    {
        if (!IS_ALIGNED_TO_2MB(page_addr))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }
    }

    /* Return success if the immutable bit is already 0 */
    if (page_rmp_entry.q1.f.immutable == 0)
    {
        status = SEV_STATUS_SUCCESS;
        goto end;
    }

    switch (page_state)
    {
        case SNP_PAGE_STATE_METADATA:       /* Metadata to Reclaim */
        {
            page_rmp_entry.q1.f.immutable = 0;
            page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;
            page_rmp_entry.q1.f.gpa = RMP_GET_GPA(page_rmp_entry.q1.f.gpa); /* Clear the firmware state hack */
            break;
        }
        case SNP_PAGE_STATE_FIRMWARE:       /* Firmware to Reclaim */
        {
            page_rmp_entry.q1.f.immutable = 0;
            page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;
            break;
        }
        case SNP_PAGE_STATE_PRE_GUEST:      /* Pre-Guest to Guest-Invalid */
        {
            page_rmp_entry.q1.f.immutable = 0;
            page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;
            break;
        }
        case SNP_PAGE_STATE_PRE_SWAP:       /* Pre-Swap to Guest-Valid */
        {
            page_rmp_entry.q1.f.immutable = 0;
            page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;
            break;
        }
        default:
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        }
    }

    /* Write all our RMP changes back to x86 memory */
    status = rmp_entry_write(page_rmp_paddr, &page_rmp_entry);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

sev_status_t snp_mcmd_page_unsmash(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_page_unsmash_t *pu = NULL;
    uint64_t page_rmp_paddr;
    uint64_t original_page_rmp_paddr;
    volatile rmp_entry_t *rmp_entry_x86_buffer = NULL;
    void *original_rmp_entry_x86_buffer = NULL;
    snp_page_state_t page_state;
    snp_page_state_t prev_page_state = SNP_PAGE_STATE_INVALID;
    uint64_t prev_gpa = 0;
    uint32_t prev_asid = 0;
    uint64_t prev_vmpl = 0;
    const uint32_t num_entries = PAGE_SIZE_2M/PAGE_SIZE_4K;   /* 512 */
    const uint32_t entry_size = sizeof(rmp_entry_t);          /* 16 */

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    pu = &cmd->snp_page_unsmash;

    /* Make sure reserved bits are 0 */
    if (pu->page_paddr & SNP_ADDR_PAGE_RECLAIM_RESERVED_MASK)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Verify that page_paddr is 2MB aligned */
    /* Note: if this requirement is removed, we must change the code to check for 64MB crossing */
    if (!IS_ALIGNED_TO_2MB(pu->page_paddr))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Check the Platform state */
    if (gpDram->perm.snp_state != SNP_STATE_INIT)
    {
        status = SEV_STATUS_INVALID_PLATFORM_STATE;
        goto end;
    }

    /* RMP entries are in x86 memory too, so map to the first RMP entry
       Will catch a DEFAULT page as starting address */
    status = get_rmp_paddr(pu->page_paddr, &page_rmp_paddr);    /* Get RMP addr of first page */
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    original_page_rmp_paddr = page_rmp_paddr;

    /* Make sure all pages are within the RMP and do not overlap the RMP's self entries */
    if (ranges_overlap(pu->page_paddr, pu->page_paddr + (PAGE_SIZE_2M-1ULL),
                       gpDram->perm.rmp_base, gpDram->perm.rmp_end))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    skip_rmp_addr_check(true);
    status = sev_hal_map_memory_ccp(page_rmp_paddr, (void *)&original_rmp_entry_x86_buffer, entry_size*num_entries); /* Read RMP entries */
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    rmp_entry_x86_buffer = (rmp_entry_t *)original_rmp_entry_x86_buffer;
    /* You need to check that each Immutable bit is set before writing to ANY
     *  RMP entries to prevent time of check/time of use attacks */
    /* For each 4k page in the 2M page */
    for (uint32_t i = 0; i < num_entries; i++)
    {
        page_state = rmp_entry_get_state((rmp_entry_t *)rmp_entry_x86_buffer);

        /* Checks for all pages that don't depend on other pages */
        if (rmp_entry_x86_buffer->q1.f.page_size != DRAM_PAGE_SIZE_4K || /* 1. Each page has RMP.PageSize=4k page */
            rmp_entry_x86_buffer->q1.f.immutable != 1 ||                 /* 2. Each page has RMP.Immutable=1 */
            rmp_entry_x86_buffer->q1.f.vmsa != 0 ||                      /* 3. Each page has RMP.VMSA=0 */
            rmp_entry_x86_buffer->q1.f.asid == 0)                        /* 6. ASID may not be 0 */
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto unmap;
        }

        if (i == 0)
        {
            prev_page_state = page_state;
            prev_gpa = RMP_GPA_TO_PADDR(rmp_entry_x86_buffer->q1.f.gpa);
            prev_asid = rmp_entry_x86_buffer->q1.f.asid;
            prev_vmpl = ((rmp_entry_t *)rmp_entry_x86_buffer)->q2.val;

            if (!IS_ALIGNED_TO_2MB(RMP_GPA_TO_PADDR(rmp_entry_x86_buffer->q1.f.gpa)))
            {
                status = SEV_STATUS_INVALID_PAGE_STATE;
                goto unmap;
            }
        }
        else
        {
            /* Checks that depend on other pages */
            if (page_state != prev_page_state ||                   /* 4. All pages are in the same state */
                rmp_entry_x86_buffer->q1.f.asid != prev_asid ||    /* 6. All pages have RMP.ASID set identically */
                rmp_entry_x86_buffer->q1.f.gpa != prev_gpa+1)      /* 7. The guest physical pages are 2MB and consecutive */
            {
                status = SEV_STATUS_INVALID_PAGE_STATE;
                goto unmap;
            }

            if (((rmp_entry_t *)rmp_entry_x86_buffer)->q2.val != prev_vmpl) /* 5. All pages have the same VMPL permissions */
            {
                status = SEV_STATUS_INVALID_PAGE_STATE;
                goto unmap;
            }
        }

        prev_page_state = page_state;
        prev_gpa = rmp_entry_x86_buffer->q1.f.gpa; /* The PAGE_SIZE_4K 'consecutive' is the 1 increment << 12 */

        /* Check if the RMP entry has crossed over 64 MB */
        /* 8. The system physical pages are 2MB in size, 2 MB aligned, and consecutive */
        if ((page_rmp_paddr & X86_64MB_MASK) != ((page_rmp_paddr + entry_size) & X86_64MB_MASK))
        {
            /* Crossing 64MB has occurred */
            sev_hal_unmap_memory(original_rmp_entry_x86_buffer);
            page_rmp_paddr += entry_size;
            status = sev_hal_map_memory_ccp(page_rmp_paddr, (void *)&original_rmp_entry_x86_buffer, (num_entries - i)*entry_size); /* Read RMP entries */
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            rmp_entry_x86_buffer = (rmp_entry_t *)original_rmp_entry_x86_buffer;
        }
        else
        {
            rmp_entry_x86_buffer = (rmp_entry_t *)((uint32_t)rmp_entry_x86_buffer + entry_size); /* Increase the pointer's addr */
            page_rmp_paddr += entry_size;
        }
    }

    sev_hal_unmap_memory((void *)original_rmp_entry_x86_buffer);

    /* Reset the pointer to original value */
    page_rmp_paddr = original_page_rmp_paddr;
    status = sev_hal_map_memory_ccp(page_rmp_paddr, (void *)&original_rmp_entry_x86_buffer,
                                    sizeof(rmp_entry_t)*(num_entries)); /* Read RMP entries */
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;
    rmp_entry_x86_buffer = (rmp_entry_t *)original_rmp_entry_x86_buffer;

    /* Turn the 4k pages into one 2M page */
    /*  First page - page_size set to 2M, reset subpage count */
    /*  Subpages changes:
           assigned = 1, asid = 1, immutable = lock = 0 */
    for (uint32_t i = 0; i < num_entries; i++)
    {
        if (i == 0)
        {
            /* First page */
            rmp_entry_x86_buffer->q1.f.page_size = DRAM_PAGE_SIZE_2M;
            rmp_entry_x86_buffer->q1.f.subpage_count = 0;
        }
        else
        {
            rmp_entry_x86_buffer->q1.f.assigned = 1;
            rmp_entry_x86_buffer->q1.f.asid = 0;
            rmp_entry_x86_buffer->q1.f.immutable = 0;
            rmp_entry_x86_buffer->q1.f.lock = rmp_entry_x86_buffer->q1.f.immutable;
        }

        /* Check if the RMP entry has crossed over 64 MB */
        if ((page_rmp_paddr & X86_64MB_MASK) != ((page_rmp_paddr + entry_size) & X86_64MB_MASK))
        {
            /* Crossing 64MB has occurred */
            sev_hal_unmap_memory(original_rmp_entry_x86_buffer);
            page_rmp_paddr += entry_size;
            status = sev_hal_map_memory_ccp(page_rmp_paddr, (void *)&original_rmp_entry_x86_buffer, (entry_size - i)*num_entries); /* Read RMP entries */
            if (status != SEV_STATUS_SUCCESS)
            goto end;

            rmp_entry_x86_buffer = (rmp_entry_t *)original_rmp_entry_x86_buffer;
        }
        else
        {
            rmp_entry_x86_buffer = (rmp_entry_t *)((uint32_t)rmp_entry_x86_buffer + entry_size); /* Increase the pointer's addr */
            page_rmp_paddr += entry_size;
        }
    }

unmap:
    /* Unmap the rmp_entry mem */
    sev_hal_unmap_memory((void *)original_rmp_entry_x86_buffer);

end:
    skip_rmp_addr_check(false);
    return status;
}

sev_status_t snp_mcmd_config(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_config_t *cf = NULL;
    snp_tcb_version_t requested_tcb;
    snp_tcb_version_t current_tcb;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    cf = &cmd->snp_config;
    requested_tcb = *(snp_tcb_version_t *)&cf->reported_tcb;

    /* Verify the reserved fields are zero */
    if (cf->reserved != 0 || !is_empty(cf->reserved2, sizeof(cf->reserved2)))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Calculate the current tcb version using the latest uCode SVN */
    get_committed_tcb(&current_tcb);

    if (requested_tcb.val == 0)
        requested_tcb.val = current_tcb.val;

    /* Check that the REPORTED_TCB parameter is less than or equal to
       the installed TCB version */
    else if (tcb_compare_versions(&requested_tcb, &current_tcb) > 0)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Derive a new vcek signing key using the reported_tcb */
    status = vcek_hash_derive(gpDram->perm.snp_identity.vcek_hash, DIGEST_SHA384_SIZE_BYTES, &requested_tcb);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = vcek_derive(&gpDram->perm.snp_identity);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Set the global variable */
    gPersistent.config_tcb.val = requested_tcb.val;
    gpDram->perm.mask_chip_id = cf->mask_chip_id;
    gpDram->perm.mask_chip_key = cf->mask_chip_key;

end:
    return status;
}

sev_status_t snp_mcmd_download_firmware_ex(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_download_firmware_ex_t *dlfw = NULL;
    uint64_t x86_addr = 0;
    uint32_t size = 0;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    dlfw = &cmd->snp_download_firmware_ex;
    x86_addr = dlfw->fw_paddr;
    size = dlfw->fw_len;

    /* SEV platform state has to be UNINIT */
    if (sev->sev.state != SEV_STATE_UNINIT)
        return SEV_STATUS_INVALID_PLATFORM_STATE;

    /* Verify the reserved fields are zero */
    if (dlfw->reserved != 0 || dlfw->reserved2 != 0)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Make sure fw_paddr is 32B aligned */
    if (!IS_ALIGNED_TO_32_BYTES(x86_addr))
        return SEV_STATUS_INVALID_ADDRESS;

    /* Save the commit flag for dlfw_continue */
    gpDram->perm.dlfw_ex_commit = dlfw->commit ? true : false;

    status = sev_hal_cache_new_image(x86_addr, size, SEV_NEWFW_LOAD_ONLY);

    /* Give the new FW a chance to 'accept' the platform state */
    if (status == SEV_STATUS_SUCCESS)
        status = ERR_SEV_DLFW_CONTINUING;

end:
    return status;
}

sev_status_t snp_mcmd_commit(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_mcmd_commit_t *co = NULL;

    if (!sev || !cmd)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    co = &cmd->snp_commit;

    /* Check the length param */
    if (co->length != sizeof(*co))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Set the committed_svn to the current_svn of the current firmware */
    /* Set the committed_version to the firmware_version of the current firmware */
    /* Following 0x42 constant should be 0, but there's a nested check
       for 0 that causes it to fail. */
    status = sev_hal_cache_new_image(0x42UL, 0, SEV_NEWFW_COMMIT_ONLY);

    /* Update the CommittedTCB, CommittedVersion */
    update_committed_versions(NULL);

end:
    return status;
}

/**
 * When doing a DLFW_EX operation, DLFW_EX in the 'current'/'old' FW first.
 * DLFW_EX will load the 'new' FW in to the Boot Loader's DRAM cache of the
 * SEV FW image using the cache_new_image BL SVC call. When that returns,
 * the DLFW_EX command in the 'old' FW will exit back to the BL, but with a
 * status that says DO NOT return status yet... Instead, load the 'new' FW
 * and invoke it's DLFW_CONTINUE command. That ends up here.
 * What this command does is poke around in the SEV/SNP data structures to
 * see if this FW can 'upgrade' the data structures from the 'old' FW form
 * to the 'new' FW form. This may involve adding new fields AT THE END of
 * old data structures. If, for some reason, this upgrade process doesn't
 * work as expected, then this command can tell the Boot Loader to roll-back
 * to the 'old' FW. The Boot Loader saved a copy of the old FW for precisely
 * this possibility.
 * To allow testing of this roll-back facility, we have the DLFW_CONTINUE
 * command handler check the x86 MSRs as it would have at SNP_INIT time.
 * One of the MSRs is modifiable after SNP_INIT... and so having the test
 * suite modify that MSR allows the test suite to verify that rollback works.
 */
sev_status_t snp_mcmd_dlfw_continue(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Real test of compatibility of data from old FW with this FW */
    if (gpDram->perm.magic != SEV_PERM_MAGIC)
    {
        status = SEV_STATUS_UPDATE_FAILED;
        goto end;
    }

    /* If doing a rollback to the committed version, don't do the MSR check */
    /* Hack corresponding to one in the test suite... MSR 0xC0011035 on P1 */
    /* PLAT-76815: Check certain MSR on P0 to avoid security issues */
    if (!(gpDram->perm.committed_api_major == SEV_API_MAJOR &&
          gpDram->perm.committed_api_minor == SEV_API_MINOR &&
          gpDram->perm.committed_build_id  == SEV_BUILD_ID))
    {
        uint32_t same = 0;
        uint64_t value = 0;

        /* C001_1035 (IBS_OP_DATA) */
        status = sev_hal_check_msr(0xC0011035, &same, &value);
        if (status != SEV_STATUS_SUCCESS || !same)
        {
            status = SEV_STATUS_UPDATE_FAILED;
            goto end;
        }
    }

end:
    if (status != SEV_STATUS_SUCCESS)
    {
        if (sev_hal_cache_new_image(0x42UL, 0, SEV_NEWFW_RESTORE_BACKUP) != SEV_STATUS_SUCCESS)
        {
            status = SEV_STATUS_HARDWARE_UNSAFE;
        }
        else
        {
            /* If the rollback was successful, report that the in-progress DLFW_EX
               failed due to something the new FW didn't like about the platform
               state. Otherwise, return ... the error? Some other error? */
            status = SEV_STATUS_UPDATE_FAILED;
        }
    }

    if (status == SEV_STATUS_SUCCESS && gpDram->perm.dlfw_ex_commit)
    {
        /* Set the committed_svn to the current_svn of the current firmware */
        /* Set the committed_version to the firmware_version of the current firmware */
        /* Following 0x42 constant should be 0, but there's a nested check
           for 0 that causes it to fail. */
        status = sev_hal_cache_new_image(0x42UL, 0, SEV_NEWFW_COMMIT_ONLY);

        /* Update the CommittedTCB, CommittedVersion */
        update_committed_versions(NULL);
    }

    return status;
}

#define RET_BAD_STATUS(x) if ((status = (x)) != 0) return status
#define RET_VAL_BAD_STATUS(x, y) if ((x) != 0) return (y)
#define VLEK_WK_KDF_LABEL "vlek-wrapping-key"
sev_status_t snp_mcmd_vlek_load(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    snp_mcmd_vlek_load_t *vlek_load = (snp_mcmd_vlek_load_t *) cmd;
    vlek_wrapped_t vlek_wrapped;
    snp_tcb_version_t reported_tcb;
    uint8_t vlek[8][PSP_HASHSTICK_LENGTH];
    uint8_t key[32];

    if (vlek_load->length != sizeof(*vlek_load) ||
        vlek_load->vlek_wrapped_version != 0 ||
        vlek_load->reserved[0] || vlek_load->reserved[1] ||
        vlek_load->reserved[2])
        return SEV_STATUS_INVALID_PARAM;

    RET_BAD_STATUS(copy_from_x86(vlek_load->vlek_wrapped_paddr, (void *)&vlek_wrapped, sizeof(vlek_wrapped)));

    get_reported_tcb(&reported_tcb);

    if (vlek_wrapped.tcb_version.val != reported_tcb.val)
        return SEV_STATUS_BAD_SVN;

    RET_BAD_STATUS(nist_kdf(key, sizeof(key),
                    gpDram->perm.snp_identity.vcek_hash, sizeof(gpDram->perm.snp_identity.vcek_hash),
                    VLEK_WK_KDF_LABEL, sizeof(VLEK_WK_KDF_LABEL) -1,
                    NULL, 0));

    RET_VAL_BAD_STATUS(aes256gcm_authenticated_decrypt(key, sizeof(key),
                                    &vlek_wrapped.tcb_version.f.boot_loader, 16, // include the reserved fields
                                    &vlek_wrapped.vlek_wrapped[0], sizeof(vlek_wrapped.vlek_wrapped),
                                    &vlek[0][0],
                                    &vlek_wrapped.iv[0], sizeof(vlek_wrapped.iv),
                                    vlek_wrapped.vlek_auth_tag),
                       SEV_STATUS_BAD_MEASUREMENT);

    memcpy(gpDram->perm.vlek, vlek, sizeof(gpDram->perm.vlek));

    key_from_hash(&gpDram->perm.vlek_key, &vlek[7][0], KEYTYPE_VLEK);

    return status;
}

sev_status_t snp_mcmd_feature_info(sev_t *sev, sev_mcmd_t *cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    snp_mcmd_feature_info_t *cmd_buf = &cmd->snp_feature_info;
    snp_feature_info_t info = {0};
    uint64_t rmp_paddr;
    rmp_entry_t rmp_entry;
    snp_page_state_t page_state;

    if (cmd_buf->length != sizeof(*cmd_buf))
        return SEV_STATUS_INVALID_PARAM;

    /* Check address validity of output address */
    if ((cmd_buf->feature_info_paddr & 0x3) ||
        (PAGE_SIZE_4K - (cmd_buf->feature_info_paddr & (PAGE_SIZE_4K -1)) < sizeof(snp_feature_info_t)))
        return SEV_STATUS_INVALID_ADDRESS;

    /* If SNP is active, verify destination page state is writeable */
    if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
    {
        RET_BAD_STATUS(rmp_get_addr_entry_state(cmd_buf->feature_info_paddr, &rmp_paddr, &rmp_entry, &page_state));

        if (page_state != SNP_PAGE_STATE_FIRMWARE && page_state != SNP_PAGE_STATE_DEFAULT)
            return SEV_STATUS_INVALID_PAGE_STATE;
    }

    switch(cmd_buf->ecx_in) {
        case 0: /* For host to use directly */
            info.eax = SEV_FEATURE_INFO_x00_EAX; /* Max sub-function index (ecx_in) supported */
            info.ebx = SEV_FEATURE_INFO_x00_EBX; /* SEV Legacy (ie, non-SNP) commands supported */
            info.ecx = SEV_FEATURE_INFO_x00_ECX; /* VLEK, X86_SNP_SHUTDOWN option of SHUTDOWN_EX supported */
            /* Fetch SMU support for X86_SNP_SHUTDOWN option... */
            if (!smu_has_set_msr())
                info.ecx &= ~SEV_FEATURE_INFO_x00_ECX_X86_SNP_SHUTDOWN;
            info.edx = SEV_FEATURE_INFO_x00_EDX; /* Reserved */
            break;
        case 1: /* Intended to see guest CPUID values from HV */
            info.eax = SEV_FEATURE_INFO_x01_EAX; /* Mask of supported guest messages (all of them) */
            info.ebx = SEV_FEATURE_INFO_x01_EBX; /* Reserved */
            info.ecx = SEV_FEATURE_INFO_x01_ECX; /* Reserved */
            info.edx = SEV_FEATURE_INFO_x01_EDX; /* Reserved */
            break;
        default:
            return SEV_STATUS_INVALID_PARAM;
    }

    RET_BAD_STATUS(copy_to_x86(cmd_buf->feature_info_paddr, (void *)&info, sizeof(info)));
    return status;
}
