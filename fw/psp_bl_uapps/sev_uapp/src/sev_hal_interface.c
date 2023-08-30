// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apicid.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_hal_interface.h"
#include "core.h"
#include "x86_copy.h"

/**
 * http://twiki.amd.com/twiki/bin/viewauth/PSArch/TrustedMemoryAccess
 * CPU TMR Allocation: Register Offset Section.
 *
 * Note: If you are writing (SEV_ES_TMR_BASE), then you have to write to every thread
 *       If you are reading, then you can just read per-core except for VM_HSAVE_PA,
 *       which is per thread
 */
#define CPU_TMR_RMP_BASE_ADDR_OFFSET       (0x0)
#define CPU_TMR_RMP_END_ADDR_OFFSET        (0x8)
#define CPU_TMR_WBINVD_DONE_T0_OFFSET      (0x10)
#define CPU_TMR_WBINVD_DONE_T1_OFFSET      (0x11)
#define CPU_TMR_WBNOINVD_DONE_T0_OFFSET    (0x12)
#define CPU_TMR_WBNOINVD_DONE_T1_OFFSET    (0x13)
#define CPU_TMR_SME_EN_OFFSET              (0x14)
#define CPU_TMR_SNP_EN_OFFSET              (0x15)
#define CPU_TMR_VMPL_EN_OFFSET             (0x16)
#define CPU_TMR_SMKE_EN_OFFSET             (0x17)
#define CPU_TMR_UCODE_PATCH_LEVEL_OFFSET   (0x18)
#define CPU_TMR_VM_HSAVE_PA_OFFSET         (0x20) /* 8 bytes */
#define CPU_TMR_SEV_ES_TMR_BASE            (0x28) /* 8 bytes */
#define CPU_TMR_INVALID_ASID0_OFFSET       (0x40)

#define CPU_TMR_THREAD_OFFSET              (4096)

/**
 * Bit offsets from the byte offsets above
 */
#define CPU_TMR_WBINVD_DONE_BIT     (0)
#define CPU_TMR_WBINVD_DONE_FLAG    (1ul << (CPU_TMR_WBINVD_DONE_BIT))

#define CPU_TMR_SME_EN_BIT   (0)
#define CPU_TMR_SME_EN_FLAG  (1ul << (CPU_TMR_SME_EN_BIT))

#define CPU_TMR_SNP_EN_BIT   (0)
#define CPU_TMR_SNP_EN_FLAG  (1ul << (CPU_TMR_SNP_EN_BIT))

#define CPU_TMR_VMPL_EN_BIT  (0)
#define CPU_TMR_VMPL_EN_FLAG (1ul << (CPU_TMR_VMPL_EN_BIT))

#define CPU_TMR_SMKE_EN_BIT  (0)
#define CPU_TMR_SMKE_EN_FLAG (1ul << (CPU_TMR_SMKE_EN_BIT))

/**
 * SMT Enabled  => 8 Cores per CCD => 16 (0 to 15) threads.
 * SMT Disabled => 8 Cores per CCD => 8  (0 to 7) threads.
 */
#define SMT_EN_CCD_INVALID_MASK    (0xFFFF)
#define SMT_DIS_CCD_INVALID_MASK   (0xFF)

bool is_core_enabled(uint32_t die, uint32_t ccd, uint32_t complex, uint32_t coreid)
{
    /* When a core corresponding to the second complex is passed in, the core present
     * bit mask for that particular complex should be checked. It is a 16 bit mask,
     * the higher order bits correspond to the 2nd complex when applicable.
    */
    uint16_t core_present = 0;

    if (die >= gTotalDieNum || ccd >= MAX_CCDS || coreid >= MAX_NUM_CORES_PER_CCD_RSDN)
        return false;

    core_present = gPersistent.socket_info[die].core_present_in_ccd_bit_mask[ccd];

    if ((complex == 1) && (coreid < MAX_NUM_CORES_PER_CCX))
        coreid = coreid + MAX_NUM_CORES_PER_CCX;

    return (core_present & (1 << coreid));
}

uint32_t asid_to_reg_mask(uint32_t asid, uint32_t *reg)
{
    uint32_t mask_bit = 0;

    /*
     * ASID1 is bit 0 on the first register and ASID32 is on bit31 on the first
     * register, etc.
     *
     * We need to reduce the asid by one to map to the register.
     */

    if (!reg)
        return 0;

    asid = asid - 1;
    *reg = asid / INVALID_ASID_BITS_PER_REG;
    mask_bit = asid - (*reg * INVALID_ASID_BITS_PER_REG);
    return 1ul << mask_bit;
}

static uint64_t invalid_asid_address(uint32_t apic_id, uint32_t asid)
{
    uint64_t tmr_base = 0, tmr_limit = 0;
    bool is_valid = false;
    uint32_t reg_offset = 0;
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Retrieve the address and length of the CPU TMR region */
    status = sev_hal_get_tmr(SEV_CPU_TMR, &tmr_base, &tmr_limit, &is_valid);
    if (status != SEV_STATUS_SUCCESS)
        return tmr_base;

    (void)asid_to_reg_mask(asid, &reg_offset);

    tmr_base += (apic_id * CPU_TMR_THREAD_OFFSET);
    tmr_base += CPU_TMR_INVALID_ASID0_OFFSET;
    tmr_base += (reg_offset * INVALID_ASID_REG_SIZE);

    return tmr_base;
}

static uint32_t get_max_complexes(void)
{
    if (gPersistent.soc_version >= RSDN_A0_SOC_VER_VAL)
        return MAX_NUM_CCXS_PER_CCD_RSDN;
    else
        return MAX_NUM_CCXS_PER_CCD;
}

static sev_status_t access_invalid_asid_regs(uint32_t asid, uint32_t ccd_mask,
                                             uint32_t *value, bool read)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, ccd = 0, complex = 0, core = 0, apic_id = 0, thread = 0, threads_per_core = 0;
    uint32_t ccd_bit = 0;
    uint32_t max_complexes;

    void *reg_addr = NULL;
    uint64_t invalidate_addr = CPU_TMR_INVALID_ASID0_OFFSET;

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    threads_per_core = (gPersistent.smt_enabled) ? THREADS_PER_CORE : 1;
    max_complexes = get_max_complexes();

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (ccd = 0; ccd < MAX_CCDS; ccd++)
        {
            /* Skip CCD if it's not available */
            if (((gPersistent.socket_info[die].ccd_present_bit_mask >> ccd) & 1) == 0)
                continue;

            for (complex = 0; complex < max_complexes; complex++)
            {
                /* Only read/write to CCDs that were requested (part of Activate EX) */
                ccd_bit = 1ul << (die * MAX_CCX_PER_SOCKET_SHIFT + ccd * max_complexes + complex);

                if ((ccd_mask & ccd_bit & gPersistent.ccx_present_bit_mask) == 0)
                    continue;

                for (core = 0; core < MAX_NUM_CORES_PER_CCX; core++)
                {
                    /* Skip if core is not enabled */
                    if (is_core_enabled(die, ccd, complex, core) == false)
                        continue;

                    /* Access per thread since we're writing */
                    for (thread = 0; thread < threads_per_core; thread++)
                    {
                        status = get_apic_id(die, ccd, complex, core, thread, &apic_id);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;

                        invalidate_addr = invalid_asid_address(apic_id, asid);

                        status = sev_hal_map_memory(invalidate_addr, &reg_addr);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;

                        if (read)
                        {
                            *value = ReadReg32((uint32_t)reg_addr);
                            status = sev_hal_unmap_memory(reg_addr);
                            /*
                            * Since we program all core registers identically,
                            * one successful read is enough.
                            */
                            goto end;
                        }
                        else
                        {
                            WriteReg32((uint32_t)reg_addr, *value);
                            status = sev_hal_unmap_memory(reg_addr);
                            if (status != SEV_STATUS_SUCCESS)
                                goto end;
                        }
                    }
                }
            }
        }
    }

end:
    return status;
}

static sev_status_t read_invalid_asid_reg(uint32_t asid, uint32_t ccd_mask, uint32_t *value)
{
    return access_invalid_asid_regs(asid, ccd_mask, value, true);
}

static sev_status_t write_invalid_asid_reg(uint32_t asid, uint32_t ccd_mask, uint32_t *value)
{
    return access_invalid_asid_regs(asid, ccd_mask, value, false);
}

/**
 * Set or clear INVALID_ASID register for specified ASID, for specified CCDs.
 * This is on all dies (sockets) as specified by ccd_mask.
 */
static sev_status_t mark_asid(uint32_t asid, uint32_t ccd_mask, bool set_valid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t value = 0, reg = 0;
    uint32_t ccd_bit = 0;
    uint32_t lastbit = 0;

    if (ccd_mask)
    {
        lastbit = 31 - __clz(ccd_mask);    /* Count leading zeroes */
        for (uint32_t i = 0; i <= lastbit; i++)
        {
            ccd_bit = 1ul << (i);

            /* Skip CCD if it's not available or not requested */
            if ((ccd_mask & ccd_bit & gPersistent.ccx_present_bit_mask) == 0)
                continue;

            status = read_invalid_asid_reg(asid, ccd_bit, &value);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            if (set_valid == true)
                /* Clear the invalid bit for this ASID */
                value &= ~asid_to_reg_mask(asid, &reg);
            else
                /* Set the invalid bit for this ASID */
                value |= asid_to_reg_mask(asid, &reg);

            status = write_invalid_asid_reg(asid, ccd_bit, &value);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

end:
    return status;
}

sev_status_t mark_asid_valid(uint32_t asid, uint32_t ccd_mask)
{
    return mark_asid(asid, ccd_mask, true);
}

sev_status_t mark_asid_invalid(uint32_t asid, uint32_t ccd_mask)
{
    return mark_asid(asid, ccd_mask, false);
}

static sev_status_t write_all_invalid_asid_regs(bool is_invalid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t ccd_bit = 0;
    uint32_t max_complexes = get_max_complexes();
    uint32_t max_ccds = get_max_ccds();

    uint32_t value = is_invalid ? ~0U : 0;

    for (uint32_t ccd = 0; ccd < max_ccds * MAX_SOCKET_NUM * max_complexes; ccd++)
    {
        /* Skip CCD if it's not available */
        ccd_bit = (1 << ccd);
        if ((ccd_bit & gPersistent.ccx_present_bit_mask) == 0)
            continue;

        for (uint32_t asid = 1; asid < MAX_SEV_ASIDS; asid += INVALID_ASID_BITS_PER_REG)
        {
            status = write_invalid_asid_reg(asid, ccd_bit, &value);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

end:
    return status;
}

/**
 * Mark all ASIDs valid on all cores on this die.
 */
sev_status_t mark_all_asids_valid(void)
{
    return write_all_invalid_asid_regs(0);
}

/**
 * Mark all ASIDs invalid on all cores on this die.
 */
sev_status_t mark_all_asids_invalid(void)
{
    return write_all_invalid_asid_regs(1);
}

static sev_status_t access_cpu_tmr(uint32_t apic_id, uint32_t offset, uint32_t *value,
                                   uint32_t num_regs, bool read)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    void *reg_addr = NULL;
    uint64_t tmr_base = 0, tmr_limit = 0;
    bool is_valid = false;
    uint32_t i = 0;

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Retrieve the address and length of the CPU TMR region */
    status = sev_hal_get_tmr(SEV_CPU_TMR, &tmr_base, &tmr_limit, &is_valid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    tmr_base += (apic_id * CPU_TMR_THREAD_OFFSET);
    tmr_base += offset;
    if (tmr_base > tmr_limit)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    skip_cpu_tmr_addr_check(true);
    status = sev_hal_map_memory_ccp(tmr_base, &reg_addr, num_regs * sizeof(uint32_t));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (read)
    {
        for (i = 0; i < num_regs; i++)
        {
            value[i] = ReadReg32((uint32_t)((uint32_t *)reg_addr + i));
        }
    }
    else
    {
        for (i = 0; i < num_regs; i++)
        {
            WriteReg32((uint32_t)((uint32_t *)reg_addr + i), value[i]);
        }
    }

    status = sev_hal_unmap_memory(reg_addr);

end:
    skip_cpu_tmr_addr_check(false);
    return status;
}

/**
 * Check if the bit mask is set on all of the cores.
 * Ignores all the bits we don't care about
 */
static bool is_enabled_all_cores(uint32_t tmr_offset, uint32_t bit_mask)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, ccd = 0, complex = 0, core = 0, apic_id = 0, value = 0;
    uint32_t max_complexes = get_max_complexes();

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (ccd = 0; ccd < MAX_CCDS; ccd++)
        {
            /* Skip CCD if it's not available */
            if (((gPersistent.socket_info[die].ccd_present_bit_mask >> ccd) & 1) == 0)
                continue;

            for (complex = 0; complex < max_complexes; complex++)
            {
                for (core = 0; core < MAX_NUM_CORES_PER_CCX; core++)
                {
                    /* Skip if core is not enabled */
                    if (is_core_enabled(die, ccd, complex, core) == false)
                        continue;

                    status = get_apic_id(die, ccd, complex, core, 0, &apic_id);
                    if (status != SEV_STATUS_SUCCESS)
                        return false;

                    status = access_cpu_tmr(apic_id, tmr_offset, &value, 1, true);
                    if ((status != SEV_STATUS_SUCCESS) || ((value & bit_mask) != bit_mask))
                        return false;
                }
            }
        }
    }

    return true;
}

/**
 * Get the value of either 1 or 2 registers and make sure they are the same across all threads or cores
 * For uCode patch level, get the lowest value across all cores.
 * params: per_thread - To check per core or per thread
 *                      Certain registers are the same across threads so checking per core is enough
 */
static sev_status_t get_reg_all_threads(uint32_t tmr_offset, uint32_t *value,
                                        uint32_t num_regs, bool per_thread)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, ccd = 0, complex = 0, core = 0, apic_id = 0, threads_per_core = 0, thread = 0;
    uint32_t current_value[2] = {0};
    uint32_t value0 = 0;
    uint32_t value1 = 0;
    bool first = true;
    uint32_t max_complexes = get_max_complexes();

    /* Currently no reason to be reading more than 64 bits */
    if (!value || (num_regs != 1 && num_regs != 2))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    threads_per_core = (gPersistent.smt_enabled) ? THREADS_PER_CORE : 1;
    if (!per_thread)        /* We only want to read per-core, so just thread_0 */
        threads_per_core = 1;

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (ccd = 0; ccd < MAX_CCDS; ccd++)
        {
            /* Skip CCD if it's not available */
            if (((gPersistent.socket_info[die].ccd_present_bit_mask >> ccd) & 1) == 0)
                continue;

            for (complex = 0; complex < max_complexes; complex++)
            {
                for (core = 0; core < MAX_NUM_CORES_PER_CCX; core++)
                {
                    /* Skip if core is not enabled */
                    if (is_core_enabled(die, ccd, complex, core) == false)
                        continue;

                    for (thread = 0; thread < threads_per_core; thread++)
                    {
                        status = get_apic_id(die, ccd, complex, core, thread, &apic_id);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;

                        status = access_cpu_tmr(apic_id, tmr_offset, &current_value[0], num_regs, true);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;

                        /* Read all cores and make sure they match (except uCode Patch Level) */
                        if (first)
                        {
                            value0 = current_value[0];
                            if (num_regs == 2)
                                value1 = current_value[1];

                            first = false;
                        }
                        else
                        {
                            if ((value0 == current_value[0]) &&
                                (num_regs == 1 || value1 == current_value[1]))
                                continue; /* This thread matches previous threads */

                            /* Normally, this is an error... but uCode Patch Level is special */
                            if (tmr_offset != CPU_TMR_UCODE_PATCH_LEVEL_OFFSET || num_regs == 2)
                            {
                                /* Other values must match exactly */
                                status = SEV_STATUS_INVALID_CONFIG;
                                goto end;
                            }

                            /* For uCode Patch Level, make sure parts are the same, except patch level */
                            if ((current_value[0] & 0xFFFFFF00) != (value0 & 0xFFFFFF00))
                            {
                                /* Special check required for stepping because Genoa B2 is compatible with Genoa B1 */
                                if ((current_value[0] & 0xFFFFFF00) == 0x0a101200 && (value0 & 0xFFFFFF00) == 0x0a101100)
                                {
                                    /* Force a P1 Genoa B2 part to be Genoa B1 for uCode patch level compare */
                                    current_value[0] &= ~0x00000200;
                                    current_value[0] |=  0x00000100;
                                }
                                else if ((current_value[0] & 0xFFFFFF00) == 0x0a101100 && (value0 & 0xFFFFFF00) == 0x0a101200)
                                {
                                    /* Force a P0 Genoa B2 part to be a Genoa B1 part for the uCode patch level compare*/
                                    value0 &= ~0x00000200;
                                    value0 |=  0x00000100;
                                }
                                else
                                {
                                    /* Other combinations of similar parts, but different steppings aren't compatible */
                                    status = SEV_STATUS_INVALID_CONFIG;
                                    goto end;
                                }
                            }

                            /* Keep track of the minimum patch level and stepping seen so far. */
                            if (current_value[0] < value0)
                                value0 = current_value[0];
                        }
                    }
                }
            }
        }
    }

    /* All threads are good... update caller's return values. */
    value[0] = value0;
    if (num_regs == 2)
        value[1] = value1;
end:
    return status;
}

/**
 * Set the value of registers across all threads
 */
static sev_status_t write_regs_all_threads(uint32_t tmr_offset, uint32_t *value,
                                           uint32_t num_regs)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, ccd = 0, complex = 0, core = 0, threads_per_core = 0, thread = 0, apic_id = 0;
    uint32_t max_complexes = get_max_complexes();

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    threads_per_core = (gPersistent.smt_enabled) ? THREADS_PER_CORE : 1;

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (ccd = 0; ccd < MAX_CCDS; ccd++)
        {
            /* Skip CCD if it's not available */
            if (((gPersistent.socket_info[die].ccd_present_bit_mask >> ccd) & 1) == 0)
                continue;

            for (complex = 0; complex < max_complexes; complex++)
            {
                for (core = 0; core < MAX_NUM_CORES_PER_CCX; core++)
                {
                    /* Skip if core is not enabled */
                    if (is_core_enabled(die, ccd, complex, core) == false)
                        continue;

                    for (thread = 0; thread < threads_per_core; thread++)
                    {
                        status = get_apic_id(die, ccd, complex, core, thread, &apic_id);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;

                        status = access_cpu_tmr(apic_id, tmr_offset, value, num_regs, false);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;
                    }
                }
            }
        }
    }

end:
    return status;
}

sev_status_t get_rmp_base_end(uint64_t *rmp_base, uint64_t *rmp_end)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = get_reg_all_threads(CPU_TMR_RMP_BASE_ADDR_OFFSET, (uint32_t *)rmp_base, 2, false);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = get_reg_all_threads(CPU_TMR_RMP_END_ADDR_OFFSET, (uint32_t *)rmp_end, 2, false);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

/**
 * Check WBINVD_DONE bits on all existing die/ccd/cores in the system.
 * Return overall done status in *is_done, and a bit mask of which CCDs were
 * seen as done even if not all were. Don't stop on negative result.
 * Note: Master only.
 */
sev_status_t is_wbinvd_done(bool *is_done, uint32_t *ccds_done)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, ccd = 0, complex = 0, core = 0, apic_id = 0;
    uint32_t ccd_bit = 0;
    uint32_t value_t0 = 0, value_t1 = 0;
    bool result = false;
    uint32_t max_complexes = get_max_complexes();

    if ((!is_done) || (!ccds_done))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *ccds_done = 0;
    *is_done = true;
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (ccd = 0; ccd < MAX_CCDS; ccd++)
        {
            /* Skip CCD if it's not available */
            if (((gPersistent.socket_info[die].ccd_present_bit_mask >> ccd) & 1) == 0)
                continue;

            for (complex = 0; complex < max_complexes; complex++)
            {
                ccd_bit = 1ul << (die * MAX_CCX_PER_SOCKET_SHIFT + ccd * max_complexes + complex);
                for (core = 0; core < MAX_NUM_CORES_PER_CCX; core++)
                {
                    /* Skip if core is not enabled */
                    if (is_core_enabled(die, ccd, complex, core) == false)
                        continue;

                    /* Read WBINVD_DONE_T0 then WBINVD_DONE_T1 on the same core */
                    status = get_apic_id(die, ccd, complex, core, 0, &apic_id);
                    if (status != SEV_STATUS_SUCCESS)
                        goto end;

                    status = access_cpu_tmr(apic_id, CPU_TMR_WBINVD_DONE_T0_OFFSET, &value_t0, 1, true);
                    if (status != SEV_STATUS_SUCCESS)
                        goto end;
                    status = access_cpu_tmr(apic_id, CPU_TMR_WBINVD_DONE_T1_OFFSET, &value_t1, 1, true);
                    if (status != SEV_STATUS_SUCCESS)
                        goto end;

                    /* Only check T1 bits if SMT is enabled */
                    result = (value_t0 & CPU_TMR_WBINVD_DONE_FLAG) == CPU_TMR_WBINVD_DONE_FLAG;
                    if (gPersistent.smt_enabled)
                        result &= ((value_t1 & CPU_TMR_WBINVD_DONE_FLAG) == CPU_TMR_WBINVD_DONE_FLAG);

                    if (result)
                    {
                        *ccds_done |= ccd_bit;
                    }
                    else
                    {
                        *is_done = false;
                        break;
                    }
                }
            }
        }
    }

end:
    return status;
}

sev_status_t clear_wbinvd_done(uint32_t ccd_mask)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, ccd = 0, complex = 0, core = 0, apic_id = 0;
    uint32_t ccd_bit = 0;
    uint32_t value = 0;
    uint32_t max_complexes = get_max_complexes();

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (ccd = 0; ccd < MAX_CCDS; ccd++)
        {
            /* Skip CCD if it's not available */
            if (((gPersistent.socket_info[die].ccd_present_bit_mask >> ccd) & 1) == 0)
                continue;

            for (complex = 0; complex < max_complexes; complex++)
            {
                /* Skip this CCX if not requested */
                ccd_bit = 1ul << (die * MAX_CCX_PER_SOCKET_SHIFT + ccd * max_complexes + complex);
                if ((ccd_mask & ccd_bit) == 0)
                    continue;

                for (core = 0; core < MAX_NUM_CORES_PER_CCX; core++)
                {
                    /* Skip if core is not enabled */
                    if (is_core_enabled(die, ccd, complex, core) == false)
                        continue;

                    /* Access WBINVD_DONE_T0 and WBINVD_DONE_T1 on T0 */
                    status = get_apic_id(die, ccd, complex, core, 0, &apic_id);
                    if (status != SEV_STATUS_SUCCESS)
                        goto end;

                    status = access_cpu_tmr(apic_id, CPU_TMR_WBINVD_DONE_T0_OFFSET, &value, 1, true);
                    if (status != SEV_STATUS_SUCCESS)
                        goto end;
                    ((uint8_t *)&value)[0] &= ~CPU_TMR_WBINVD_DONE_FLAG;  /* T0 */
                    ((uint8_t *)&value)[1] &= ~CPU_TMR_WBINVD_DONE_FLAG;  /* T1 */
                    status = access_cpu_tmr(apic_id, CPU_TMR_WBINVD_DONE_T0_OFFSET, &value, 1, false);
                    if (status != SEV_STATUS_SUCCESS)
                        goto end;
                }
            }
        }
    }

end:
    return status;
}

bool sme_is_enabled_all_cores(void)
{
    return is_enabled_all_cores(CPU_TMR_SME_EN_OFFSET, CPU_TMR_SME_EN_FLAG);
}

bool vmpl_is_enabled_all_cores(void)
{
    return is_enabled_all_cores(CPU_TMR_VMPL_EN_OFFSET, CPU_TMR_VMPL_EN_FLAG);
}

bool smke_is_enabled_all_cores(void)
{
    return is_enabled_all_cores(CPU_TMR_SMKE_EN_OFFSET, CPU_TMR_SMKE_EN_FLAG);
}

uint32_t retrieve_microcode_patch_level(void)
{
    uint32_t mc_level = 0;
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = get_reg_all_threads(CPU_TMR_UCODE_PATCH_LEVEL_OFFSET, &mc_level, 1, false);
    if (status != SEV_STATUS_SUCCESS)
        return 0;

    return mc_level;
}

bool vm_hsave_pa_cleared_all_cores(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t value = 0;

    status = get_reg_all_threads(CPU_TMR_VM_HSAVE_PA_OFFSET, (uint32_t *)&value, 2, true);
    if (status != SEV_STATUS_SUCCESS || value != 0)
        return false;
    return true;
}

/**
 * This function writes SEV-ES TMR address to the CPU TMR for all cores
 */
sev_status_t write_sev_es_tmr_address_to_all_cores(uint64_t value)
{
    return write_regs_all_threads(CPU_TMR_SEV_ES_TMR_BASE, (uint32_t *)&value, 2);
}
