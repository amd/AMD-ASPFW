// Copyright(C) 2018-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "apicid.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_scmd.h"
#include "bl_syscall.h"
#include "core.h"
#include "sev_hal_interface.h"

/**
 * SMT enabled:
 *  APICID format from PPR:
 *  | Socket ID | LogicalDieID[3:0] | LogicalCoreId[2:0] | ThreadId |
 *
 * SMT disabled:
 *  | 1'b0 | Socket ID | LogicalDieId[3:0] | LogicalCoreId[2:0] |
 */

/* SMT Enabled */
#define APIC_ID_SMT_THREAD_ID_SHIFT       (0)
#define APIC_ID_SMT_LOGICAL_CORE_SHIFT    (1)
#define APIC_ID_SMT_LOGICAL_DIE_SHIFT     (4)
#define APIC_ID_SMT_LOGICAL_SOCKET_SHIFT  (8)

/* SMT Disabled */
#define APIC_ID_LOGICAL_CORE_SHIFT     (APIC_ID_SMT_LOGICAL_CORE_SHIFT - 1)

/* INITPKG0 Register Defines. PPR L3::SCFCTP::PMREG_INITPKG0 */
#define INITPKG0_SOCKET_ID(x)          (((x) & 0x00003000) >> 12)
#define INITPKG0_LOGICAL_DIE_ID(x)     (((x) & 0x00780000) >> 19)
#define INITPKG0_LOGICAL_CCX_ID(x)     (((x) & 0x00040000) >> 18)
#define INITPKG0_LOGICAL_CORE_ID(x)    (((x) & 0x0003C000) >> 14)
#define INITPKG0_SMT_EN(x)             ((x) & 1)

/* INITPKG7 Register Defines. PPR L3::SCFCTP::PMREG_INITPKG7 */
#define INITPKG7_NUM_LOGICAL_DIES(x)   (((x) >> 21) & 0xf)
#define INITPKG7_NUM_LOGICAL_CCXS(x)   (((x) >> 20) & 0x1)
#define INITPKG7_NUM_LOGICAL_CORES(x)  (((x) >> 16) & 0xf)
#define INITPKG7_NUM_SOCKETS(x)        (((x) >> 25) & 0x3)
#define INITPKG7_APIC_16T_MODE(x)      (((x) >> 11) & 0x1)

#define INITPKG_ZERO_PADDING_BIT_POS   4

/* APIC ID Table Entry */
#define APIC_ID_ENTRY_VALID         (0x80)
#define APIC_ID_ENTRY_SOCKET_SHIFT  (4)     /* 4 bits of CCDs to address MAX_CCDS */
#define APIC_ID_ENTRY_CCD_SHIFT     (0)

#define APIC_ID_ZERO_PAD_SHIFT      (3)

uint32_t get_field_width(uint32_t num_instances)
{
    return (32ul - __clz(num_instances));
}

/*
 * Helper function to read INITPKG0.
 * The value changes per core.
 */
static sev_status_t read_initpkg0(uint32_t socketid, uint32_t ccx_ccd, uint32_t core, uint32_t *value)
{
    sev_scfctp_init_pkg_regs_t *initpkg = gPersistent.initpkg_addr;

    /*
     * Validate input against initpkg structure's limits
     * so that we don't have illegal accesses
     */
    if ((initpkg == NULL) ||
        (socketid >= MCM_MAX_SOCKET_NUM) ||
        (ccx_ccd >= MCM_MAX_NUM_CCDS) ||
        (core >= MCM_MAX_CORE_NUM))
        return ERR_INVALID_PARAMS;

    *value = initpkg->init_regs[socketid].socket_info[ccx_ccd].ccd_info[core].initpkg0;
    return SEV_STATUS_SUCCESS;
}

/* Helper function to return the maximum physical cores per ccd */
static uint32_t get_max_physical_cores_per_ccd(void)
{
    if (gPersistent.soc_version >= RSDN_A0_SOC_VER_VAL)
         return MAX_NUM_CORES_PER_CCD_RSDN;
     else
         return MAX_NUM_CORES_PER_CCD;
}

sev_status_t get_apic_id_format(apicid_fmt_specifier_t *afs)
{
    uint32_t bp = 0;

    memset(afs, 0, sizeof(*afs));

    if (gPersistent.initpkg7 == 0)
        return SEV_STATUS_HARDWARE_PLATFORM;

    afs->thread_bit_shift = 0;
    bp = (gPersistent.smt_enabled == true);

    afs->core_bit_shift = bp;
    bp += get_field_width(INITPKG7_NUM_LOGICAL_CORES(gPersistent.initpkg7));

    if (INITPKG7_APIC_16T_MODE(gPersistent.initpkg7) && bp < INITPKG_ZERO_PADDING_BIT_POS)
    {
        afs->zero_bit_shift = bp;
        bp = INITPKG_ZERO_PADDING_BIT_POS;
    }

    afs->ccx_bit_shift = bp;
    bp += get_field_width(INITPKG7_NUM_LOGICAL_CCXS(gPersistent.initpkg7));

    afs->ccd_bit_shift = bp;
    bp += get_field_width(INITPKG7_NUM_LOGICAL_DIES(gPersistent.initpkg7));

    afs->sock_bit_shift = bp;
    bp += get_field_width(INITPKG7_NUM_SOCKETS(gPersistent.initpkg7));

    if (bp >= sizeof(uint32_t) * CHAR_BIT)
        return SEV_STATUS_HARDWARE_PLATFORM;

    return SEV_STATUS_SUCCESS;
}

/**
 * Helper functions to parse INITPKG7
 * Contains Max complex/socket/ccd id
 * See http://twiki.amd.com/twiki/bin/view/CBArch/CBApicID
 *
 */
uint32_t get_num_cores_per_complex(void)
{
    return INITPKG7_NUM_LOGICAL_CORES(gPersistent.initpkg7) + 1;
}

uint32_t get_ccds_per_socket(void)
{
    return INITPKG7_NUM_LOGICAL_DIES(gPersistent.initpkg7) + 1;
}

uint32_t get_ccxs_per_ccd(void)
{
    return INITPKG7_NUM_LOGICAL_CCXS(gPersistent.initpkg7) + 1;
}

uint32_t get_max_ccds(void)
{
    if (gPersistent.soc_version >= RSDN_A0_SOC_VER_VAL)
        return MAX_CCDS_RSDN;
    else
        return MAX_CCDS_RS;
}

uint32_t get_physical_ccxs_per_ccd(void)
{
    if (gPersistent.soc_version >= RSDN_A0_SOC_VER_VAL)
        return CCXS_PER_CCD_RSDN;
    else
        return CCXS_PER_CCD_RS;
}

/**
 * Master and Slave - using PSP Secure Dram
 */
sev_status_t create_apicid_table(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t ccd = 0, complex = 0, core = 0, ccx = 0;
    uint32_t local_ccx = 0, local_core = 0;
    uint8_t *apicid_table = NULL;

    uint32_t value = 0;
    uint32_t logical_core_id = 0, logical_die_id = 0, logical_ccx_id = 0;
    uint32_t socket_id = 0;
    uint8_t apicid_lookup = 0;
    uint32_t apicid = 0;

    uint32_t max_cores_per_ccd = 0;
    uint32_t max_physical_cores_per_ccx = 0;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (get_apic_id_format(&gPersistent.afs) != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_HARDWARE_PLATFORM;
        goto end;
    }

    /* Enable ACTIVATE EX unless APIC table has a conflict */
    sev->activate_ex_enable = true;
    apicid_table = sev->apic_ids;

    memset(apicid_table, 0, sizeof(sev->apic_ids));

    max_cores_per_ccd = get_max_physical_cores_per_ccd();
    max_physical_cores_per_ccx = max_cores_per_ccd/get_physical_ccxs_per_ccd();

    for (ccd = 0; ccd < MAX_CCDS; ccd++)
    {
        for (complex = 0; complex < MAX_COMPLEXES; complex++)
        {
            for (core = 0; core < max_cores_per_ccd; core++)
            {
                /* Skip if core is not enabled */
                if (is_core_enabled(gCurrentDieID, ccd, complex, core) == false)
                    continue;

                if (get_physical_ccxs_per_ccd() == 2)
                {
                    local_ccx = (core < max_physical_cores_per_ccx) ? 0 : 1;
                    local_core = (core < max_physical_cores_per_ccx) ? core : core - max_physical_cores_per_ccx;
                    ccx = ((ccd * get_physical_ccxs_per_ccd()) + local_ccx);
                    if ((status = read_initpkg0(gCurrentDieID, ccx, local_core, &value)) != SEV_STATUS_SUCCESS)
                        goto end;
                }
                else
                {
                    if ((status = read_initpkg0(gCurrentDieID, ccd, core, &value)) != SEV_STATUS_SUCCESS)
                        goto end;
                    ccx = ccd;
                }

                logical_core_id = INITPKG0_LOGICAL_CORE_ID(value);
                logical_die_id = INITPKG0_LOGICAL_DIE_ID(value);
                logical_ccx_id = INITPKG0_LOGICAL_CCX_ID(value);

                /* Logical core id should range from 0..num_logical_cores, logical die_id
                   should range from 0..num_logical_dies */
                if ((logical_core_id >= get_num_cores_per_complex()) || (logical_die_id >= get_ccds_per_socket()))
                {
                    /* This should never happen */
                    status = SEV_STATUS_HARDWARE_PLATFORM;
                    goto end;
                }

                socket_id = INITPKG0_SOCKET_ID(value);
                apicid_lookup = (ccx << APIC_ID_ENTRY_CCD_SHIFT) |
                                (socket_id << APIC_ID_ENTRY_SOCKET_SHIFT);

                /*
                 * SMT Enabled  => Two Threads per core => Two APICID Identries for each core
                 * SMT Disabled => One Thread  per core => One APICID Identry for each core
                 */
                if (gPersistent.smt_enabled)
                {
                    uint32_t apicid_1 = 0;
                    apicid = get_apic_id_logical(socket_id, logical_die_id, logical_ccx_id, logical_core_id, 0);
                    apicid_1 = get_apic_id_logical(socket_id, logical_die_id, logical_ccx_id, logical_core_id, 1);

                    if ((apicid >= MAX_APIC_IDS) || (apicid_1 >= MAX_APIC_IDS) ||
                        (apicid_table[apicid] != 0) ||
                        (apicid_table[apicid_1] != 0))
                    {
                        /* Conflict detected. Disable ACTIVATE EX and exit table creation */
                        sev->activate_ex_enable = false;
                        status = SEV_STATUS_SUCCESS;  /* Yes, return Success. */
                        goto end;
                    }
                    apicid_table[apicid] = apicid_lookup | APIC_ID_ENTRY_VALID;
                    apicid_table[apicid_1] = apicid_lookup | APIC_ID_ENTRY_VALID;
                }
                else
                {
                    apicid = get_apic_id_logical(socket_id, logical_die_id, logical_ccx_id, logical_core_id, 0);

                    if ((apicid >= MAX_APIC_IDS) || (apicid_table[apicid] != 0))
                    {
                        /* Conflict detected. Disable ACTIVATE EX and exit table creation */
                        sev->activate_ex_enable = false;
                        status = SEV_STATUS_SUCCESS;  /* Yes, return Success. */
                        goto end;
                    }
                    apicid_table[apicid] = apicid_lookup | APIC_ID_ENTRY_VALID;
                }
            }
        }
    }

end:
    return status;
}

/**
 * Master only
 */
sev_status_t sync_apicid_tables(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_scmd_t cmd;
    uint8_t *m_apic_table = NULL;
    uint8_t *s_apic_table = NULL;
    uint32_t i;

    /* Return if it's just one socket */
    if (gTotalDieNum == 1)
        goto end;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&cmd, 0, sizeof(cmd));
    cmd.id = SEV_SCMD_ID_GET_APICID;
    status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    sev_hal_invalidate_dcache((uint32_t)&gpDram->p1_info, sizeof(gpDram->p1_info));

    /*
     * If slave has issue with activate_ex_enable, then master also needs
     * to be updated
     */
    if (gpDram->p1_info.activate_ex_enable == false)
    {
        sev->activate_ex_enable = false;
        status = SEV_STATUS_SUCCESS;    /* Yes, return Success. */
        goto end;
    }

    m_apic_table = sev->apic_ids;
    s_apic_table = gpDram->p1_info.apic_ids;

    for (i = 0; i < MAX_APIC_IDS; i++)
    {
        if (s_apic_table[i] != 0)
        {
            if (m_apic_table[i] == 0)
                m_apic_table[i] = s_apic_table[i];
            else
            {
                /*
                 * If master die already has entry, this is an error for the
                 * APICID. Disable the activate ex
                 */
                sev->activate_ex_enable = false;
                status = SEV_STATUS_SUCCESS;    /* Yes, return Success */
                goto end;
            }
        }
    }

end:
    return status;
}

/**
 * Utility intended for Master.
 */
sev_status_t apicid_to_ccx_bitmask(sev_t *sev, uint32_t *apicid_list,
                                   size_t listcnt, uint32_t *ccx_bitmask)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t *apic_lookup = NULL;
    uint32_t bitmask = 0;
    size_t i = 0;
    uint32_t phy_ccx_val = 0, apicid = 0;

    if (!sev || !apicid_list || !ccx_bitmask || (listcnt > APIC_ID_LIST_MAX_CNT))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    apic_lookup = sev->apic_ids;
    for (i = 0; i < listcnt; i++)
    {
        apicid = apicid_list[i];
        if (apicid >= MAX_APIC_IDS)
        {
            status = ERR_INVALID_PARAMS;
            goto end;
        }

        /*
         * Get the physical ccx value:
         * | 1 bit socket id | 4 bits ccd |, plus a valid bit (0x80)
         * 0x80 = socket 0, CCD 0, CCX0
         * 0x81 = socket 0, CCD 0, CCX1
         * ...
         * 0x8F = socket 0, CCD 7, CCX1
         * 0x90 = socket 1, CCD 0, CCX0
         * 0x91 = socket 1, CCD 1, CCX1
         * etc.
         */

        phy_ccx_val = (uint32_t)apic_lookup[apicid];
        if (phy_ccx_val & APIC_ID_ENTRY_VALID)
        {
            /* Valid entry, build bitmask */
            phy_ccx_val &= ~APIC_ID_ENTRY_VALID;
            bitmask |= (1 << phy_ccx_val);
        }
        else
        {
            /* Invalid entry */
            status = SEV_STATUS_INVALID_CONFIG;
            goto end;
        }
    }

    *ccx_bitmask = bitmask;

end:
    return status;
}

/**
 * Given the Socket ID and CCD ID, return the first APIC ID for the CCD
 *   - Note: the parameters are LOGICAL IDs
 *
 * Examples: Note that Socket and Die do not move based on padding, only cores do.
 * SDDDDCCCT (no down-core/SMT enabled)
 * SDDDD0CCT (4 cores, SMT enabled)
 * SDDDD0CCC (8 cores, SMT disabled)
 *  SDDDCCCT (8 cores, SMT enabled, 8 CCDs)
 *
 * Note: The APIC IDs for the threads in the 2nd socket start at 0x100 (256).
 *       There's a hole in the allocation of APIC IDs since the number of CCDs is not a power of 2.
 *       Ex: 2P, 12 CCD, 8 core system, SMT enabled: 384 total threads (2*12*8*2)
 *           So APIC IDs on P0 are 0->191 and on P1 are 256->447
 *
 * Apic ID format Specifier (AFS) is already checked for errors and hence suppressing
 * Coverity errors.
*/

uint32_t get_apic_id_logical(uint32_t socket_id, uint32_t ccd, uint32_t ccx, uint32_t core, uint32_t thread_id)
{
    uint32_t apicid = 0;

    if (gPersistent.smt_enabled)
        /* coverity[cert_int34_c_violation] Suppress intentional CERT C error on next line */
        apicid = (thread_id << gPersistent.afs.thread_bit_shift);

    /* coverity[cert_int34_c_violation] Suppress intentional CERT C error on next line */
    apicid |= ((core << gPersistent.afs.core_bit_shift) |
              (ccd << gPersistent.afs.ccd_bit_shift));

    if (get_ccxs_per_ccd() > 1)
        /* coverity[cert_int34_c_violation] Suppress intentional CERT C error on next line */
        apicid |= (ccx << gPersistent.afs.ccx_bit_shift);

    /* coverity[cert_int34_c_violation] Suppress intentional CERT C error on next line */
    return (apicid | (socket_id << gPersistent.afs.sock_bit_shift));
}


/**
 * Given the Socket ID and CCD ID, return the first APIC ID for the CCD
 *   - Note: the parameters are physical ids
 *
 */
sev_status_t get_apic_id(uint32_t socket_id, uint32_t ccd, uint32_t ccx, uint32_t core, uint32_t thread_id, uint32_t *apicid)
{
    uint32_t value = 0;
    uint32_t logical_core_id = 0, logical_die_id = 0, logical_ccx_id = 0;
    uint32_t physical_ccx = 0;
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (apicid == NULL) {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (get_physical_ccxs_per_ccd() == 2)
    {
        physical_ccx = ((ccd * get_physical_ccxs_per_ccd()) + ccx);
        if ((status = read_initpkg0(socket_id, physical_ccx, core, &value)) != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        if ((status = read_initpkg0(socket_id, ccd, core, &value)) != SEV_STATUS_SUCCESS)
            goto end;
    }

    logical_core_id = INITPKG0_LOGICAL_CORE_ID(value);
    logical_die_id = INITPKG0_LOGICAL_DIE_ID(value);
    logical_ccx_id = INITPKG0_LOGICAL_CCX_ID(value);

    *apicid = get_apic_id_logical(socket_id, logical_die_id, logical_ccx_id, logical_core_id, thread_id);
end:
    return status;
}


