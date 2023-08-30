// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_HAL_INTERFACE_H
#define SEV_HAL_INTERFACE_H

#include <stddef.h>
#include <stdint.h>

#include "sev_status.h"

#define MAX_CCDS                (16)
#define MAX_CCDS_RSDN           (8)     // FW_SUPPORTED_MAX_NUM_CCDS. Needs to stay power of 2
#define MAX_CCDS_RS             (16)    // FW_SUPPORTED_MAX_NUM_CCDS. Needs to stay power of 2
#define MAX_CCD_BITMASK         ((1 << MAX_CCDS) - 1) /* 0xFFFF */
#define THREADS_PER_CORE        (2)
#define MAX_COMPLEXES           (1)
#define CCXS_PER_CCD_RS         (1)
#define CCXS_PER_CCD_RSDN       (2)

#define MAX_CCX_PER_SOCKET_SHIFT    (16)    // Maximum bits required to represent all the CCXs per socket.

#define CCXS_ON_P0(ccxs)        ((ccxs >> 0) & MAX_CCD_BITMASK)         /* CCD Bit Mask on Socket 0. */
#define CCXS_ON_P1(ccxs)        ((ccxs >> MAX_CCDS) & MAX_CCD_BITMASK)  /* CCD Bit Mask on Socket 1. */

#define INVALID_ASID_BITS_PER_REG       (32)
#define INVALID_ASID_REG_SIZE           (4)     /* INVALID_ASID register size in bytes */

/**
 * Reports if a core is available on a specific die/socket
 */
bool is_core_enabled(uint32_t ccd, uint32_t coreid, uint32_t complex, uint32_t die);

/**
 * Calculate the mask for the ASID register
 */
uint32_t asid_to_reg_mask(uint32_t asid, uint32_t *reg);

/**
 * Mark an ASID valid on all cores on this die.
 */
sev_status_t mark_asid_valid(uint32_t asid, uint32_t ccd_mask);

/**
 * Mark an ASID invalid on all cores on this die.
 */
sev_status_t mark_asid_invalid(uint32_t asid, uint32_t ccd_mask);

/**
 * Mark all ASIDs valid on all cores on this die.
 */
sev_status_t mark_all_asids_valid(void);

/**
 * Mark all ASIDs invalid on all cores on this die.
 */
sev_status_t mark_all_asids_invalid(void);

/**
 * Writes the VmgSts register on all cores on this die.
 */
sev_status_t write_all_vmg_status_regs(uint32_t flags);

/**
 * Clear the WBINVD_DONE bits on the specified CCD.
 */
sev_status_t clear_wbinvd_done(uint32_t ccd_mask);

/**
 * Test if SME is enabled across all cores
 */
bool sme_is_enabled_all_cores(void);

/**
 * Test if SMKE is enabled across all cores
 */
bool smke_is_enabled_all_cores(void);

/**
 * Test if VMPL is enabled across all cores
 */
bool vmpl_is_enabled_all_cores(void);

/**
 * Test if VM_HSAVE_PA is 0 across all cores
 */
bool vm_hsave_pa_cleared_all_cores(void);

/**
 * Test if wbinvd has been issued on all dies/cores.
 */
sev_status_t is_wbinvd_done(bool *is_done, uint32_t *ccds_done);

/**
 * Retrieve microcode patch level
 */
uint32_t retrieve_microcode_patch_level(void);

/**
 * Retrieve RMP BASE and END
 */
sev_status_t get_rmp_base_end(uint64_t *rmp_base, uint64_t *rmp_end);

/**
 * This function writes SEV-ES TMR address to the CPU TMR for all cores
 */
sev_status_t write_sev_es_tmr_address_to_all_cores(uint64_t value);

#endif /* SEV_HAL_INTERFACE_H */
