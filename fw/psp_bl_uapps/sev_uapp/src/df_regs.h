// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#ifndef DF_REGS_H
#define DF_REGS_H

#include <stdint.h>

#include "sev_errors.h"

/**
 * Data Fabric instance IDs.
 * PPR 13.4.1 System InstanceID and FabricID Assignment
 */
#define PIE_INSTANCE_ID     (44)    /* PIE (PIE0) */

#define CCM0_INSTANCE_ID    (16)    /* CCM0 to CCM7 is 16 to 23 */

#define TMR_NR_MIN    (0)
#define TMR_NR_MAX    (7)

/**
 * PSP TMR Allocation can be found here:
 * http://confluence.amd.com/display/ASST/PSP+TMR+Allocation
 *
 * ES_TMR should be dynamically allocated
 */
#define SEV_ES_TMR_POOL     (1)
#define SEV_ES_TMR_CRC      (2)
#define SEV_ES_TMR_SIZE     (0x100000)
#define SEV_ES_TMR_SIZE_SNP (0x200000) /* If SNP Enabled, 2MB TMR. CSF-945 */
#define SNP_RMP_CPU_TMR     (3)
#define SNP_RMP_IOMMU_TMR   (4)
#define SEV_CPU_TMR         (5) /* S3 image */
#define SEV_CPU_TMR2        (6) /* SSCB access TMR */
#define SNP_RMP_TMPM_TMR    (7) /* Allow RMP writes by TMPM */

#define TMR_SDP_MICROCODE_TRUST_LVL (0x04)   /* Microcode SDP Trust level for Genoa is 4 */

/* D18F7xA08...D18F7xAB0 [Trusted Memory Region Control 7:0] (DF::TmrCtl) */
#define TMR_CTRL_SEC_VALID_SHIFT    (16)                              /* Enable TMR security level checks. Not used for SNP */
#define TMR_CTRL_SEC_VALID_FLAG     (1ul << TMR_CTRL_SEC_VALID_SHIFT)
#define TMR_CTRL_SAE_IOM_SHIFT      (13)
#define TMR_CTRL_SAE_IOM_FLAG       (1ul << TMR_CTRL_SAE_IOM_SHIFT)   /* Source access == IOM (IOMMU) */
#define TMR_CTRL_SAE_NCM_SHIFT      (12)
#define TMR_CTRL_SAE_NCM_FLAG       (1ul << TMR_CTRL_SAE_NCM_SHIFT)   /* Source access == Non-Coherent Master (MPDMA/etc) */
#define TMR_CTRL_SAE_CCM_SHIFT      (10)
#define TMR_CTRL_SAE_CCM_FLAG       (1ul << (TMR_CTRL_SAE_CCM_SHIFT)) /* Source access == CCM (x86, uCode) */
#define TMR_CTRL_SAE_PIE_SHIFT      (9)
#define TMR_CTRL_SAE_PIE_FLAG       (1ul << (TMR_CTRL_SAE_PIE_SHIFT)) /* Source access == PIE (DF: Power, Interrupts, Etcetera) */
#define TMR_CTRL_SAE_SMU_SHIFT      (8)
#define TMR_CTRL_SAE_SMU_FLAG       (1ul << (TMR_CTRL_SAE_SMU_SHIFT)) /* Source access == SMU */
#define TMR_CTRL_UNIT_ID0_VAL_SHIFT (5)
#define TMR_CTRL_UNIT_ID0_VAL_FLAG  (1ul << (TMR_CTRL_UNIT_ID0_VAL_SHIFT)) /* TMR's Unit ID 0 is valid and must match */
#define TMR_CTRL_UNIT_ID1_VAL_SHIFT (7)
#define TMR_CTRL_UNIT_ID1_VAL_FLAG  (1ul << (TMR_CTRL_UNIT_ID1_VAL_SHIFT)) /* TMR's Unit ID 1 is valid and must match */
#define TMR_CTRL_CACHE_EN_SHIFT     (2)
#define TMR_CTRL_CACHE_EN_FLAG      (1ul << (TMR_CTRL_CACHE_EN_SHIFT))
#define TMR_CTRL_WRITE_EN_SHIFT     (1)
#define TMR_CTRL_WRITE_EN_FLAG      (1ul << (TMR_CTRL_WRITE_EN_SHIFT))
#define TMR_CTRL_VALID_SHIFT        (0)
#define TMR_CTRL_VALID_FLAG         (1ul << (TMR_CTRL_VALID_SHIFT))

/* Allow only Microcode to write to CRC area */
#define TMR_CTRL_CRC_DEFAULTS_CRC64  ((TMR_CTRL_SEC_VALID_FLAG) | \
                                      (TMR_CTRL_SAE_CCM_FLAG)   | \
                                      (TMR_CTRL_WRITE_EN_FLAG)  | \
                                      (TMR_CTRL_VALID_FLAG))

/* POOL should be no write/access from anyone other than PSP */
#define TMR_CTRL_POOL_DEFAULTS      ((TMR_CTRL_VALID_FLAG))

/**
 * During SNP_INIT while the RMP is being setup, the SNP TMR should have no
 * write/access from anyone other than PSP until it is released.
 * Allow for read from x86/CCM, but do not allow for writes to the region.
 *
 * After the RMP is setup, enable writes to allow uCode/CPU to write. The
 * hardware will still protect writes from x86 with SNP enabled.
 */
#define TMR_CTRL_RMP_CPU_DEFAULTS   ((TMR_CTRL_SAE_CCM_FLAG)  | \
                                     (TMR_CTRL_SAE_NCM_FLAG)  | \
                                     (TMR_CTRL_SAE_IOM_FLAG)  | \
                                     (TMR_CTRL_CACHE_EN_FLAG) | \
                                     (TMR_CTRL_VALID_FLAG))

/* Allow reads by all masters. Valid after RMP is initialized in SNP_INIT until reboot. */
#define TMR_CTRL_RMP_IOMMU_DEFAULTS ((TMR_CTRL_SAE_IOM_FLAG)  | \
                                     (TMR_CTRL_SAE_NCM_FLAG)  | \
                                     (TMR_CTRL_SAE_CCM_FLAG)  | \
                                     (TMR_CTRL_SAE_SMU_FLAG)  | \
                                     (TMR_CTRL_VALID_FLAG))

/* Allow writes - after RMP is set up - to the RMP from the PM-MPDMA (aka TMPM) */
#define TMR_CTRL_RMP_TMPM_DEFAULTS ((TMR_CTRL_SAE_IOM_FLAG)   | \
                                    (TMR_CTRL_WRITE_EN_FLAG)  | \
                                    (TMR_CTRL_UNIT_ID0_VAL_FLAG) | \
                                    (TMR_CTRL_UNIT_ID1_VAL_FLAG) | \
                                    (TMR_CTRL_VALID_FLAG))

/* TMR address registers are only 32 bits, from bit 16 to bit 47. This is the shift value */
#define TMR_X86_PHYS_ADDR_SHIFT         (16ULL)

/* D18F7xA0C...D18F7xAB4 [Trusted Memory Region FabricId & UnitId A 7:0] (DF::TmrFidA) */
#define TMR_FIDA_UNIT_ID_SHIFT          (16)
#define TMR_FIDA_UNIT_ID_MASK           (0x3Fu << TMR_FIDA_UNIT_ID_SHIFT) /* 6 bit Unit ID */
#define TMPM_UNIT_ID                    (0x3Du)

#define TMR_FIDB_UNIT_ID_SHIFT          (16)
#define TMR_FIDB_UNIT_ID_MASK           (0x3Fu << TMR_FIDB_UNIT_ID_SHIFT) /* 6 bit Unit ID */
#define TMPM_UNIT_ID_DMA                (0x3Au)

/* D18F1x3F8 [PSP Miscellaneous Modes] (DF::PspMiscMode) */
#define MISC_GLOB_VISIBLE_WR_FLUSH_BIT  (1)
#define MISC_GLOB_VISIBLE_WR_FLUSH_FLAG (1ul << (MISC_GLOB_VISIBLE_WR_FLUSH_BIT))
#define MISC_TSME_ENABLE_BIT            (3)
#define MISC_TSME_ENABLE_FLAG           (1ul << (MISC_TSME_ENABLE_BIT))
#define MISC_PSP_RD_SZ_WRBKINVD_BIT     (16)    /* Read-Sized causes Write Back Invalidate */
#define MISC_PSP_RD_SZ_WRBKINVD_FLAG    (1ul << (MISC_PSP_RD_SZ_WRBKINVD_BIT))

#define DF_TRUST_LVL_IMPLICIT_BIT       (0)     /* Implicitly trusted PSP (Secure MP0). */
#define DF_TRUST_LVL_HIGH_BIT           (2)     /* CPU Microcode, SMU (MP1), SCFCTP/Aspen. */
#define DF_TRUST_LVL_UNTRUSTED_BIT      (7)     /* Default. All non-microcode accesses from CPU,
                                                 * all accesses from I/O, and any unknown sources. */

#define DF_TRUST_LVL_IMPLICIT_MASK      (1ul << (DF_TRUST_LVL_IMPLICIT_BIT))
#define DF_TRUST_LVL_HIGH_MASK          (1ul << (DF_TRUST_LVL_HIGH_BIT))
#define DF_TRUST_LVL_UNTRUSTED_MASK     (1ul << (DF_TRUST_LVL_UNTRUSTED_BIT))

/**
 * The function values directly comes from the PPR.
 * For DF_TMR_FUNC:        D18F7xA00...D18F7xAA8 DF::TmrBaseAddr
 */
#define DF_TMR_FUNC                     (0x7)

/**
 * Wake up the DF.
 * Ensure that the non-PIE DF registers are capable of servicing requests.
 */
sev_status_t df_access_lock(void);

/**
 * Allow the DF to sleep.
 */
sev_status_t df_access_unlock(void);

/**
 * Read a 32-bit DF register indirectly.
 *
 * This function reads a single register instance only.
 */
sev_status_t read_df_reg32(uint32_t instance, uint32_t function, uint32_t offset, uint32_t *value);

/**
 * Read a 64-bit DF register indirectly.
 *
 * This function reads a single register instance only.
 */
sev_status_t read_df_reg64(uint32_t instance, uint32_t function, uint32_t offset, uint64_t *value);

/**
 * Write a 32-bit DF register indirectly.
 *
 * This function writes a single register instance only.
 */
sev_status_t write_df_reg32(uint32_t instance, uint32_t function, uint32_t offset, uint32_t value);

/**
 * Write a 64-bit DF register indirectly.
 *
 * This function writes a single register instance only.
 */
sev_status_t write_df_reg64(uint32_t instance, uint32_t function, uint32_t offset, uint64_t value);

/**
 * Read multiple instances of DF registers indirectly.
 *
 * This function uses a broadcast read and returns the logical OR of each
 * instance of the register on the calling die.
 */
sev_status_t read_df_reg_bcast32(uint32_t function, uint32_t offset, uint32_t *value);

/**
 * Write multiple instances of DF registers indirectly.
 *
 * This function uses a broadcast access to write each instance of the
 * register on the calling die.
 */
sev_status_t write_df_reg_bcast32(uint32_t function, uint32_t offset, uint32_t value);

/**
 * This function uses a broadcast access to read each instance of the
 * given TMR on the calling die. At least one of *base, *limit, *mask, and
 * *control must be non-NULL. Otherwise, ERR_INVALID_PARAMS is returned.
 */
sev_status_t get_tmr_info(size_t tmr_nr, uint64_t *base, uint64_t *limit,
                          uint32_t *trust_lvl, uint32_t *flags);

/**
 * Parses the TmrCtl register value and returns the value of the TmrVal flag.
 */
bool tmr_is_valid(uint32_t tmr_ctrl);

/**
 * This function uses a broadcast access to write each instance of the
 * given TMR on the calling die.
 */
sev_status_t set_tmr(size_t tmr_nr, uint64_t base, uint64_t limit,
                     uint32_t flags, uint32_t trust_lvl);

sev_status_t set_tmr_modify_flags(size_t tmr_nr, uint32_t flags, bool set);

/**
 * Set/get the flag fields of the PspMiscMode register using broadcast accesses.
 * This only get/sets for a single processor. Use slave commands also in
 *   higher-level functions
 */
sev_status_t set_psp_misc_mode(uint32_t flags);
sev_status_t get_psp_misc_mode(uint32_t *flags);

/**
 * Copies 'size' bytes from 'key' into the key slot for 'asid' in all CNLI on
 * each die.
 */
sev_status_t set_cnli_key(uint32_t asid, const uint8_t *seed, size_t size);

/**
 * Get the DF security level from SDP security level.
 */
sev_status_t get_df_sec_level(uint32_t sdp_sec_level, uint32_t *df_sec_level);


#endif /* DF_REGS_H */
