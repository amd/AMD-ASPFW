// Copyright(C) 2016-2022 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_hal_iommu.h"
#include "sev_plat.h"

/**
 * For new platforms, check EVERY single register to make sure it didn't change.
 * Check every single base address, NBIO shift (changed between Milan and Genoa), etc.
 */

/* IOMMUL2BPSP BASE Registers (Find in HDT) */
#define IOMMUL2BPSP_BASE_ADDRESS            (0x13FFE000)    /* 0x13FFE000 for NBIO0, 0x141FE000 for NBIO1, etc. */
/* There are two physical NBIOs but logically there are 4 for IOMMUMMIO, so addresses are
   0x13FFE0000, 0x140FE000 for NBIO0, and 0x141FE000, 0x142FE000  for NBIO 1*/
#define IOMMUL2BPSP_NBIO_SHIFT              (20)            /* 0x140FE000 - 0x13FFE000 = 0x100000 */

/* IOMMUL2::VMGUARDIO_CNTRL_0 Register */
#define IOMMUL2B_VMGUARDIO_CNTRL_0_OFFSET   (0x1E0)
#define IOMMUL2B_VMGUARDIO_VMPL_EN_MASK     (1 << 8)
#define IOMMUL2B_VMGUARDIO_SNP_EN_MASK      (1 << 7)

/* IOMMUL2::RMPTABLE_BASE_LO Register */
#define IOMMUL2B_RMP_TABLE_BASE_LO_OFFSET    (0x5F0)
#define IOMMUL2B_RMP_TABLE_BASE_LO_OFFSET32  (IOMMUL2B_RMP_TABLE_BASE_LO_OFFSET / 4)
#define IOMMUL2B_RMP_TABLE_BASE_HI_OFFSET    (0x5F4)
#define IOMMUL2B_RMP_TABLE_BASE_HI_OFFSET32  (IOMMUL2B_RMP_TABLE_BASE_HI_OFFSET / 4)
#define IOMMUL2B_RMP_TABLE_END_LO_OFFSET     (0x5F8)
#define IOMMUL2B_RMP_TABLE_END_LO_OFFSET32   (IOMMUL2B_RMP_TABLE_END_LO_OFFSET / 4)
#define IOMMUL2B_RMP_TABLE_END_HI_OFFSET     (0x5FC)
#define IOMMUL2B_RMP_TABLE_END_HI_OFFSET32   (IOMMUL2B_RMP_TABLE_END_HI_OFFSET / 4)

/* IOMMUMMIO Base Defines (Find in HDT) */
#define IOMMUMMIO_BASE_ADDRESS              (0x02400000)    /* 0x02400000 for NBIO0, 0x02600000 for NBIO1, etc */
/* There are two physical NBIOs but logically there are 4 for IOMMUMMIO, so addresses are
   0x02400000, 0x02500000 for NBIO0, and 0x026000000, 0x027000000 for NBIO 1*/
#define IOMMUMMIO_NBIO_SHIFT                (20)            /* 0x02500000 - 0x02400000 = 0x100000 */

/* IOMMUMMIO::IOMMU_MMIO_CNTRL_0 Register */
#define IOMMUMMIO_MMIO_CNTRL_0_OFFSET       (0x0018)
#define IOMMUMMIO_MMIO_CNTRL_0_OFFSET32     (IOMMUMMIO_MMIO_CNTRL_0_OFFSET / 4)
#define IOMMUMMIO_IOMMU_EN_MASK             (1 << 0)
#define IOMMUMMIO_EVENT_LOG_EN_MASK         (1 << 2)
#define IOMMUMMIO_CMD_BUF_EN_MASK           (1 << 12)
#define IOMMUMMIO_PPR_LOG_EN_MASK           (1 << 13)
#define IOMMUMMIO_PPR_Q_SHIFT               (30)
#define IOMMUMMIO_PPR_Q_MASK                (0x3UL << IOMMUMMIO_PPR_Q_SHIFT)

/* IOMMUMMIO::IOMMU_MMIO_CNTRL_1 Register */
#define IOMMUMMIO_MMIO_CNTRL_1_OFFSET       (0x001C)
#define IOMMUMMIO_MMIO_CNTRL_1_OFFSET32     (IOMMUMMIO_MMIO_CNTRL_1_OFFSET / 4)
#define IOMMUMMIO_EVENT_QUEUE_MASK          (0x3 << 0)

/* IOMMUMMIO::IOMMU_MMIO_EFR_1 Register */
#define IOMMUMMIO_MMIO_EFR_1_OFFSET         (0x0034)
#define IOMMUMMIO_MMIO_EFR_1_OFFSET32       (IOMMUMMIO_MMIO_EFR_1_OFFSET / 4)
#define IOMMUMMIO_MMIO_SNP_SUP_MASK         (1ull << 31)


/* IOMMUL2::SHDW Base Defines (Find in HDT) */
#define IOMMUL2ASHDW_BASE_ADDRESS            (0x15704000)   /* 0x15704000 for NBIO0, 0x15904000 for NBIO1, etc */
/* There are two physical NBIOs but logically there are 4 for IOMMUL2ASHDW , so addresses are
   0x15704000, 0x15804000 for NBIO0, and 0x15904000, 0x15A04000 for NBIO 1*/
#define IOMMUL2ASHDW_NBIO_SHIFT              (20)           /* 0x15904000 - 0x15704000 = 0x100000 */

/* IOMMUL2::SHDWL2A_IOMMU_MMIO_CNTRL_0 Register */
#define SHDWL2A_IOMMU_MMIO_CNTRL_0_OFFSET   (0x18)
#define SHDWL2A_IOMMU_MMIO_CNTRL_0_OFFSET32 (SHDWL2A_IOMMU_MMIO_CNTRL_0_OFFSET / 4)
#define SHDWL2A_IOMMU_MMIO_CNTRL_0_IOMMU_EN (1 << 0)


/* IOMMUL2ACFG Base Config - has same offset as Shadow (Find in HDT) */
#define IOMMUL2ACFG_BASE_ADDRESS            (0x15700000)    /* 0x15700000 for NBIO0, 0x15900000 for NBIO1, etc */
/* There are two physical NBIOs but logically there are 4 for IOMMUL2ASHDW , so addresses are
   0x15700000, 0x15800000 for NBIO0, and 0x15900000, 0x15A00000 for NBIO 1*/
#define IOMMUL2ACFG_NBIO_SHIFT              (20)            /* 0x15800000 - 0x15700000 = 0x100000 */

/* IOMMUL2::L2_ECO_CNTRL_0 Register */
#define IOMMUL2ACFG_L2_ECO_CNTRL_0_OFFSET         (0x108)
#define IOMMUL2ACFG_L2_ECO_CNTRL_0_OFFSET32       (IOMMUL2ACFG_L2_ECO_CNTRL_0_OFFSET/4)
#define IOMMUL2ACFG_L2_ECO_CNTRL_0_ENABLE         (1 << 0)

/**
 * L1_PERF_CNTL Regs --
 *     There are three section per NBIO. IOAGR, PCIE0, PCIE1.
 *     IOAGR: 0x1530_0000 .. 0x1550_0000... for each NBIO
 *     PCIE0: 0x1470_0000    0x14B0_0000    for each NBIO
 *     PCIE1: 0x14B0_0000 ...0x14C0_0000    for each NBIO
 * Find in HDT - PPR::IOMMUL1 and move selector at bottom
 */
#define IOMMUL1IOAGR_BASE_ADDRESS                (0x15300000)   /* 0x15300000 for NBIO0, 0x15500000 for NBIO1, etc */
#define IOMMUL1PCIE0_BASE_ADDRESS                (0x14700000)
#define IOMMUL1PCIE1_BASE_ADDRESS                (0x14B00000)
/* There are two physical NBIOs but logically there are 4 for IOMMUL1s, so addresses are
   0x15300000, 0x15400000 for NBIO0, and 0x15500000, 0x15600000 for NBIO 1 for IOAGR */
#define IOMMUL1_NBIO_SHIFT                       (20)           /* 0x15400000 - 0x15300000 = 0x100000 */

/* IOMMUL1::L1_GUEST_ADDR_CNTRL Register */
#define IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET       (0xD8)
#define IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET32     (IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET / 4)
#define IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE       (1 << 0)

/* IOMMUL1::L1_FEATURE_SUP_CNTRL Register */
#define IOMMUL1_L1_FEATURE_SUP_CNTRL_OFFSET      (0xDC)
#define IOMMUL1_L1_FEATURE_SUP_CNTRL_OFFSET32    (IOMMUL1_L1_FEATURE_SUP_CNTRL_OFFSET / 4)
#define IOMMUL1_L1_FEATURE_GT_SUP_W              (1 << 4)

/* IOMMUL1::SHDWL1_IOMMU_MMIO_CNTRL_0 Register */
#define IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_OFFSET   (0x4018)
#define IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_OFFSET32 (IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_OFFSET / 4)
#define IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_IOMMU_EN (1 << 0)


/* Base Registers for Protection Ranges */
/* IOMMUMMIO::IOMMU_MMIO_EVENT_BASE_0 Register */
#define IOMMUMMIO_MMIO_EVENT_BASE_0_OFFSET         (0x10)
#define IOMMUMMIO_MMIO_EVENT_BASE_0_OFFSET32       (IOMMUMMIO_MMIO_EVENT_BASE_0_OFFSET / 4)

/* IOMMUMMIO::IOMMU_MMIO_EVENT_BASE_1 Register */
#define IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET         (0x14)
#define IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET32       (IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET / 4)

/* EVENT BASE Masks */
#define IOMMUMMIO_MMIO_EVENT_BASE_LO_MASK          (0xFFFFF000)

/* EVENT LEN (bit 24:27). 0000b-0001b = Reserved. 1000b = 256 entries (4k) 1001b = 8k */
/* Each entry is 16 bytes. Algo for bytes: (1 << (len+4)) */
#define IOMMUMMIO_MMIO_EVENT_LENGTH(x)             (1UL << (x + 4))
#define IOMMUMMIO_MMIO_EVENT_LEN_SHIFT             (24)
#define IOMMUMMIO_MMIO_EVENT_LEN_MASK              (0xf << IOMMUMMIO_MMIO_EVENT_LEN_SHIFT)
#define IOMMUMMIO_MMIO_EVENT_LEN_MIN               (1UL << 3)

#define IOMMUMMIO_MMIO_EVENT_BASE_HI_SHIFT         (32)
#define IOMMUMMIO_MMIO_EVENT_BASE_HI_MASK          (0xFFFFF)

/* IOMMU_MMIO_EXCL_BASE Ranges */
/* IOMMUMMIO::IOMMU_MMIO_EXCL_BASE_0 Register */
#define IOMMUMMIO_EXCL_BASE_0_OFFSET               (0x20)
#define IOMMUMMIO_EXCL_BASE_0_OFFSET32             (IOMMUMMIO_EXCL_BASE_0_OFFSET / 4)
#define IOMMUMMIO_EXCL_BASE_0_LO_MASK              (0xFFFFF000)

/* IOMMUMMIO::IOMMU_MMIO_EXCL_BASE_1 Register */
#define IOMMUMMIO_EXCL_BASE_1_OFFSET               (0x24)
#define IOMMUMMIO_EXCL_BASE_1_OFFSET32             (IOMMUMMIO_EXCL_BASE_1_OFFSET / 4)
#define IOMMUMMIO_EXCL_BASE_1_HI_SHIFT             (32)
#define IOMMUMMIO_EXCL_BASE_1_HI_MASK              (0xFFFFF)

/* IOMMUMMIO::IOMMU_MMIO_EXCL_LIM_0 Register */
#define IOMMUMMIO_EXCL_LIM_0_OFFSET                (0x28)
#define IOMMUMMIO_EXCL_LIM_0_OFFSET32              (IOMMUMMIO_EXCL_LIM_0_OFFSET / 4)
#define IOMMUMMIO_EXCL_LIM_0_LO_MASK               (0xFFFFF000)

/* IOMMUMMIO::IOMMU_MMIO_EXCL_LIM_1 Register */
#define IOMMUMIMO_EXCL_LIM_1_OFFSET                (0x2C)
#define IOMMUMMIO_EXCL_LIM_1_OFFSET32              (IOMMUMIMO_EXCL_LIM_1_OFFSET / 4)
#define IOMMUMMIO_EXCL_LIM_1_HI_SHIFT              (32)
#define IOMMUMMIO_EXCL_LIM_1_HI_MASK               (0xFFFFF)


/* IOMMU_MMIO_PPR_BASE A Ranges */
/* IOMMUMMIO::IOMMU_MMIO_PPR_BASE_0 Register */
#define IOMMUMMIO_PPR_BASE_0_OFFSET                (0x38)
#define IOMMUMMIO_PPR_BASE_0_OFFSET32              (IOMMUMMIO_PPR_BASE_0_OFFSET / 4)
#define IOMMUMMIO_PPR_BASE_0_LO_MASK               (0xFFFFF000)

/* IOMMUMMIO::IOMMU_MMIO_PPR_BASE_1 Register */
#define IOMMUMMIO_PPR_BASE_1_OFFSET                (0x3C)
#define IOMMUMMIO_PPR_BASE_1_OFFSET32              (IOMMUMMIO_PPR_BASE_1_OFFSET / 4)

#define IOMMUMMIO_PPR_BASE_1_HI_SHIFT              (32)
#define IOMMUMMIO_PPR_BASE_1_HI_MASK               (0xFFFFF)

#define IOMMUMMIO_PPR_BASE_1_LENGTH(x)             (1UL << (x + 4))
#define IOMMUMMIO_PPR_BASE_1_LEN_SHIFT             (24)
#define IOMMUMMIO_PPR_BASE_1_LEN_MASK              (0xf << IOMMUMMIO_PPR_BASE_1_LEN_SHIFT)
#define IOMMUMMIO_PPR_BASE_1_LEN_MIN               (1UL << 3)


/* IOMMU_MMIO_PPR_B_BASE Range */
/* IOMMUMMIO::IOMMU_MMIO_PPR_B_BASE_0 Register */
#define IOMMUMMIO_PPR_B_BASE_0_OFFSET              (0xF0)
#define IOMMUMMIO_PPR_B_BASE_0_OFFSET32            (IOMMUMMIO_PPR_B_BASE_0_OFFSET / 4)

#define IOMMUMMIO_PPR_B_BASE_0_LO_MASK             (0xFFFFF000)

/* IOMMUMMIO::IOMMU_MMIO_PPR_B_BASE_1 Register */
#define IOMMUMMIO_PPR_B_BASE_1_OFFSET              (0xF4)
#define IOMMUMMIO_PPR_B_BASE_1_OFFSET32            (IOMMUMMIO_PPR_B_BASE_1_OFFSET / 4)

#define IOMMUMMIO_PPR_B_BASE_1_HI_SHIFT            (32)
#define IOMMUMMIO_PPR_B_BASE_1_HI_MASK             (0xFFFFF)

#define IOMMUMMIO_PPR_B_BASE_1_LENGTH(x)           (1UL << (x + 4))
#define IOMMUMMIO_PPR_B_BASE_1_LEN_SHIFT           (24)
#define IOMMUMMIO_PPR_B_BASE_1_LEN_MASK            (0xf << IOMMUMMIO_PPR_B_BASE_1_LEN_SHIFT)
#define IOMMUMMIO_PPR_B_BASE_1_LEN_MIN             (1UL << 3)


/* IOMMU MMIO EVENT B BASE Range */
/* IOMMUMMIO::IOMMU_MMIO_EVENT_B_BASE_0 Register */
#define IOMMUMMIO_EVENT_B_BASE_0_OFFSET            (0xF8)
#define IOMMUMMIO_EVENT_B_BASE_0_OFFSET32          (IOMMUMMIO_EVENT_B_BASE_0_OFFSET / 4)

#define IOMMUMMIO_EVENT_B_BASE_0_LO_MASK           (0xFFFFF000)

/* IOMMUMMIO::IOMMU_MMIO_EVENT_B_BASE_1 Register */
#define IOMMUMMIO_EVENT_B_BASE_1_OFFSET            (0xFC)
#define IOMMUMMIO_EVENT_B_BASE_1_OFFSET32          (IOMMUMMIO_EVENT_B_BASE_1_OFFSET / 4)

#define IOMMUMMIO_EVENT_B_BASE_1_HI_SHIFT          (32)
#define IOMMUMMIO_EVENT_B_BASE_1_HI_MASK           (0xFFFFF)

#define IOMMUMMIO_EVENT_B_BASE_1_LENGTH(x)         (1UL << (x + 4))
#define IOMMUMMIO_EVENT_B_BASE_1_LEN_SHIFT         (24)
#define IOMMUMMIO_EVENT_B_BASE_1_LEN_MASK          (0xf << IOMMUMMIO_EVENT_B_BASE_1_LEN_SHIFT)
#define IOMMUMMIO_EVENT_B_BASE_1_LEN_MIN           (1UL << 3)

/* Harvesting related definitions. These names match fuse names, but are really
 * indicies in to the SkipRSMU table set up by the on-die Boot ROM. The on-die
 * boot ROM name for the index is given to the right of the value defined to provide
 * a connection. The on-die Boot ROM file is bootcode/src/firmware/rsmu_config.h.
 * The source in the on-die Boot ROM that maps fuses to entries in the SkipRSMU
 * table is bootcode/src/firmware/src/harvest.c. */
#include "rom_rsmu.h"

#define NBIO_IOMMU0_HARVEST                         BC__RSMU_L2IMU0_LOGICAL_ID
#define NBIO_IOMMU1_HARVEST                         BC__RSMU_L2IMU1_LOGICAL_ID
#define NBIO_IOMMU2_HARVEST                         BC__RSMU_L2IMU2_LOGICAL_ID
#define NBIO_IOMMU3_HARVEST                         BC__RSMU_L2IMU3_LOGICAL_ID

/* L1IOMMU IOAGR uses NBIO_NB2_0_HARVEST which maps to BC__RSMU_L1IMUIOAGR0_LOGICAL_ID
 * and up and is contiguous.
 */
#define NBIO_L1IMUIOAGR0_HARVEST                    BC__RSMU_L1IMUIOAGR0_LOGICAL_ID

/* For L1 IOMMU, the mapping is
 *
 * NBIO_L1_PCIE_0_0_HARVEST    L1IMUPCIE0  0x14700000
 * NBIO_L1_PCIE_0_1_HARVEST    L1IMUPCIE4  0x14B00000
 * NBIO_L1_PCIE_0_2_HARVEST    L1IMUPCIE1  0x14800000
 * NBIO_L1_PCIE_0_3_HARVEST    L1IMUPCIE5  0x14C00000
 * NBIO_L1_PCIE_1_0_HARVEST    L1IMUPCIE2  0x14900000
 * NBIO_L1_PCIE_1_1_HARVEST    L1IMUPCIE6  0x14D00000
 * NBIO_L1_PCIE_1_2_HARVEST    L1IMUPCIE3  0x14A00000
 * NBIO_L1_PCIE_1_3_HARVEST    L1IMUPCIE7  0x14E00000
 *
 * Note logically it is in order to BC__RSMU_L1IMUPCIE0_LOGICAL_ID..BC__RSMU_L1IMUPCIE7_LOGICAL_ID
 * And since the fw goes into these in the order of addresses, we'll do the same for harvesting.
 *
 * #define IOMMUL1PCIE0_BASE_ADDRESS                (0x14700000) is equivalent to L1IMUPCIE0..3 addresses
 * #define IOMMUL1PCIE1_BASE_ADDRESS                (0x14B00000) is equivalent to L1IMUPCIE4..7 addresses
 *
 */
#define L1IMUPCIE0_HARVEST                        BC__RSMU_L1IMUPCIE0_LOGICAL_ID
#define L1IMUPCIE4_HARVEST                        BC__RSMU_L1IMUPCIE4_LOGICAL_ID

static inline bool skip_rsmu(size_t offset)
{
    return gPersistent.skip_rsmus[offset];
}

static uint32_t iommul2bpsp_base_address(uint32_t nbio, uint32_t offset)
{
    uint32_t address = IOMMUL2BPSP_BASE_ADDRESS;
    address += (nbio << IOMMUL2BPSP_NBIO_SHIFT) + offset;
    return address;
}

static uint32_t iommummio_base_address(uint32_t nbio, uint32_t offset)
{
    uint32_t address = IOMMUMMIO_BASE_ADDRESS;
    address += (nbio << IOMMUMMIO_NBIO_SHIFT) + offset;
    return address;
}

static uint32_t iommul2shdw_base_address(uint32_t nbio, uint32_t offset)
{
    uint32_t address = IOMMUL2ASHDW_BASE_ADDRESS;
    address += (nbio << IOMMUL2ASHDW_NBIO_SHIFT) + offset;
    return address;
}

static uint32_t iommul2acfg_base_address(uint32_t nbio, uint32_t offset)
{
    uint32_t address = IOMMUL2ACFG_BASE_ADDRESS;
    address += (nbio << IOMMUL2ACFG_NBIO_SHIFT) + offset;
    return address;
}

static uint32_t iommul1_base_address(uint32_t nbio, uint32_t sub_base_addr, uint32_t offset)
{
    uint32_t address = sub_base_addr;
    address += (nbio << IOMMUL1_NBIO_SHIFT) + offset;
    return address;
}


/**
 * The flow of calls in the file needs to be very specific to prevent race
 * conditions where x86 could change IOMMU settings after we set/validate them.
 * Steps:
 * 1. Firmware writes any registers needed which get locked after SNP_EN is set (check_iommu_event_logs)
 * 2. Set SNP_EN (enable_snp_iommu)
 * 3. Validate all the settings set by x86 (validate_snp_iommu)
 * 4. Set all enabled log pages to FIRMWARE_IOMMU state (set_iommu_table_state)
 *    check that any log pages still not enabled are still set to -1 from (check_iommu_event_logs)
 */

/**
 * Steps 1-4 of 15.5.1.2.6.3 Global SNP enablement
 */
sev_status_t enable_snp_iommu(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, nbio = 0;
    uint32_t addr = 0, data = 0;
    uint64_t iommu_rmp_table_base = 0;
    uint64_t iommu_rmp_table_end = 0;
    volatile uint32_t *axi_addr = NULL;

    /* No need to re-enable SNP IOMMU if it has already been enabled */
    if (gpDram->perm.snp_iommu_enabled)
        return status;

    /*
     * 1. Program RMP Table Base and Limit registers in IOMMUL2::RMPTABLE_BASE_LO[RMP_BASE_LO]
     *    and IOMMUL2::RMPTABLE_BASE_HI[RMP_BASE_HI].
     * Note: IOMMU RMP Table Start DOES NOT include counters. Starting location
     *       is after the counters space.
     * Note: IOMMU RMP Table End is aligned 8K. For example 0x4_041F_FFFF would be 0x4_041F_E000.
     */
    iommu_rmp_table_base = gpDram->perm.rmp_base + RMP_ASID_COUNTERS_SIZE;
    iommu_rmp_table_end = gpDram->perm.rmp_end & ~((uint64_t)PAGE_SIZE_4K * 2ull - 1ull);
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST + nbio))
                continue;
            addr = iommul2bpsp_base_address(nbio, 0);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            axi_addr[IOMMUL2B_RMP_TABLE_BASE_LO_OFFSET32] = (uint32_t)(iommu_rmp_table_base & 0xFFFFFFFFULL);
            axi_addr[IOMMUL2B_RMP_TABLE_BASE_HI_OFFSET32] = (uint32_t)(iommu_rmp_table_base >> 32ULL);
            axi_addr[IOMMUL2B_RMP_TABLE_END_LO_OFFSET32] = (uint32_t)(iommu_rmp_table_end);
            axi_addr[IOMMUL2B_RMP_TABLE_END_HI_OFFSET32] = (uint32_t)(iommu_rmp_table_end >> 32ULL);
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /* 2. Enable Global SNP and VMPL inside IOMMU L2B by programming
          IOMMUL2::VMGUARDIO_CNTRL_0[SNP_EN] = 1 and IOMMUL2::VMGUARDIO_CNTRL_0[VMPL_EN] = 1 */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST + nbio))
                continue;
            addr = iommul2bpsp_base_address(nbio, IOMMUL2B_VMGUARDIO_CNTRL_0_OFFSET);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            data = *axi_addr;
            data |= IOMMUL2B_VMGUARDIO_VMPL_EN_MASK;
            data |= IOMMUL2B_VMGUARDIO_SNP_EN_MASK;
            *axi_addr = data;
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /* 3. Enable Global SNP inside IOMMU L2A by programming IOMMUL2::L2_ECO_CNTRL_0[0] = 1 */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST + nbio))
                continue;
            addr = iommul2acfg_base_address(nbio, IOMMUL2ACFG_L2_ECO_CNTRL_0_OFFSET);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            *axi_addr |= IOMMUL2ACFG_L2_ECO_CNTRL_0_ENABLE;
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /*
     * 4. Enable Global SNP inside IOMMU L1 by programming IOMMUL1::L1_GUEST_ADDR_CNTRL[0] = 1
     *     for each IOMMU L1 present in the system
     */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (!skip_rsmu(NBIO_L1IMUIOAGR0_HARVEST + nbio))
            {
                /* IOAGR */
                addr = iommul1_base_address(nbio, IOMMUL1IOAGR_BASE_ADDRESS, IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                *axi_addr |= IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE;
                sev_hal_unmap_smn((void *)axi_addr);
            }

            if (!skip_rsmu(L1IMUPCIE0_HARVEST + nbio))
            {
                /* PCIE0 */
                addr = iommul1_base_address(nbio, IOMMUL1PCIE0_BASE_ADDRESS, IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                *axi_addr |= IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE;
                sev_hal_unmap_smn((void *)axi_addr);
            }

            if (!skip_rsmu(L1IMUPCIE4_HARVEST + nbio))
            {
                /* PCIE1 */
                addr = iommul1_base_address(nbio, IOMMUL1PCIE1_BASE_ADDRESS, IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                *axi_addr |= IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE;
                sev_hal_unmap_smn((void *)axi_addr);
            }
        }
    }

    gpDram->perm.snp_iommu_enabled = true;

end:
    return status;
}

/**
 * Steps 5 of PPR: 15.5.1.2.6.3 Global SNP enablement
 */
sev_status_t validate_snp_iommu(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, nbio = 0;
    uint32_t addr = 0, data = 0;
    volatile uint32_t *axi_addr = NULL;

    /*
     * Fail SNP Init if these are not set to their expected values
     *  1. IOMMUMMIO::IOMMU_MMIO_CNTRL_0[IOMMU_EN] must be 1
     *  2. IOMMUMMIO::IOMMU_MMIO_EFR_1[SNP_SUP] must be 1
     */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST+nbio))
                 continue;

            addr = iommummio_base_address(nbio, 0);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            data = axi_addr[IOMMUMMIO_MMIO_CNTRL_0_OFFSET32];
            if ((data & IOMMUMMIO_IOMMU_EN_MASK) == 0)
            {
                sev_hal_unmap_smn((void *)axi_addr);
                status = SEV_STATUS_HARDWARE_PLATFORM;
                goto end;
            }

            data = axi_addr[IOMMUMMIO_MMIO_EFR_1_OFFSET32];
            if ((data & IOMMUMMIO_MMIO_SNP_SUP_MASK) == 0)
            {
                sev_hal_unmap_smn((void *)axi_addr);
                status = SEV_STATUS_HARDWARE_PLATFORM;
                goto end;
            }
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /*
     *  8. IOMMUL2::SHDWL2A_IOMMU_MMIO_CNTRL_0[IOMMU_EN] must be 1
     */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST+nbio))
                continue;

            addr = iommul2shdw_base_address(nbio, 0);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            /* 8. IOMMUL2::SHDWL2A_IOMMU_MMIO_CNTRL_0[IOMMU_EN] must be 1 */
            if ((axi_addr[SHDWL2A_IOMMU_MMIO_CNTRL_0_OFFSET32] & SHDWL2A_IOMMU_MMIO_CNTRL_0_IOMMU_EN) == 0)
            {
                sev_hal_unmap_smn((void *)axi_addr);
                status = SEV_STATUS_HARDWARE_PLATFORM;
                goto end;
            }
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /* 15. IOMMUL1::SHDWL1_IOMMU_MMIO_CNTRL_0[IOMMU_EN] must be 1 for each IOMMU L1 present in the system */
    for (die = 0; die < gTotalDieNum; die++)
    {
        uint32_t shdwl1_iommu_mmio_cntrl_0 = IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_IOMMU_EN;
        /* ORing all the registers together, they must be all zero for L1_GT_SUP_W */
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (!skip_rsmu(NBIO_L1IMUIOAGR0_HARVEST + nbio))
            {
                /* IOAGR */
                addr = iommul1_base_address(nbio, IOMMUL1IOAGR_BASE_ADDRESS, IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                shdwl1_iommu_mmio_cntrl_0 &= *axi_addr;
                sev_hal_unmap_smn((void *)axi_addr);
            }

            if (!skip_rsmu(L1IMUPCIE0_HARVEST + nbio))
            {
                /* PCIE0 */
                addr = iommul1_base_address(nbio, IOMMUL1PCIE0_BASE_ADDRESS, IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                shdwl1_iommu_mmio_cntrl_0 &= *axi_addr;
                sev_hal_unmap_smn((void *)axi_addr);
            }

            if (!skip_rsmu(L1IMUPCIE4_HARVEST + nbio))
            {
                /* PCIE1 */
                addr = iommul1_base_address(nbio, IOMMUL1PCIE1_BASE_ADDRESS, IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                shdwl1_iommu_mmio_cntrl_0 &= *axi_addr;
                sev_hal_unmap_smn((void *)axi_addr);
            }
        }

        /* Must be enabled */
        if ((shdwl1_iommu_mmio_cntrl_0 & IOMMUL1_SHDWL1_IOMMU_MMIO_CNTRL_0_IOMMU_EN) == 0)
        {
            status = SEV_STATUS_HARDWARE_PLATFORM;
            goto end;
        }
    }

end:
    return status;
}

sev_status_t disable_snp_iommu(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, nbio = 0;
    uint32_t addr = 0, data = 0;
    volatile uint32_t *axi_addr = NULL;

    /* Disable Global SNP inside IOMMUL2BPSP -> IOMMUL2:VMGUARDIO_CNTRL_0[SNP_EN] = 0 */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST+nbio))
                continue;
            addr = iommul2bpsp_base_address(nbio, IOMMUL2B_VMGUARDIO_CNTRL_0_OFFSET);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            data = *axi_addr;
            // data &= ~(IOMMUL2B_VMGUARDIO_VMPL_EN_MASK);
            data &= ~(IOMMUL2B_VMGUARDIO_SNP_EN_MASK);
            *axi_addr = data;
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /*
     * Disable Global IOMMULA2 and L1 IOMMU_L2A::L2_ECO_CNTROL_0[0] = 0
     * and programming IOMMU_L1::L1_GUEST_ADDR_CNTRL[0] = 0
     * for each IOMMU L1 present in the system.
     */
    /* L2_ECO_CNTRL0 */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST+nbio))
                continue;
            addr = iommul2acfg_base_address(nbio, IOMMUL2ACFG_L2_ECO_CNTRL_0_OFFSET);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            *axi_addr &= ~(IOMMUL2ACFG_L2_ECO_CNTRL_0_ENABLE);
            sev_hal_unmap_smn((void *)axi_addr);
        }
    }

    /* L1_GUEST_ADDR_CNTRL */
    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
             if (!skip_rsmu(NBIO_L1IMUIOAGR0_HARVEST + nbio))
             {
                /* IOAGR */
                addr = iommul1_base_address(nbio, IOMMUL1IOAGR_BASE_ADDRESS, IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                *axi_addr &= ~(IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE);
                sev_hal_unmap_smn((void *)axi_addr);
            }

            if (!skip_rsmu(L1IMUPCIE0_HARVEST + nbio))
            {
                /* PCIE0 */
                addr = iommul1_base_address(nbio, IOMMUL1PCIE0_BASE_ADDRESS, IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                *axi_addr &= ~(IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE);
                sev_hal_unmap_smn((void *)axi_addr);
            }

            if (!skip_rsmu(L1IMUPCIE4_HARVEST + nbio))
            {
                /* PCIE1 */
                addr = iommul1_base_address(nbio, IOMMUL1PCIE1_BASE_ADDRESS, IOMMUL1_L1_GUEST_ADDR_CNTRL_OFFSET);
                status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                *axi_addr &= ~(IOMMUL1_L1_GUEST_ADDR_CNTRL_ENABLE);
                sev_hal_unmap_smn((void *)axi_addr);
            }
        }
    }

    gpDram->perm.snp_iommu_enabled = false;

end:
    return status;
}

/* Expecting a table_end that is aligned (ex 0x2000) and will -1ULL inside this function */
static sev_status_t set_iommu_table_state_work(snp_page_state_t page_state,
                                               uint64_t table_start, uint64_t table_end)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    static uint64_t entry_start = 0, entry_end = 0;

    table_end -= 1ULL;

    /* Check for overflow and that table_end is not less than table_start */
    if (table_end < table_start)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto end;
    }

    status = get_rmp_paddr(table_start, &entry_start);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = get_rmp_paddr(table_end, &entry_end);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (page_state == SNP_PAGE_STATE_FIRMWARE_IOMMU)
    {
        /* Add protection to the range */
        status = set_rmp_range_to_firmware_iommu_state(entry_start, entry_end);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /*
         * CSF-958, set overlap to true because this edge case:
         * Imagine having a 1MB RMP (that is 2MB aligned). Then put any of the
         * IOMMU pages in the 2nd MB. When the base 2MB page is checked against
         * the self-protecting RMP entries, it will hit one. So we DO want to
         * allow overlap here to be able tos et the subpage count of the base
         * 2MB page; there are no security risks here
         */
        status = set_rmp_sub_page_count(table_start, table_end, true);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Store page in global table to reclaim during SNP_SHUTDOWN_EX */
        if (gpDram->perm.iommu_entry_ctr >= MAX_IOMMU_TABLE_STATES)
        {
            status = ERR_OUT_OF_RESOURCES; /* Internal error */
            goto end;
        }
        gpDram->perm.iommu_entry_list_start[gpDram->perm.iommu_entry_ctr] = entry_start;
        gpDram->perm.iommu_entry_list_end[gpDram->perm.iommu_entry_ctr] = entry_end;
        gpDram->perm.iommu_entry_ctr++;
    }
    else
    {
        /* Disable protection to the range */
        status = set_rmp_range_to_hypervisor_state(entry_start, entry_end);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

end:
    return status;
}

/**
 * Sets any non-enabled log pages to -1. Note: these registers get must be set
 * before enable_snp_iommu() sets SNP_EN=1 to lock down the IOMMU.
 */
sev_status_t check_iommu_event_logs(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, nbio = 0;
    uint32_t addr = 0;
    volatile uint32_t *axi_addr = NULL;
    uint32_t control0_reg = 0, control1_reg = 0;

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST+nbio))
                 continue;
            addr = iommummio_base_address(nbio, 0);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            control0_reg = axi_addr[IOMMUMMIO_MMIO_CNTRL_0_OFFSET32];
            control1_reg = axi_addr[IOMMUMMIO_MMIO_CNTRL_1_OFFSET32];

            /* Event Log A */
            if ((control0_reg & IOMMUMMIO_EVENT_LOG_EN_MASK) == 0)
            {
                // If Enable Mask is not set, set the BAR address to -1
                axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_0_OFFSET32] |= IOMMUMMIO_MMIO_EVENT_BASE_LO_MASK;
                axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET32] |= IOMMUMMIO_MMIO_EVENT_BASE_HI_MASK;
            }

            /* Completion Wait */
            if ((control0_reg & IOMMUMMIO_CMD_BUF_EN_MASK) == 0)
            {
                // If Enable Mask is not set, set the BAR address to -1 with a 1 byte length
                axi_addr[IOMMUMMIO_EXCL_BASE_0_OFFSET32] |= IOMMUMMIO_EXCL_BASE_0_LO_MASK;
                axi_addr[IOMMUMMIO_EXCL_BASE_1_OFFSET32] |= IOMMUMMIO_EXCL_BASE_1_HI_MASK;
            }

            /* PPR Log A */
            if ((control0_reg & IOMMUMMIO_PPR_LOG_EN_MASK) == 0)
            {
                axi_addr[IOMMUMMIO_PPR_BASE_0_OFFSET32] |= IOMMUMMIO_PPR_BASE_0_LO_MASK;
                axi_addr[IOMMUMMIO_PPR_BASE_1_OFFSET32] |= IOMMUMMIO_PPR_BASE_1_HI_MASK;
            }

            /* PPR Log B (PPRQ) */
            if ((control0_reg & IOMMUMMIO_PPR_Q_MASK) == 0)
            {
                axi_addr[IOMMUMMIO_PPR_B_BASE_0_OFFSET32] |= IOMMUMMIO_PPR_B_BASE_0_LO_MASK;
                axi_addr[IOMMUMMIO_PPR_B_BASE_1_OFFSET32] |= IOMMUMMIO_PPR_B_BASE_1_HI_MASK;
            }

            /* Event Log B */
            if ((control1_reg & IOMMUMMIO_EVENT_QUEUE_MASK) == 0)
            {
                axi_addr[IOMMUMMIO_EVENT_B_BASE_0_OFFSET32] |= IOMMUMMIO_EVENT_B_BASE_0_LO_MASK;
                axi_addr[IOMMUMMIO_EVENT_B_BASE_1_OFFSET32] |= IOMMUMMIO_EVENT_B_BASE_1_HI_MASK;
            }

            sev_hal_unmap_smn((void *)axi_addr);
            axi_addr = NULL;
        }
    }

end:
    if (axi_addr != NULL)
        sev_hal_unmap_smn((void *)axi_addr);

    return status;
}

/**
 * Sets all enabled log pages to the FIRMWARE_IOMMU state.
 * Must be called after enable_snp_iommu() (SNP_EN=1 is set in the IOMMU to lock it).
 * Confirms that any non-enabled logs are set to -1 (check_iommu_event_logs()).
 *  If not, fail immediately. For all security details about this, see SEV FW MAS.
 */
sev_status_t set_iommu_table_state(snp_page_state_t page_state)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t die = 0, nbio = 0;
    uint32_t addr = 0;
    volatile uint32_t *axi_addr = NULL;
    uint32_t control0_reg = 0, control1_reg = 0;
    static uint64_t table_start = 0, table_end = 0;
    uint32_t upper32_addr = 0;
    static uint32_t length = 0;

    if (page_state != SNP_PAGE_STATE_HYPERVISOR && page_state != SNP_PAGE_STATE_FIRMWARE_IOMMU)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Clear the iommu_table_list */
    memset(gpDram->perm.iommu_entry_list_start, 0, sizeof(gpDram->perm.iommu_entry_list_start));
    memset(gpDram->perm.iommu_entry_list_end, 0, sizeof(gpDram->perm.iommu_entry_list_end));
    gpDram->perm.iommu_entry_ctr = 0;

    for (die = 0; die < gTotalDieNum; die++)
    {
        for (nbio = 0; nbio < MAX_NBIO; nbio++)
        {
            if (skip_rsmu(NBIO_IOMMU0_HARVEST+nbio))
                continue;

            addr = iommummio_base_address(nbio, 0);
            status = sev_hal_map_smn_on_die(addr, (void **)&axi_addr, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            control0_reg = axi_addr[IOMMUMMIO_MMIO_CNTRL_0_OFFSET32];
            control1_reg = axi_addr[IOMMUMMIO_MMIO_CNTRL_1_OFFSET32];

            /* Event Log A */
            if (control0_reg & IOMMUMMIO_EVENT_LOG_EN_MASK)
            {
                table_start = (uint64_t)(axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_0_OFFSET32] & IOMMUMMIO_MMIO_EVENT_BASE_LO_MASK);
                upper32_addr = (axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET32] & IOMMUMMIO_MMIO_EVENT_BASE_HI_MASK);
                table_start |= (uint64_t)(upper32_addr) << IOMMUMMIO_MMIO_EVENT_BASE_HI_SHIFT;

                length = axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET32] & IOMMUMMIO_MMIO_EVENT_LEN_MASK;
                length >>= IOMMUMMIO_MMIO_EVENT_LEN_SHIFT;
                length = IOMMUMMIO_MMIO_EVENT_LENGTH(length);
                if (length < IOMMUMMIO_MMIO_EVENT_LEN_MIN)
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }

                table_end = table_start + length;

                status = set_iommu_table_state_work(page_state, table_start, table_end);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_config;
            }
            else
            {
                // If Enable Mask is not set, make sure the BAR address is still -1 from check_iommu_event_logs()
                if (((axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_0_OFFSET32] & IOMMUMMIO_MMIO_EVENT_BASE_LO_MASK) != IOMMUMMIO_MMIO_EVENT_BASE_LO_MASK) ||
                    ((axi_addr[IOMMUMMIO_MMIO_EVENT_BASE_1_OFFSET32] & IOMMUMMIO_MMIO_EVENT_BASE_HI_MASK) != IOMMUMMIO_MMIO_EVENT_BASE_HI_MASK))
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }
            }

            /* Completion Wait */
            if (control0_reg & IOMMUMMIO_CMD_BUF_EN_MASK)
            {
                /* Exclusion Range BASE and LIMIT can be the same value.
                   If base is 0x1000, LIMIT is 0x2000 it actually covers 0x1000 to 0x2FFF */
                table_start = (uint64_t)(axi_addr[IOMMUMMIO_EXCL_BASE_0_OFFSET32] & IOMMUMMIO_EXCL_BASE_0_LO_MASK);
                upper32_addr = (axi_addr[IOMMUMMIO_EXCL_BASE_1_OFFSET32] & IOMMUMMIO_EXCL_BASE_1_HI_MASK);
                table_start |= (uint64_t)(upper32_addr) << IOMMUMMIO_EXCL_BASE_1_HI_SHIFT;

                table_end = (uint64_t)(axi_addr[IOMMUMMIO_EXCL_LIM_0_OFFSET32] & IOMMUMMIO_EXCL_LIM_0_LO_MASK);
                upper32_addr = (axi_addr[IOMMUMMIO_EXCL_LIM_1_OFFSET32] & IOMMUMMIO_EXCL_LIM_1_HI_MASK);
                table_end |= (uint64_t)(upper32_addr) << IOMMUMMIO_EXCL_LIM_1_HI_SHIFT;

                /* Exclusion Range End - needs to add one more page to complete the actual coverage */
                table_end += PAGE_SIZE_4K;

                status = set_iommu_table_state_work(page_state, table_start, table_end);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_config;
            }
            else
            {
                // If Enable Mask is not set, make sure the BAR address is still -1 from check_iommu_event_logs()
                if (((axi_addr[IOMMUMMIO_EXCL_BASE_0_OFFSET32] & IOMMUMMIO_EXCL_BASE_0_LO_MASK) != IOMMUMMIO_EXCL_BASE_0_LO_MASK) ||
                    ((axi_addr[IOMMUMMIO_EXCL_BASE_1_OFFSET32] & IOMMUMMIO_EXCL_BASE_1_HI_MASK) != IOMMUMMIO_EXCL_BASE_1_HI_MASK))
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }
            }

            /* PPR Log A */
            if (control0_reg & IOMMUMMIO_PPR_LOG_EN_MASK)
            {
                table_start = (uint64_t)(axi_addr[IOMMUMMIO_PPR_BASE_0_OFFSET32] & IOMMUMMIO_PPR_BASE_0_LO_MASK);
                upper32_addr = (axi_addr[IOMMUMMIO_PPR_BASE_1_OFFSET32] & IOMMUMMIO_PPR_BASE_1_HI_MASK);
                table_start |= (uint64_t)(upper32_addr) << IOMMUMMIO_PPR_BASE_1_HI_SHIFT;

                length = axi_addr[IOMMUMMIO_PPR_BASE_1_OFFSET32] & IOMMUMMIO_PPR_BASE_1_LEN_MASK;
                length >>= IOMMUMMIO_PPR_BASE_1_LEN_SHIFT;
                /* Length in bytes */
                length = IOMMUMMIO_PPR_BASE_1_LENGTH(length);
                if (length < IOMMUMMIO_PPR_BASE_1_LEN_MIN)
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }

                table_end = table_start + length;

                status = set_iommu_table_state_work(page_state, table_start, table_end);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_config;
            }
            else
            {
                // If Enable Mask is not set, make sure the BAR address is still -1 from check_iommu_event_logs()
                if (((axi_addr[IOMMUMMIO_PPR_BASE_0_OFFSET32] & IOMMUMMIO_PPR_BASE_0_LO_MASK) != IOMMUMMIO_PPR_BASE_0_LO_MASK) ||
                    ((axi_addr[IOMMUMMIO_PPR_BASE_1_OFFSET32] & IOMMUMMIO_PPR_BASE_1_HI_MASK) != IOMMUMMIO_PPR_BASE_1_HI_MASK))
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }
            }

            /* PPR Log B (PPRQ) */
            if (control0_reg & IOMMUMMIO_PPR_Q_MASK)
            {
                table_start = (uint64_t)(axi_addr[IOMMUMMIO_PPR_B_BASE_0_OFFSET32] & IOMMUMMIO_PPR_B_BASE_0_LO_MASK);
                upper32_addr = (axi_addr[IOMMUMMIO_PPR_B_BASE_1_OFFSET32] & IOMMUMMIO_PPR_B_BASE_1_HI_MASK);
                table_start |= (uint64_t)(upper32_addr) << IOMMUMMIO_PPR_B_BASE_1_HI_SHIFT;

                length = axi_addr[IOMMUMMIO_PPR_B_BASE_1_OFFSET32] & IOMMUMMIO_PPR_B_BASE_1_LEN_MASK;
                length >>= IOMMUMMIO_PPR_B_BASE_1_LEN_SHIFT;
                /* Length in bytes */
                length = IOMMUMMIO_PPR_B_BASE_1_LENGTH(length);
                if (length < IOMMUMMIO_PPR_B_BASE_1_LEN_MIN)
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }

                table_end = table_start + length;

                status = set_iommu_table_state_work(page_state, table_start, table_end);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_config;
            }
            else
            {
                // If Enable Mask is not set, make sure the BAR address is still -1 from check_iommu_event_logs()
                if (((axi_addr[IOMMUMMIO_PPR_B_BASE_0_OFFSET32] & IOMMUMMIO_PPR_B_BASE_0_LO_MASK) != IOMMUMMIO_PPR_B_BASE_0_LO_MASK) ||
                    ((axi_addr[IOMMUMMIO_PPR_B_BASE_1_OFFSET32] & IOMMUMMIO_PPR_B_BASE_1_HI_MASK) != IOMMUMMIO_PPR_B_BASE_1_HI_MASK))
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }
            }

            /* Event Log B */
            if (control1_reg & IOMMUMMIO_EVENT_QUEUE_MASK)
            {
                table_start = (uint64_t)(axi_addr[IOMMUMMIO_EVENT_B_BASE_0_OFFSET32] & IOMMUMMIO_EVENT_B_BASE_0_LO_MASK);
                upper32_addr = (axi_addr[IOMMUMMIO_EVENT_B_BASE_1_OFFSET32] & IOMMUMMIO_EVENT_B_BASE_1_HI_MASK);
                table_start |= (uint64_t)(upper32_addr) << IOMMUMMIO_EVENT_B_BASE_1_HI_SHIFT;

                length = axi_addr[IOMMUMMIO_EVENT_B_BASE_1_OFFSET32] & IOMMUMMIO_EVENT_B_BASE_1_LEN_MASK;
                length >>= IOMMUMMIO_EVENT_B_BASE_1_LEN_SHIFT;
                /* Length in bytes */
                length = IOMMUMMIO_EVENT_B_BASE_1_LENGTH(length);
                if (length < IOMMUMMIO_EVENT_B_BASE_1_LEN_MIN)
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }

                table_end = table_start + length;

                status = set_iommu_table_state_work(page_state, table_start, table_end);
                if (status != SEV_STATUS_SUCCESS)
                    goto exit_config;
            }
            else
            {
                // If Enable Mask is not set, make sure the BAR address is still -1 from check_iommu_event_logs()
                if (((axi_addr[IOMMUMMIO_EVENT_B_BASE_0_OFFSET32] & IOMMUMMIO_EVENT_B_BASE_0_LO_MASK) != IOMMUMMIO_EVENT_B_BASE_0_LO_MASK) ||
                    ((axi_addr[IOMMUMMIO_EVENT_B_BASE_1_OFFSET32] & IOMMUMMIO_EVENT_B_BASE_1_HI_MASK) != IOMMUMMIO_EVENT_B_BASE_1_HI_MASK))
                {
                    status = SEV_STATUS_INVALID_CONFIG;
                    goto exit_config;
                }
            }

            sev_hal_unmap_smn((void *)axi_addr);
            axi_addr = NULL;
        }
    }

    /* Set error to INVALID CONFIG for any user/driver programmed ranges */
exit_config:
    if (status != SEV_STATUS_SUCCESS)
        status = SEV_STATUS_INVALID_CONFIG;
end:
    if (axi_addr != NULL)
        sev_hal_unmap_smn((void *)axi_addr);

    return status;
}
