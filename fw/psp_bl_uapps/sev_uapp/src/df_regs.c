// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "df_regs.h"
#include "nist_kdf.h"
#include "secure_ops.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_scmd.h"

/* PPR: 13.3.4.1 indirect accesses */
#define DF_INDIRECT_ACCESS_INSTANCE_PSP  (0)

/**
 * FCAC (Fabric Config Access Control) Register
 * D18F4x040 [Fabric Configuration Access Control (FCAC)] (DF::FabricConfigAccessControl)
 */
#define FCAC_FUNC       (4)
#define FCAC_OFFSET     (0x40)

/**
 * FCAC register fields
 */
#define FCAC_INSTANCE_ID_SHIFT      (16)
#define FCAC_INSTANCE_ID_MASK       (0xFFul << (FCAC_INSTANCE_ID_SHIFT))
#define FCAC_INSTANCE_LOCK_SHIFT    (1)
#define FCAC_INSTANCE_LOCK_MASK     (1ul << (FCAC_INSTANCE_LOCK_SHIFT))
#define FCAC_INSTANCE_EN_SHIFT      (0)
#define FCAC_INSTANCE_EN_MASK       (1ul << (FCAC_INSTANCE_EN_SHIFT))

#define FCAC_ALL_FLAGS_MASK         ((FCAC_INSTANCE_LOCK_MASK) & \
                                     (FCAC_INSTANCE_EN_MASK))

/**
 * FICAA Register
 * D18F4x0[80...94] [Fabric Indirect Configuration Access Address (FICAA)]
 * (DF::FabricIndirectConfigAccessAddress)
 */
#define FICAA_FUNC          (4)
#define FICAA_OFFSET        (0x80) /* F4x80 of F4x[80 - 94] range */

/**
 * FICAA register fields
 */
#define FICAA_INSTANCE_SHIFT    (16)
#define FICAA_INSTANCE_MASK     (0xFFul << (FICAA_INSTANCE_SHIFT)) /* [23:16] */
#define FICAA_64BIT_SHIFT       (14)
#define FICAA_64BIT_FLAG        (1ul << (FICAA_64BIT_SHIFT))       /* [14] */
#define FICAA_FUNCTION_SHIFT    (11)
#define FICAA_FUNCTION_MASK     (0x7ul << (FICAA_FUNCTION_SHIFT))  /* [13:11] */
#define FICAA_REG_NUM_SHIFT     (1)
#define FICAA_REG_NUM_MASK      (0x3FFul << (FICAA_REG_NUM_SHIFT)) /* [10:1]  */
#define FICAA_SINGLE_SHIFT      (0)
#define FICAA_SINGLE_FLAG       (1ul << (FICAA_SINGLE_SHIFT))      /* [0] */

/* FICAD Register
 * DF::FabricIndirectConfigAccessDataLo and DF::FabricIndirectConfigAccessDataHi
 */
#define FICAD_FUNC          (4)
#define FICAD_OFFSET        (0xA0) /* F4xA0 of F4x0[A0 - C8] range */

/* PPR: Table 230: ValidValuesTable: Instance IDs for DF Components */
#define CNLI0_DF_INSTANCE_ID    (0x35)
#define CNLI1_DF_INSTANCE_ID    (0x36)
#define CNLI2_DF_INSTANCE_ID    (0x37)
#define CNLI3_DF_INSTANCE_ID    (0x38)

/* PPR: D18F6xC80 (DF::CnliAESIndex) */
#define CNLI_DF_FUNCTION_ID     (0x6)

#define CNLI_AES_INDEX_OFFSET   (0xC80)
#define CNLI_AES_DATA_OFFSET    (0xC84)

#define CNLI_KEY_ARRAY_AUTOINC_MASK (1ul << 31)

#define CNLI_KEY_LABEL    "sev-vm-encryption-key-1"

#define MAX_CNLI                    (4)

/**
 * Trusted memory region registers
 * http://twiki.amd.com/twiki/bin/view/DFArch/CoherentSlave#MAS
 * Genoa has 9 TMRs. TMR0 + 8 additional TMRs
 * There are 6 registers per TMR
 *      Offset 0xA00 = TmrBaseAddr0
 *      Offset 0xA04 = TmrLimitAddr0
 *      Offset 0xA08 = TmrCtl
 *      Offset 0xA0C = TmrFidA
 *      Offset 0xA10 = TmrFidB
 *      Offset 0xA14 = TmrExtAddr
 */
#define TMR_BASE_ADDR_OFFSET    (0xA00)   /* DF::TmrBaseAddr  */
#define TMR_LIMIT_ADDR_OFFSET   (0xA04)   /* DF::TmrLimitAddr */
#define TMR_CTL_OFFSET          (0xA08)   /* DF::TmrCtl       */
#define TMR_FIDA_OFFSET         (0xA0C)   /* DF::TmrFidA      */
#define TMR_FIDB_OFFSET         (0xA10)   /* DF::TmrFidB      */
#define TMR_EXT_ADDR_OFFSET     (0xA14)   /* DF::TmrExtAddr   */

#define TMR_OFFSET              (0x18)

#define TMR_TRUST_LVL_LSBS_SHIFT    (0)
#define TMR_TRUST_LVL_LSBS_MASK     (0xFul << (TMR_TRUST_LVL_LSBS_SHIFT))

#define TMR_TRUST_LVL_SHIFT         (17)
#define TMR_TRUST_LVL_MASK          (0x7 << TMR_TRUST_LVL_SHIFT)

#define TMR_ADDR_MASK               (0xFFFFFFFFull << TMR_X86_PHYS_ADDR_SHIFT)

/* DF::TmrExtAddr */
#define TMR_EXT_SHIFT               (48)
#define TMR_EXT_MASK                (0xFFull << TMR_EXT_SHIFT)
#define TMR_BASE_ADDR_EXT_SHIFT     (0)
#define TMR_BASE_ADDR_EXT_MASK      (0xFFull << TMR_BASE_ADDR_EXT_SHIFT)
#define TMR_LIMIT_ADDR_EXT_SHIFT    (16)
#define TMR_LIMIT_ADDR_EXT_MASK     (0xFFull << TMR_LIMIT_ADDR_EXT_SHIFT)

/**
 * PSP Misc Mode register
 * D18F6x408 [PSP Miscellaneous Modes] (DF::PspMiscMode)
 */
#define PSP_MISC_MODE_FUNC          (6)
#define PSP_MISC_MODE_OFFSET        (0x408)

/**
 * FtiSecLvlMapReg
 * D18F1x33C [FTI Security Level Mapping] (DF::FtiSecLvlMapReg)
 * 13.14.1.1 Data Fabric Register Security Operation
 */
#define FTI_SEC_LVL_MAP_REG_FUNC    (6)
#define FTI_SEC_LVL_MAP_REG_OFFSET  (0xDD0)

/**
 * C-State Control register
 * D18F5x300 [Cstate Control] (DF::CstateControl)
 */
#define CSTATE_CONTROL_FUNC                 (5)
#define CSTATE_CONTROL_OFFSET               (0x300)

#define CSTATE_CONTROL_DISABLE_SHIFT        (5)
#define CSTATE_CONTROL_DISABLE_FLAG         (1ul << (CSTATE_CONTROL_DISABLE_SHIFT))
#define CSTATE_CONTROL_CLIENTS_IDLE_SHIFT   (1)
#define CSTATE_CONTROL_CLIENTS_IDLE_FLAG    (1ul << (CSTATE_CONTROL_CLIENTS_IDLE_SHIFT))

#define CSTATE_ALWAYS_ON_FUNC               (0x5)
#define CSTATE_ALWAYS_ON_OFFSET_MIN         (0x300)
#define CSTATE_ALWAYS_ON_OFFSET_MAX         (0x3FF)

#define is_ficaa(function, offset)    \
    ((function) == (FICAA_FUNC) && (offset) == (FICAA_OFFSET))

#define is_ficad(function, offset)    \
    ((function) == (FICAD_FUNC) && (offset) == (FICAD_OFFSET))

#define all_clients_idle(cstate_flags)    \
    (((cstate_flags) & (CSTATE_CONTROL_CLIENTS_IDLE_FLAG)) > 0)

enum df_reg_op
{
    DF_REG_OP_READ32,
    DF_REG_OP_READ64,
    DF_REG_OP_WRITE32,
    DF_REG_OP_WRITE64,
};

/**
 * Access DF registers directly via SMN.
 *
 * If necessary, this function will wake the DF from C-state prior to
 * attempting the access.
 */
static sev_status_t access_df_reg_direct(uint32_t function, uint32_t offset,
                                         uint64_t *value, enum df_reg_op op)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t addr_smn = DF_SMN_ADDR(function, offset);
    void *addr_axi = NULL;

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Map SMN address to AXI */
    status = sev_hal_map_smn(addr_smn, &addr_axi);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    switch (op)
    {
    /*
     * 'value' is defined as uint64_t* to allow for both 32 and 64-bit
     * operations. However, if we don't cast it properly for 32-bit operations,
     * then we can corrupt nearby memory locations by writing a 64-bit value
     * into a 32-bit variable. Nasty.
     */
    case DF_REG_OP_READ32:
        *(uint32_t *)value = ReadReg32((uint32_t)addr_axi);
        break;
    case DF_REG_OP_WRITE32:
        WriteReg32((uint32_t)addr_axi, *(uint32_t *)value);
        break;
    case DF_REG_OP_READ64:
        *value = read_reg64(addr_axi);
        break;
    case DF_REG_OP_WRITE64:
        write_reg64(addr_axi, *value);
        break;
    default:
        status = ERR_INVALID_PARAMS;
        goto exit_unmap;
    }

    /* Ensure that the operation has completed before we return. */
    ARMCC_DSB_ISB();

exit_unmap:
    if (addr_axi)
        sev_hal_unmap_smn(addr_axi);
end:
    return status;
}

static sev_status_t get_cstate_control(uint32_t *flags)
{
    /*
     * CStateControl is in the always-on area of the PIE, so we don't need
     * to wake-up the DF here.
     */
    return access_df_reg_direct(CSTATE_CONTROL_FUNC, CSTATE_CONTROL_OFFSET,
                                (uint64_t *)flags, DF_REG_OP_READ32);
}

sev_status_t df_access_lock(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t flags = 0;

    /* Only allow issuing of DF C State Changes in Master.
       Master will issue command to the slave to disable C State */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        /*
         * DF CStates can be toggled asynchronously (e.g. via test scripts),
         * so always send the disable message (as recommended by the SMU FW team).
         */
        status = sev_hal_df_acquire();
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        status = get_cstate_control(&flags);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* If the DF is still not awake, then don't attempt to access it */
        if (all_clients_idle(flags))
        {
            status = SEV_STATUS_HARDWARE_PLATFORM;
            goto end;
        }

        /* Issue DF C State command to the slave */
        if (gTotalDieNum > 1)
        {
            sev_scmd_t cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.id = SEV_SCMD_ID_DF_ACQUIRE;
            status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

end:
    return status;
}

sev_status_t df_access_unlock(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Only allow release started by the Master.
       Master will issue command to the slave to Enable DF C State */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        status = sev_hal_df_release();
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        if (gTotalDieNum > 1)
        {
            sev_scmd_t cmd;
            memset(&cmd, 0, sizeof(cmd));
            cmd.id = SEV_SCMD_ID_DF_RELEASE;
            status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

end:
    return status;
}

static sev_status_t write_ficaa(uint32_t instance, uint32_t function,
                                uint32_t offset, uint32_t flags)
{
    uint32_t value = 0;
    uint32_t reg_index = offset/sizeof(uint32_t);
    value |= (instance << FICAA_INSTANCE_SHIFT) & FICAA_INSTANCE_MASK;
    value |= (function << FICAA_FUNCTION_SHIFT) & FICAA_FUNCTION_MASK;
    value |= (reg_index << FICAA_REG_NUM_SHIFT) & FICAA_REG_NUM_MASK;
    value |= flags;
    return access_df_reg_direct(FICAA_FUNC, FICAA_OFFSET, (uint64_t *)&value, DF_REG_OP_WRITE32);
}

static sev_status_t read_ficad32(uint32_t *value)
{
    return access_df_reg_direct(FICAD_FUNC, FICAD_OFFSET, (uint64_t *)value, DF_REG_OP_READ32);
}

static sev_status_t write_ficad32(uint32_t value)
{
    return access_df_reg_direct(FICAD_FUNC, FICAD_OFFSET, (uint64_t *)&value, DF_REG_OP_WRITE32);
}

static sev_status_t read_ficad64(uint64_t *value)
{
    return access_df_reg_direct(FICAD_FUNC, FICAD_OFFSET, value, DF_REG_OP_READ64);
}

static sev_status_t write_ficad64(uint64_t value)
{
    return access_df_reg_direct(FICAD_FUNC, FICAD_OFFSET, &value, DF_REG_OP_WRITE64);
}

static sev_status_t access_df_reg_indirect(uint8_t instance, uint32_t function,
                                           uint32_t offset, uint32_t flags,
                                           uint64_t *value, enum df_reg_op op)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* FICAA and FICAD should never be accessed indirectly */
    if (is_ficaa(function, offset) || is_ficad(function, offset))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = write_ficaa(instance, function, offset, flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    switch (op)
    {
    case DF_REG_OP_READ32:
        status = read_ficad32((uint32_t *)value);
        break;
    case DF_REG_OP_WRITE32:
        status = write_ficad32((uint32_t) *value);
        break;
    case DF_REG_OP_READ64:
        status = read_ficad64(value);
        break;
    case DF_REG_OP_WRITE64:
        status = write_ficad64(*value);
        break;
    default:
        status = ERR_INVALID_PARAMS;
    }

end:
    return status;
}

sev_status_t read_df_reg32(uint32_t instance, uint32_t function, uint32_t offset, uint32_t *value)
{
    return access_df_reg_direct(function, offset, (uint64_t *)value, DF_REG_OP_READ32);
}

sev_status_t read_df_reg64(uint32_t instance, uint32_t function, uint32_t offset, uint64_t *value)
{
    return access_df_reg_indirect(instance, function, offset,
                                  FICAA_SINGLE_FLAG|FICAA_64BIT_FLAG,
                                  value, DF_REG_OP_READ64);
}

sev_status_t write_df_reg32(uint32_t instance, uint32_t function, uint32_t offset, uint32_t value)
{
    return access_df_reg_direct(function, offset, (uint64_t *)&value, DF_REG_OP_WRITE32);
}

sev_status_t write_df_reg64(uint32_t instance, uint32_t function, uint32_t offset, uint64_t value)
{
    return access_df_reg_indirect(instance, function, offset,
                                  FICAA_SINGLE_FLAG|FICAA_64BIT_FLAG,
                                  &value, DF_REG_OP_WRITE64);
}

static sev_status_t read_fcac(uint32_t *instance, uint32_t *flags)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t value = 0;

    status = access_df_reg_direct(FCAC_FUNC, FCAC_OFFSET, (uint64_t *)&value,
                                  DF_REG_OP_READ32);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (instance)
        *instance = (value & FCAC_INSTANCE_ID_MASK) >> FCAC_INSTANCE_ID_SHIFT;
    if (flags)
        *flags = value & FCAC_ALL_FLAGS_MASK;

end:
    return status;
}

static sev_status_t write_fcac(uint32_t instance, uint32_t flags)
{
    uint32_t value = 0;

    value |= (instance << FCAC_INSTANCE_ID_SHIFT) & FCAC_INSTANCE_ID_MASK;
    value |= flags & FCAC_ALL_FLAGS_MASK;

    return access_df_reg_direct(FCAC_FUNC, FCAC_OFFSET, (uint64_t *)&value,
                                DF_REG_OP_WRITE32);
}

static sev_status_t enable_broadcast_mode(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t instance = 0, flags = 0;

    status = read_fcac(&instance, &flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* If we are already locked into broadcast mode, then we're done */
    if ((flags & FCAC_INSTANCE_LOCK_MASK) > 0)
        goto end;

    /* Clear the instance enable bit */
    flags &= ~FCAC_INSTANCE_EN_MASK;

    status = write_fcac(instance, flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

static sev_status_t access_df_reg_bcast32(uint32_t function, uint32_t offset,
                                          uint32_t *value, enum df_reg_op op)
{
    sev_status_t status = enable_broadcast_mode();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Broadcasting updates using indirect accesses is sometimes unreliable.
     * (HDT would show different register values after each refresh.) Broad-
     * casts using direct accesses seem much more reliable.
     */
    status = access_df_reg_direct(function, offset, (uint64_t *)value, op);

end:
    return status;
}

sev_status_t read_df_reg_bcast32(uint32_t function, uint32_t offset,
                                 uint32_t *value)
{
    return access_df_reg_bcast32(function, offset, value, DF_REG_OP_READ32);
}

sev_status_t write_df_reg_bcast32(uint32_t function, uint32_t offset,
                                  uint32_t value)
{
    return access_df_reg_bcast32(function, offset, &value, DF_REG_OP_WRITE32);
}

/**
 * Writes TMR registers
 */
static sev_status_t write_tmr_reg(uint32_t index, uint32_t offset, uint32_t value)
{
    offset += (index * TMR_OFFSET);
    return write_df_reg32(index, DF_TMR_FUNC, offset, value);
}

/**
 * Reads a TMR register
 */
static sev_status_t read_tmr_reg(uint32_t index, uint32_t offset, uint32_t *value)
{
    if (value == NULL)
        return ERR_INVALID_PARAMS;

    offset += (index * TMR_OFFSET);
    return read_df_reg32(index, DF_TMR_FUNC, offset, value);
}

sev_status_t get_tmr_info(size_t tmr_nr, uint64_t *base, uint64_t *limit,
                          uint32_t *trust_lvl, uint32_t *flags)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t tmr_base = 0;
    uint32_t tmr_limit = 0;
    uint32_t tmr_ctrl = 0;
    uint32_t tmr_ext = 0;

    /* TMR Base address [47:16] */
    status = read_tmr_reg(tmr_nr, TMR_BASE_ADDR_OFFSET, &tmr_base);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* TMR Limit address [47:16] */
    status = read_tmr_reg(tmr_nr, TMR_LIMIT_ADDR_OFFSET, &tmr_limit);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* TmrCtl register */
    status = read_tmr_reg(tmr_nr, TMR_CTL_OFFSET, &tmr_ctrl);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* TMR Base and Limit address Extensions [55:48] */
    status = read_tmr_reg(tmr_nr, TMR_EXT_ADDR_OFFSET, &tmr_ext);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (base)
    {
        *base = ((uint64_t)tmr_base << TMR_X86_PHYS_ADDR_SHIFT) +
                (((uint64_t)tmr_ext & TMR_BASE_ADDR_EXT_MASK) << (TMR_EXT_SHIFT - TMR_BASE_ADDR_EXT_SHIFT));
    }

    /* The TMR covers all addresses between [base] and [limit + 0xFFFF] */
    if (limit)
    {
        *limit = ((uint64_t)tmr_limit << TMR_X86_PHYS_ADDR_SHIFT) +
                  (((uint64_t)tmr_ext & TMR_LIMIT_ADDR_EXT_MASK) << (TMR_EXT_SHIFT - TMR_LIMIT_ADDR_EXT_SHIFT));
        *limit += (1ull << TMR_X86_PHYS_ADDR_SHIFT) - 1;    /* 64K */
    }

    if (flags)
        *flags = tmr_ctrl;

    if (trust_lvl)
        *trust_lvl = ((tmr_ctrl & TMR_TRUST_LVL_MASK) >> TMR_TRUST_LVL_SHIFT);

end:
    return status;
}

inline bool tmr_is_valid(uint32_t tmr_ctrl)
{
    return tmr_ctrl & TMR_CTRL_VALID_FLAG;
}

sev_status_t set_tmr(size_t tmr_nr, uint64_t base, uint64_t limit,
                     uint32_t flags, uint32_t trust_lvl)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t tmr_base = 0;
    uint32_t tmr_limit = 0;
    uint32_t tmr_ctrl = flags;
    uint32_t tmr_ext = 0;

    /* Clear the valid flag before we update the register values */
    status = write_tmr_reg(tmr_nr, TMR_CTL_OFFSET, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* HACK: Recognize TMPM TMR and UNIT_ID flag and put TMPM Unit ID in place */
    if (tmr_nr == SNP_RMP_TMPM_TMR && (flags & TMR_CTRL_UNIT_ID0_VAL_FLAG))
    {
        status = write_tmr_reg(tmr_nr, TMR_FIDA_OFFSET, (TMPM_UNIT_ID << TMR_FIDA_UNIT_ID_SHIFT));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    if (tmr_nr == SNP_RMP_TMPM_TMR && (flags & TMR_CTRL_UNIT_ID1_VAL_FLAG))
    {
        status = write_tmr_reg(tmr_nr, TMR_FIDB_OFFSET, (TMPM_UNIT_ID_DMA << TMR_FIDB_UNIT_ID_SHIFT));
        if (status != SEV_STATUS_SUCCESS)
          goto end;
    }

    /* Write the TmrBaseAddr register */
    tmr_base = (uint32_t)((base & TMR_ADDR_MASK) >> TMR_X86_PHYS_ADDR_SHIFT);
    status = write_tmr_reg(tmr_nr, TMR_BASE_ADDR_OFFSET, tmr_base);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Write the TmrLimitAddr register */
    tmr_limit = (uint32_t)((limit & TMR_ADDR_MASK) >> TMR_X86_PHYS_ADDR_SHIFT);
    status = write_tmr_reg(tmr_nr, TMR_LIMIT_ADDR_OFFSET, tmr_limit);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Write the TmrExtAddr register */
    tmr_ext  = (uint32_t)(((base  & TMR_EXT_MASK) >> TMR_EXT_SHIFT) << TMR_BASE_ADDR_EXT_SHIFT);
    tmr_ext += (uint32_t)(((limit & TMR_EXT_MASK) >> TMR_EXT_SHIFT) << TMR_LIMIT_ADDR_EXT_SHIFT);
    status = write_tmr_reg(tmr_nr, TMR_EXT_ADDR_OFFSET, tmr_ext);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Write the TmrCtl register */
    tmr_ctrl &= ~(TMR_TRUST_LVL_MASK);
    tmr_ctrl |= (trust_lvl << TMR_TRUST_LVL_SHIFT);
    status = write_tmr_reg(tmr_nr, TMR_CTL_OFFSET, tmr_ctrl);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

sev_status_t set_tmr_modify_flags(size_t tmr_nr, uint32_t flags, bool set)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t reg_flags = 0;

    /* Clear the valid flag before we update the register values */
    status = read_tmr_reg(tmr_nr, TMR_CTL_OFFSET, &reg_flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (set)
        reg_flags |= flags;
    else
        reg_flags &= ~flags;

    status = write_tmr_reg(tmr_nr, TMR_CTL_OFFSET, reg_flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

sev_status_t set_psp_misc_mode(uint32_t flags)
{
    uint32_t function = PSP_MISC_MODE_FUNC;
    uint32_t offset = PSP_MISC_MODE_OFFSET;

    return write_df_reg_bcast32(function, offset, flags);
}

sev_status_t get_psp_misc_mode(uint32_t *flags)
{
    uint32_t function = PSP_MISC_MODE_FUNC;
    uint32_t offset = PSP_MISC_MODE_OFFSET;

    return read_df_reg_bcast32(function, offset, flags);
}

sev_status_t set_cnli_key(uint32_t asid, const uint8_t *seed, size_t size)
{
    uint8_t  key_val[CIPHER_AES_KEY_SIZE_BYTES];
    uint32_t value;
    size_t context;
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!seed || asid > GetMaxSEVASID())
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    context = (gTotalDieNum * MAX_CNLI);
    status = kdf_derive(key_val, size, seed, size, CNLI_KEY_LABEL,
                        sizeof(CNLI_KEY_LABEL), (uint8_t *)&context,
                        sizeof(context));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    for (size_t die = 0; die < gTotalDieNum; die++)
    {
        for (size_t cnli = 0; cnli < MAX_CNLI; cnli++)
        {
            value = ((asid * 8) | CNLI_KEY_ARRAY_AUTOINC_MASK);
            status = write_df_reg32(CNLI0_DF_INSTANCE_ID + cnli, CNLI_DF_FUNCTION_ID, CNLI_AES_INDEX_OFFSET, value);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            for (size_t i = 0; i < size; i += sizeof(uint32_t))
            {
                value = *(uint32_t *)&key_val[i];
                status = write_df_reg32(CNLI0_DF_INSTANCE_ID + cnli, CNLI_DF_FUNCTION_ID, CNLI_AES_DATA_OFFSET, value);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
            }
        }
    }

end:
    secure_memzero(key_val, sizeof(key_val));
    return status;
}

sev_status_t get_df_sec_level(uint32_t sdp_sec_level, uint32_t *df_sec_level)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    uint32_t function = FTI_SEC_LVL_MAP_REG_FUNC;
    uint32_t offset = FTI_SEC_LVL_MAP_REG_OFFSET;
    uint64_t value = 0;
    uint32_t ccd = 0;
    bool found = false;

    if (df_sec_level == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check CCD present and find the first CCD and get its CCM value.
       For Genoa, CCD0-7 maps to CCM0-7, then wraps around
       where CCD8-12 maps to CCM0-4.  */
    for (ccd = 0; ccd < MAX_CCDS; ccd++)
    {
        if ((gPersistent.socket_info[0].ccd_present_bit_mask >> ccd) & 1)
        {
            found = true;
            /* Handle the wrap case */
            if (ccd >= 8)
                ccd -= 8;
            break;
        }
    }

    /* This should never happen */
    if (found == false)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /*
     * Cannot use broadcast here since IOM and CCM have different values and
     *  could end up getting the wrong value from IOM
     *  status = read_df_reg_bcast32(function, offset, &value);
     *
     * Read from the CCM0 + ccd for the correct instance. read_df_reg32 is 
     * using direct access but CCM0 has to be done with indirect access.
     */
     status = access_df_reg_indirect((uint8_t)(CCM0_INSTANCE_ID + ccd), function, offset,
                                     FICAA_SINGLE_FLAG,
                                     &value, DF_REG_OP_READ32);
     if (status != SEV_STATUS_SUCCESS)
         goto end;

    /* bit 0-2 is SDP level 0, 4-6 is SDP level 1, etc */
    *df_sec_level = (value >> (4 * sdp_sec_level)) & 0x7;

end:
    return status;
}
