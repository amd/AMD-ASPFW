// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bl_syscall.h"
#include "crypto.h"
#include "p2p_cmd.h"
#include "pspsmc.h"
#include "secure_ops.h"
#include "sev_extended_errors.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_scmd.h"
#include "sev_trace.h"
#include "x86_copy.h"
#include "apicid.h"
#include "core.h"
#include "helper.h"

typedef enum sev_hal_cache_operation
{
    CACHE_CLEAN             = 0,
    CACHE_INVALIDATE        = 1,
    CACHE_CLEAN_INVALIDATE  = 2
} sev_hal_cache_operation_t;

typedef enum sev_hal_cache_type
{
    CACHE_TYPE_ICACHE       = 0,
    CACHE_TYPE_DCACHE       = 1
} sev_hal_cache_type_t;

#define ALL_CACHE       (0xFFFFFFFF)

/**
 * Cache operations.
 *
 *  Parameters:
 *      operation : type of cache operation (clean, invalidate or both)
 *      cache_type : icache or dcache
 *      virt_addr  : Virtual Address
 *      size      : size (if 0xFFFFFFFF - operation on entire cache)
 *
 *  Return value: BL_OK or error code
 */
static sev_status_t sev_hal_cache_operation(sev_hal_cache_operation_t operation,
                                            sev_hal_cache_type_t cache_type,
                                            uint32_t virt_addr, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_CacheOperation(operation, cache_type, virt_addr, size);
    if (rc != BL_OK)
    {
        status = ERR_HAL_CACHE;
    }

    return status;
}

/**
 * Data cache management
 * Call this to force cache out to memory after writing gpDram
 */
void sev_hal_clean_dcache(uint32_t vaddr, size_t size)
{
    sev_hal_cache_operation(CACHE_CLEAN, CACHE_TYPE_DCACHE, vaddr, size);
}

/**
 * Call this to pull memory into cache before reading gpDram
 */
void sev_hal_invalidate_dcache(uint32_t vaddr, size_t size)
{
    sev_hal_cache_operation(CACHE_INVALIDATE, CACHE_TYPE_DCACHE, vaddr, size);
}

void sev_hal_clean_invalidate_dcache(uint32_t vaddr, size_t size)
{
    sev_hal_cache_operation(CACHE_CLEAN_INVALIDATE, CACHE_TYPE_DCACHE, vaddr, size);
}

/**
 * Instruction cache management
 */
void sev_hal_invalidate_icache(uint32_t vaddr, size_t size)
{
    sev_hal_cache_operation(CACHE_INVALIDATE, CACHE_TYPE_ICACHE, vaddr, size);
}

void sev_hal_invalidate_all_icache(void)
{
    sev_hal_cache_operation(CACHE_INVALIDATE, CACHE_TYPE_ICACHE, 0, ALL_CACHE);
}

sev_status_t sev_hal_map_memory(uint64_t addr, void **axi_addr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!axi_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *axi_addr = Svc_MapSysHubGeneric(GET_LOWER_32(addr), GET_UPPER_32(addr), AxUSER_DRAM_BYPASS_IOMMU, INITIAL_TLB_ATTRIBUTE);
    if (*axi_addr == NULL)
        status = ERR_HAL_MEMORY_MAP;

end:
    return status;
}

/**
 * Use this only for SNP Guest context memory NOT for getting ASID-encrypted guest memory
 */
sev_status_t sev_hal_map_guest_context(uint64_t addr, void **axi_addr, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!axi_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the address range before mapping it. */
    status = validate_address_range(addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Clear C-Bit if it's set as it is going to be mapped with Inline AES Encryption */
    status = convert_x86_address(&addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Map the x86 buffer using AES Inline Encryption */
    *axi_addr = Svc_MapSysHubGeneric(GET_LOWER_32(addr), GET_UPPER_32(addr), AxUSER_DRAM_BYPASS_IOMMU,
                                     INITIAL_TLB_ATTRIBUTE | INLINE_AES_EN | INLINE_AES_KEY0_SEL | MA_PSP_CCP_SET);
    if (*axi_addr == NULL)
        status = ERR_HAL_MEMORY_MAP;

    sev_hal_invalidate_dcache((uint32_t)(*axi_addr), size);

end:
    return status;
}

/**
 * Use this only for system memory (SNP init) NOT for getting ASID-encrypted guest memory
 */
sev_status_t sev_hal_map_memory_ccp(uint64_t addr, void **axi_addr, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!axi_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the address range before mapping it. */
    status = validate_address_range(addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Set ASID for SME mode */
    status = convert_x86_address(&addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Map the x86 buffer */
    *axi_addr = Svc_MapSysHubGeneric(GET_LOWER_32(addr), GET_UPPER_32(addr), AxUSER_DRAM_BYPASS_IOMMU, INITIAL_TLB_ATTRIBUTE | MA_PSP_CCP_SET);
    if (*axi_addr == NULL)
        status = ERR_HAL_MEMORY_MAP;

end:
    return status;
}

/**
 * Use this only for getting ASID-encrypted guest memory
 *
 * Map to MP0 SRAM area, so when you access CCP you use CCP_LOCAL and NOT External,
 *   it would be come as if you're using SRAM directly
 * With CCP_LOCAL you basically have DF mapped address, so you can embedded ASID
 *   into the address space
 */
sev_status_t sev_hal_map_memory_ccp_asid(uint64_t addr, void **axi_addr, uint32_t size, uint32_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!axi_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the address range before mapping it. */
    status = validate_address_range(addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Set ASID using variable passed in */
    if (asid == 0)           /* Example, SNP SwapIO Metadata page are unencrypted */
        addr = set_asid(COPY_PLAINTEXT_IN, addr, asid);
    else
        addr = set_asid(COPY_CIPHERTEXT_IN, addr, asid);

    /* Map the x86 buffer */
    *axi_addr = Svc_MapSysHubGeneric(GET_LOWER_32(addr), GET_UPPER_32(addr), AxUSER_DRAM_BYPASS_IOMMU, INITIAL_TLB_ATTRIBUTE | MA_PSP_CCP_SET);
    if (*axi_addr == NULL)
        status = ERR_HAL_MEMORY_MAP;

end:
    return status;
}

sev_status_t sev_hal_unmap_memory(void *axi_addr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_UnmapSysHub(axi_addr);
    if (rc != BL_OK)
        status = ERR_HAL_MEMORY_MAP;

    return status;
}

sev_status_t sev_hal_unmap_guest_context(void *axi_addr, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    sev_hal_clean_dcache((uint32_t)axi_addr, size);
    rc = Svc_UnmapSysHub(axi_addr);
    if (rc != BL_OK)
        status = ERR_HAL_MEMORY_MAP;

    return status;
}

sev_status_t sev_hal_map_smn_on_die(uint32_t smn_addr, void **axi_addr, size_t die)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!axi_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (die == gCurrentDieID)
        *axi_addr = (void *)Svc_MapSmnOnCurrentDie(smn_addr);
    else
        *axi_addr = (void *)Svc_MapSmnOnDieNum(smn_addr, die);

    if (*axi_addr == NULL)
        status = ERR_HAL_MAP_SMN;

end:
    return status;
}

sev_status_t sev_hal_map_smn(uint32_t smn_addr, void **axi_addr)
{
    return sev_hal_map_smn_on_die(smn_addr, axi_addr, gCurrentDieID);
}

sev_status_t sev_hal_unmap_smn(void *axi_addr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    if (!axi_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Ensure all accesses have completed before we unmap */
    ARMCC_DSB_ISB();

    rc = Svc_UnmapSmn((uintptr_t)axi_addr);
    if (rc != BL_OK)
        status = ERR_HAL_MAP_SMN;

end:
    return status;
}

/* Status from Genoa BL svc code */
#define SEV_UAPP_RESPONSE_SUCCESS    0x1
#define SEV_UAPP_RESPONSE_FAIL       0x2
sev_status_t sev_hal_master_to_slave(uint32_t target_die, void *pCmd_buf,
                                     uint32_t buf_size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;
    p2p_cmd_t  p2p_cmd;
    p2p_buf_t  p2p_buf;
    p2p_resp_t p2p_resp;
    uint32_t slave_status = 0;
    p2p_buf_t pslave_data = {0};

    /* If it is just one, it's one socket, so return OK */
    if (gTotalDieNum == 1)
    {
        status = SEV_STATUS_SUCCESS;
        goto end;
    }

    SEV_HAL_TRACE("send SCMD to slave die...");

    /*
     * Send commands to the slave die(s) only if this is the master die and
     * there are multiple dies.
     */
    if (gCurrentDieID != SEV_GLOBAL_MASTER_DIE_ID || target_die > gTotalDieNum ||
        !pCmd_buf)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&p2p_cmd, 0, sizeof(p2p_cmd));
    memset(&p2p_resp, 0, sizeof(p2p_resp));

    p2p_cmd.cmd_id = COMMAND_SEV_SYNC_STATUS;   /* Generic SEV Master to Slave command */
    p2p_cmd.pbuf   = &p2p_buf;

    p2p_buf.pdata  = (uint8_t *)pCmd_buf;
    p2p_buf.size   = buf_size;
    p2p_buf.status = SEV_STATUS_SUCCESS;

    p2p_resp.cmd_id = COMMAND_SEV_SYNC_STATUS;
    p2p_resp.pbuf   = &pslave_data;
    p2p_resp.num_resp_data = 1;

    pslave_data.pdata = (uint8_t *)&slave_status;
    pslave_data.size  = sizeof(uint32_t);

    rc = Svc_P2PSendCmd(target_die, &p2p_cmd, &p2p_resp, 0);
    if (rc != BL_OK || slave_status != SEV_UAPP_RESPONSE_SUCCESS)
        status = ERR_HAL_SLAVE_DIE;

end:
    SEV_HAL_TRACE_EX(target_die, (uint32_t)pCmd_buf, buf_size, rc);
    return status;
}

sev_status_t sev_hal_persistent_write(void *pBuf, uint32_t input_size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_SevPersistentOp(SEV_PERSISTENT_OP_WRITE, pBuf, input_size);
    if (rc != BL_OK)
    {
        status = ERR_HAL_PERSISTENT_WRITE;
    }

    return status;
}

sev_status_t sev_hal_persistent_read(void *pBuf, uint32_t buf_size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_SevPersistentOp(SEV_PERSISTENT_OP_READ, pBuf, buf_size);
    if (rc != BL_OK)
    {
        status = ERR_HAL_PERSISTENT_READ;
    }

    return status;
}

sev_status_t sev_hal_persistent_erase(uint32_t num_blocks)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_SevPersistentOp(SEV_PERSISTENT_OP_ERASE, NULL, num_blocks);
    if (rc != BL_OK)
    {
        status = ERR_HAL_PERSISTENT_ERASE;
    }

    return status;
}

sev_status_t sev_hal_key_derive(sev_hal_key_derive_t *pParams)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_SevKeyDerive(pParams);
    if (rc != BL_OK)
    {
        status = ERR_HAL_KEY_DERIVE;
    }

    return status;
}

sev_status_t sev_hal_aes_generic(sev_hal_aes_t *pParams)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_AesGeneric(pParams);
    if (rc != BL_OK)
    {
        status = ERR_HAL_AES;
    }

    return status;
}

sev_status_t sev_hal_sha(sev_hal_sha_t *pParams, SHA_TYPE sha_type)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    if (sha_type != SHA_TYPE_256 && sha_type != SHA_TYPE_384)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    pParams->SHAType = sha_type;
    rc = Svc_SHA((SHA_OPERATION *)pParams, SHA_GENERIC);
    if (rc != BL_OK)
    {
        status = ERR_HAL_SHA256;
    }

end:
    return status;
}

sev_status_t sev_hal_ecc_primitive(sev_hal_ecc_primitive_t *pParams)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_EccPrimitive(pParams);
    if (rc != BL_OK)
    {
        status = ERR_HAL_ECC_PRIMITIVE;
    }

    return status;
}

sev_status_t sev_hal_rsapss_verify(sev_hal_rsapss_verify_t *pParams)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_RSAPSSVerify((RSAPSS_VERIFY_PARAMS *)pParams);
    if (rc != BL_OK)
    {
        status = ERR_HAL_RSA_PSS_VALIDATE;
    }

    return status;
}

sev_status_t sev_hal_trng(uint8_t *pOut, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    rc = Svc_Trng(pOut, size);
    if (rc != BL_OK)
    {
        status = ERR_HAL_TRNG;
    }

    return status;
}

sev_status_t sev_hal_get_tmr(size_t tmr_nr, uint64_t *base, uint64_t *limit,
                             bool *is_valid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t tmr_base = 0, tmr_limit = 0;
    uint32_t tmr_ctrl = 0;

    if (tmr_nr > TMR_NR_MAX || (!base && !limit && !is_valid))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = tmr_cache_read(tmr_nr, &tmr_base, &tmr_limit, &tmr_ctrl, NULL);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (base)
        *base = tmr_base;
    if (limit)
        *limit = tmr_limit;
    if (is_valid)
        *is_valid = tmr_is_valid(tmr_ctrl);

end:
    return status;
}

sev_status_t sev_hal_set_tmr(size_t tmr_nr, uint64_t base, uint64_t size,
                             uint32_t trust_lvl_mask, uint32_t flags)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = tmr_cache_write(tmr_nr, base, base + size, flags, trust_lvl_mask);

    return status;
}

sev_status_t sev_hal_reset_tmr(size_t tmr_nr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = tmr_cache_write(tmr_nr, 0, 0, 0, 0);

    return status;
}

sev_status_t sev_hal_modify_tmr_flags(size_t tmr_nr, uint32_t flags, bool set)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = tmr_cache_modify_flags(tmr_nr, flags, set);

    return status;
}

sev_status_t sev_hal_enable_tmr(size_t tmr_nr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t base = 0, limit = 0;
    uint32_t control = 0, trust_lvl = 0;

    if (tmr_nr > TMR_NR_MAX)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = tmr_cache_read(tmr_nr, &base, &limit, &control, &trust_lvl);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (!tmr_is_valid(control))
    {
        control |= TMR_CTRL_VALID_FLAG;
        status = tmr_cache_write(tmr_nr, base, limit, control, trust_lvl);
    }

end:
    return status;
}

/*
sev_status_t sev_hal_disable_tmr(size_t tmr_nr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t base = 0, limit = 0;
    uint32_t control = 0, trust_lvl = 0;

    if (tmr_nr > TMR_NR_MAX)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = tmr_cache_read(tmr_nr, &base, &limit, &control, &trust_lvl);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (tmr_is_valid(control))
    {
        control &= ~TMR_CTRL_VALID_FLAG;
        status = tmr_cache_write(tmr_nr, base, limit, control, trust_lvl);
    }

end:
    return status;
}
*/

/* Has an associated slave command because only sets it's own die */
sev_status_t sev_hal_set_misc_read_sized_wrbkinvd(bool enable)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t flags = 0;
    uint32_t check = 0;

    status = get_psp_misc_mode(&flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (enable)  /* Set */
        flags |= MISC_PSP_RD_SZ_WRBKINVD_FLAG;
    else        /* Clear */
        flags &= ~(MISC_PSP_RD_SZ_WRBKINVD_FLAG);

    /* Set PspMiscMode.PspRdSzWrBkInvd = 0/1 */
    status = set_psp_misc_mode(flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    do
    {
        status = get_psp_misc_mode(&check);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    } while ((check & MISC_PSP_RD_SZ_WRBKINVD_FLAG) != (flags & MISC_PSP_RD_SZ_WRBKINVD_FLAG));

end:
    return status;
}

sev_status_t sev_hal_get_misc_tsme_enable(uint32_t  *enable)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t flags = 0;

    status = get_psp_misc_mode(&flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    *enable = ((flags & MISC_TSME_ENABLE_FLAG) == MISC_TSME_ENABLE_FLAG);

end:
    return status;
}

/* Has an associated slave command because only sets it's own die */
sev_status_t sev_hal_df_write_flush(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t flags = 0;

    status = get_psp_misc_mode(&flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    flags |= MISC_GLOB_VISIBLE_WR_FLUSH_FLAG;

    /* Set PspMiscMode.GlobWrFlush = 1 */
    status = set_psp_misc_mode(flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * When PspMiscMode.GlobWrFlush is set to 1, the CS captures a snapshot of
     * globally visible pending DRAM writes and flushes them to the UMC. The
     * bit is cleared by hardware when the operation is complete. Once set
     * to 1, it stays 1 until a Warm Reset asserts, or the Flush operation
     * completes.
     *
     * See PPR: 7.19.2.6 VMGuard Write Flush
     */
    do
    {
        status = get_psp_misc_mode(&flags);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    } while ((flags & MISC_GLOB_VISIBLE_WR_FLUSH_FLAG) != 0);

end:
    return status;
}

sev_status_t sev_hal_get_chip_unique_key(uint8_t *buffer, size_t *size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    BL_RETCODE rc = BL_OK;

    uint8_t temp_buffer[CUK_SIZE + ALIGN_SAFE_OFFSET_32_BYTES];
    uint8_t *temp_buffer_align = (uint8_t *)ALIGN_TO_32_BYTES(temp_buffer);

    if (!buffer || !size || *size < CUK_SIZE)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    rc = (BL_RETCODE)Svc_GetCUK(temp_buffer_align, size);
    if (rc != BL_OK)
    {
        status = SEV_STATUS_HARDWARE_PLATFORM;
        goto end;
    }

    memcpy(buffer, temp_buffer_align, *size);

    /* Clean up */
    secure_memzero(temp_buffer, sizeof(temp_buffer));

end:
    return status;
}

sev_status_t sev_hal_cache_new_image(uint64_t x86_addr, uint32_t len,
                                     SEV_NEWFW_SUBOP_ENUM op)
{
    BL_RETCODE rc = BL_OK;
    sev_status_t status = SEV_STATUS_SUCCESS;

    /*
     * Convert the x86 address to include ASID number if SME is enabled
     */
    status = convert_x86_address(&x86_addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Translate BL retcodes to SEV retcodes */
    rc = (BL_RETCODE)Svc_SEVCacheNewImage(GET_LOWER_32(x86_addr), GET_UPPER_32(x86_addr), len,
                                          (uint32_t)MBEDTLS_USER_APP_PSP_DIR_TYPE |
                                          ((uint32_t)op << SEV_NEWFW_SUBOP_SHIFT));
    switch (rc) {
        case BL_OK:
            status = SEV_STATUS_SUCCESS;
            break;
        case BL_ERR_DATA_LENGTH:
            status = SEV_STATUS_INVALID_LENGTH;
            break;
        case BL_ERR_FWVALIDATION:
            status = SEV_STATUS_BAD_SIGNATURE;
            break;
        case BL_ERR_INVALID_ADDRESS:
            status = SEV_STATUS_INVALID_ADDRESS;
            break;
        case BL_ERR_OUT_OF_RESOURCES:
            status = SEV_STATUS_RESOURCE_LIMIT;
            break;
        case BL_ERR_SEV_DOWNLOADFW_BROADCAST_FAIL:
            status = SEV_STATUS_HARDWARE_PLATFORM;
            break;
        case BL_ERR_FUNCTION_NOT_SUPPORTED:
        case BL_ERR_SEV_ROLLBACK_DETECTED:  /* Checked in validate.c in bootloader */
            status = SEV_STATUS_INVALID_CONFIG;
            break;
        case BL_ERR_FWTYPE_MISMATCH:        /* Checked in validate.c in bootloader */
        case BL_ERR_DATA_ALIGNMENT:
        default:
            status = SEV_STATUS_INVALID_PARAM;
    }

end:
    return status;
}

void sev_hal_get_smm_range(uint64_t *base, uint64_t *length)
{
    Svc_GetSmmRange(base, length);
}

sev_status_t sev_hal_get_min_sev_asid(uint32_t *min_sev_asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    static uint32_t asid = ~0U;

    if (!min_sev_asid)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (asid == ~0U)
        asid = Svc_GetMinSevAsid();

    *min_sev_asid = asid;

end:
    return status;
}

/**
 * Only needs to be called on FIRST_RUN and RELOAD, otherwise, gpDram is
 * valid and should be used
 */
sev_status_t sev_hal_get_reserved_dram(void **buffer, size_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!buffer)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *buffer = Svc_GetSevReservedDram(size);
    if (!(*buffer))
        status = ERR_OUT_OF_RESOURCES;

end:
    return status;
}

sev_status_t sev_hal_read_reg_on_die(size_t die, uint32_t smn_addr,
                                     uint32_t mask, uint32_t *value)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    void *reg_addr = NULL;

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_map_smn_on_die(smn_addr, (void **)&reg_addr, die);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    *value = ReadReg32((uint32_t)reg_addr) & mask;
    sev_hal_unmap_smn(reg_addr);

end:
    return status;
}

sev_status_t sev_hal_read_reg(uint32_t smn_addr, uint32_t mask, uint32_t *value)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    void *reg_addr = NULL;

    if (!value)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_map_smn(smn_addr, (void **)&reg_addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    *value = ReadReg32((uint32_t)reg_addr) & mask;
    sev_hal_unmap_smn(reg_addr);

end:
    return status;
}

sev_status_t sev_hal_df_acquire(void)
{
    uint32_t rc = BL_OK;

    rc = Svc_SendPspSmuMsg(PSPSMC_MSG_DFCstateDisable, 1, NULL, 0);

    return rc == BL_OK ? SEV_STATUS_SUCCESS : ERR_OUT_OF_RESOURCES;
}

sev_status_t sev_hal_df_release(void)
{
    uint32_t rc = BL_OK;

    rc = Svc_SendPspSmuMsg(PSPSMC_MSG_DFCstateDisable, 0, NULL, 0);

    return rc == BL_OK ? SEV_STATUS_SUCCESS : ERR_OUT_OF_RESOURCES;
}

sev_status_t sev_hal_get_root_key_hash(digest_sha_t *hash)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;

    if (!hash)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    rc = Svc_GetRootKeyHash(hash->digest, sizeof(hash->digest));
    if (rc != BL_OK)
        status = ERR_INVALID_PARAMS;

end:
    return status;
}

static uint32_t get_ccx_present_bit_mask(uint16_t mcm_core_present_in_ccd_bit_mask, uint32_t ccd_id)
{
    uint32_t mask = 0;

    /*
    * Helper function to return CCX bit mask
    *   If 2 CCXs/CCD config (2 bits)
    *   - No cores present in that CCX, mask is binary 00
    *   - Cores present in CCX0, but not in CCX1 then mask is binary 01 and so on.
    */
    if (get_physical_ccxs_per_ccd() == 1)
    {
        mask = mcm_core_present_in_ccd_bit_mask & 0xFF ? 1 : 0;
    } else {
        mask = (mcm_core_present_in_ccd_bit_mask & 0xFF) ? 1 : 0;
        mask |= (mcm_core_present_in_ccd_bit_mask & 0xFF00) ? 2 : 0;
    }

    return mask;
}

sev_status_t sev_hal_get_mcm_info(sev_persistent_globals_t *persistent)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t rc = BL_OK;
    MCM_INFO mcm_info;

    if (!persistent)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }
    memset(&mcm_info, 0, sizeof(mcm_info));
    rc = Svc_GetMcmInfo( &mcm_info );
    if (rc != BL_OK)
    {
        status = ERR_HAL_MCM_INFO;
        goto end;
    }

    persistent->bl_fw_version = mcm_info.psp_bl_version;
    status = reverse_bytes((uint8_t *)&persistent->bl_fw_version,
                            sizeof(persistent->bl_fw_version));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* CSF-1667 - ignore 2nd least significant byte for version checking */
    persistent->bl_fw_version &= MIN_BL_VERSION_MASK;

    /* Fill out local socket's info */
    for (uint32_t i = 0; i < get_max_ccds(); i++)
    {
        uint32_t mask;
        persistent->socket_info[gCurrentDieID].core_present_in_ccd_bit_mask[i] = mcm_info.core_present_in_ccd_bit_mask[i];
        // Genoa GetMcmInfo sometimes says a CCD is present even though it has no cores, which confuses ASID array management
        if (mcm_info.core_present_in_ccd_bit_mask[i] == 0)
            mcm_info.ccd_present_bit_mask &= ~(1 << i);

        /* Computed mask is either 1 or 2 bits depending on CCXs/CCD. Iterate over the core present mask for all
           CCDs to construct the CCX mask for each the socket. Later, combine them. */
        mask = get_ccx_present_bit_mask(mcm_info.core_present_in_ccd_bit_mask[i], i);
        persistent->ccx_present_bit_mask |= (0xFFFFFFFFul & (mask << (i * get_ccxs_per_ccd())));
    }
    persistent->socket_info[gCurrentDieID].ppin = mcm_info.ppin;
    persistent->socket_info[gCurrentDieID].umc_present_bit_mask = mcm_info.umc_present_bit_mask;
    memcpy(persistent->socket_info[gCurrentDieID].ecc_seed_hash, mcm_info.ecc_seed_hash, sizeof(persistent->socket_info[0].ecc_seed_hash));

    persistent->socket_info[gCurrentDieID].ccd_present_bit_mask = mcm_info.ccd_present_bit_mask;

    /* sev_hal_read_initpkg7 relies on gPersistent's ccd_present_bit_mask */
    status = sev_hal_read_initpkg7(&gPersistent.initpkg7);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = ERR_HAL_MCM_INFO;
        goto end;
    }

    /**
     * From INITPKG7 information, determine the mask.
     * Double the field width based on ccxs/ccd. In such
     * cases, the ccd_present_bit_mask is treated as ccx mask.
     */

    /* Note: max-cores_per_ccd is logical cores, it is result of initpkg07, NOT physical cores */
    persistent->max_cores_per_ccd = get_ccxs_per_ccd() * get_num_cores_per_complex();

    persistent->umc_present_bit_mask = mcm_info.umc_present_bit_mask;

    /* Master die: Get all data from slave dies */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID && gTotalDieNum > 1)
    {
        sev_scmd_t cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_GET_MCM_INFO;
        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        sev_hal_invalidate_dcache((uint32_t)&gpDram->p1_info, sizeof(gpDram->p1_info));

        /* Save P1's socket_info locally */
        memcpy(&persistent->socket_info[1], &gpDram->p1_info.socket_info, sizeof(sev_per_socket_info_t));

        /* Combine bitmasks into all-socket mask */
        uint32_t p1_ccx_present_bit_mask = 0;
        for (uint32_t i = 0; i < get_max_ccds(); i++)
        {
            uint32_t mask = get_ccx_present_bit_mask(gpDram->p1_info.socket_info.core_present_in_ccd_bit_mask[i], i);
            p1_ccx_present_bit_mask |= (0xFFFFFFFFul & (mask << (i * get_ccxs_per_ccd())));
        }

        persistent->ccx_present_bit_mask |= (p1_ccx_present_bit_mask << MAX_CCX_PER_SOCKET_SHIFT);
        persistent->umc_present_bit_mask |= (gpDram->p1_info.socket_info.umc_present_bit_mask << UMCCH_TOTAL_NUM);
    }

    persistent->smt_enabled = mcm_info.is_smt_enabled;

end:
    return status;
}

sev_status_t sev_hal_enqueue_and_run_commands(void *cmds, uint32_t *eids, uint32_t count)
{
    BL_RETCODE status = BL_OK;
    bl_ccp_cmd_desc *pCmds = (bl_ccp_cmd_desc *)cmds;
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        *eids = 0;
        status = (BL_RETCODE)Svc_CcpVcqCmdEnqueue(pCmds, 0, eids);
        if (status != BL_OK)
        {
            switch (status)
            {
                /* Translate expected errors */
                case BL_ERR_INVALID_PARAMETER:
                    return SEV_STATUS_INVALID_PARAM;
                case BL_ERR_CCP_QUEUE_FULL:
                    return ERR_OUT_OF_RESOURCES;
                case BL_ERR_CCP_CMD_ERROR:
                    return SEV_STATUS_INVALID_COMMAND;
                case BL_ERR_SVC_CALL_ADDR_VIOLATION:
                    return SEV_STATUS_INVALID_ADDRESS;
                default:
                    return ERR_UNKNOWN;
            }
        }

        pCmds++;
        eids++;
    }
    return SEV_STATUS_SUCCESS;
}

uint32_t gLastCCPError = 0;

sev_status_t sev_hal_query_commands(uint32_t *eids, uint32_t count, int wait4ready)
{
    BL_RETCODE status = BL_OK;
    uint32_t i;

    for (i = 0; i < count;)
    {
        uint32_t ccpErr = 0;
        status = (BL_RETCODE)Svc_CcpVcqCmdQuery(eids[i], &ccpErr);
        switch (status)
        {
            case BL_OK:                         /* The command is completed successfully */
                break;

            case BL_ERR_CCP_CMD_NOTSCHEDULED:   /* The command has not scheduled yet */
            case BL_ERR_CCP_CMD_BEINGWORKEDON:  /* The command is scheduled and being worked on */
                if (wait4ready != 0)
                    continue;
                return SEV_STATUS_RESOURCE_LIMIT;

            case BL_ERR_CCP_CMD_ERROR:          /* Return value stating that the command is scheduled, */
                gLastCCPError = ccpErr;         /* but CCP engine encounters error when processing it. */
                                                /* The detailed CCP engine error code is posted on CCPerror */
                return SEV_STATUS_HARDWARE_PLATFORM; //(BL_RETCODE)MK_EXT_ERR(i,CCP_HW_ERROR_BASE,ccpErr);

            default:
                return ERR_UNKNOWN;
        }

        i++;
    }
    return SEV_STATUS_SUCCESS;
}

sev_status_t sev_hal_flush_tlb(void)
{
    uint32_t rc = BL_OK;

    rc = Svc_SendPspSmuMsg(PSPSMC_MSG_TLBFlush, 0, NULL, 0);
    if (rc != BL_OK)
        return SEV_STATUS_HARDWARE_UNSAFE;
    else
        return SEV_STATUS_SUCCESS;
}

sev_status_t sev_hal_get_tcb_version(snp_tcb_version_t *tcb_version)
{
    uint32_t rc = BL_OK;
    rc = Svc_GetSetSystemProperty(PROP_ID_TCB_VERSION, (uint8_t *)tcb_version, sizeof(snp_tcb_version_t));
    if (rc != BL_OK)
        return SEV_STATUS_HARDWARE_UNSAFE;
    else
        return SEV_STATUS_SUCCESS;
}

/* PLAT-103448, related to PLAT-70711 - Mailboxes may be blocked from access by
   user applications, so we need to fetch the hashsticks through a SVC call */
static sev_status_t sev_hal_get_hash_sticks_from_bl(HASH_STICK *hash_sticks, uint32_t buffer_size)
{
    uint32_t rc = BL_OK;
    if (buffer_size != (sizeof(HASH_STICK) * 8))
        return SEV_STATUS_INVALID_PARAM;
    rc = Svc_GetSetSystemProperty(PROP_ID_GET_HASHSTICKS, (uint8_t *)hash_sticks, buffer_size);
    if (rc != BL_OK)
        return SEV_STATUS_HARDWARE_UNSAFE;
    else
        return SEV_STATUS_SUCCESS;
}

sev_status_t sev_hal_get_seed_at_idx(uint8_t *seed, uint32_t length, uint32_t idx)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    HASH_STICK *hash_stick = NULL;
    HASH_STICK hash_sticks_from_bl[8] = {0};

    /* Fetch the hash sticks from BL if it's protected, based on
       BL version */
    if (gPersistent.bl_fw_version >= MIN_BL_VERSION_SVC_HASHSTICKS)
    {
        status = sev_hal_get_hash_sticks_from_bl(&hash_sticks_from_bl[0], sizeof(hash_sticks_from_bl));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        hash_stick = &hash_sticks_from_bl[idx];
    }
    else
    {
        hash_stick = &BL_BOOT_ROM_TABLE_PTR->HashSticks[idx];
    }

    if (seed == NULL || length < sizeof(HASH_STICK))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }
    memcpy(seed, hash_stick, sizeof(HASH_STICK));

end:
    memset(hash_sticks_from_bl, 0, sizeof(hash_sticks_from_bl));
    return status;
}

sev_status_t sev_hal_get_initpkg_dram(sev_scfctp_init_pkg_regs_t **initpkg)
{
    uint32_t rc = BL_OK;
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t addr = 0;

    if (!initpkg)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    rc = Svc_GetSetSystemProperty(PROP_ID_SEV_INITPKG, (uint8_t *)&addr, sizeof(addr));
    if (rc)
    {
        status = ERR_OUT_OF_RESOURCES;
        goto end;
    }
    *initpkg = (sev_scfctp_init_pkg_regs_t *)addr;

end:
    return status;
}

sev_status_t sev_hal_get_soc_version(SOC_VER_E *soc_version)
{
    uint32_t rc = BL_OK;
    sev_status_t status = SEV_STATUS_SUCCESS;
    static SOC_VER_E version = INVAL_SOC_VER_VAL;

    if (soc_version == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (version == INVAL_SOC_VER_VAL)
    {
        rc = Svc_GetSetSystemProperty(PROP_ID_SOC_VERSION, (uint8_t *)&version, sizeof(version));
        if (rc)
        {
            status = ERR_OUT_OF_RESOURCES;
            goto end;
        }
    }

    *soc_version = version;

end:
    return status;
}

sev_status_t sev_hal_yield(void)
{
    uint32_t rc = BL_OK;
    sev_status_t status = SEV_STATUS_SUCCESS;

    rc = Svc_Yield();
    if (rc)
    {
        status = SEV_STATUS_HARDWARE_UNSAFE;
    }
    return status;
}

sev_status_t sev_hal_write_snp_globals(uint8_t *data)
{
    uint32_t rc = BL_OK;
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!data)
    {
        return ERR_INVALID_PARAMS;
    }

    rc = Svc_GetSetSystemProperty(PROP_ID_WRITE_SNP_GLOBALS, data, sizeof(sev_snp_globals_t));
    if (rc)
        status = SEV_STATUS_HARDWARE_UNSAFE;
    return status;
}

sev_status_t sev_hal_read_snp_globals(uint8_t *data)
{
    uint32_t rc = BL_OK;
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!data)
    {
        return ERR_INVALID_PARAMS;
    }

    rc = Svc_GetSetSystemProperty(PROP_ID_READ_SNP_GLOBALS, data, sizeof(sev_snp_globals_t));
    if (rc)
        status = SEV_STATUS_HARDWARE_UNSAFE;
    return status;
}

sev_status_t sev_hal_get_dram_2mb(void **buffer)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t *dram = NULL;
    status = sev_hal_get_reserved_dram((void **)&dram, sizeof(sev_rsvd_dram_t));
    if (status != SEV_STATUS_SUCCESS || dram == NULL)
        goto end;

    dram = dram - offsetof(PSP_DRAM_DATA_SPX, SevReservedMemory);
    /* This must be aligned to 8MB (PSP secure dram size) */
    if ((uint32_t)dram & (PSP_SECURE_DRAM_TOTAL_SIZE_BYTES - 1))
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto end;
    }
    dram += PSP_SECURE_DRAM_USABLE_SIZE_BYTES;
    *buffer = dram;

end:
    return status;
}

sev_status_t sev_hal_check_msr(uint32_t msr_register, uint32_t *is_same, uint64_t *msr_value)
{
    uint32_t rc = BL_OK;
    uint32_t reg[3];

    if (!is_same || !msr_value)
    {
        return ERR_INVALID_PARAMS;
    }

    rc = Svc_SendPspSmuMsg(PSPSMC_MSG_CheckMSR, msr_register, reg, sizeof(reg));
    if (rc != BL_OK)
        return SEV_STATUS_HARDWARE_UNSAFE;
    else
    {
        *is_same = reg[0];
        *msr_value = (uint64_t)reg[1] + ((uint64_t)reg[2] << 32);
        return SEV_STATUS_SUCCESS;
    }
}

static uint64_t msrs_value[SNP_INIT_MSR_ARRAY_INDICES] = {0};
static uint32_t msrs_same[SNP_INIT_MSR_ARRAY_INDICES] = {0};
static bool msrs_fetched = false;

/* Return the previously read MSR value */
sev_status_t sev_hal_get_msr_value(uint32_t msr, uint64_t *value, bool *is_same)
{
    sev_status_t status = SEV_STATUS_INVALID_PLATFORM_STATE;

    if (!msrs_fetched)
        return SEV_STATUS_INVALID_PLATFORM_STATE;

    for (size_t i = 0; i < SNP_INIT_MSR_ARRAY_INDICES; ++i)
    {
        if (msr == SNP_INIT_MSR_ARRAY[i])
        {
            if (value)
                *value = msrs_value[i];
            if (is_same)
                *is_same = (msrs_same[i] != 0);
            status = SEV_STATUS_SUCCESS;
            break;
        }
    }

    return status;
}

sev_status_t sev_hal_check_msrs(uint64_t *msr_values)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t msr_index = 0;
    msrs_fetched = false;

    if (msr_values == NULL)
        msr_values = &msrs_value[0];

    memset(msr_values, ~0u, sizeof(*msr_values)*SNP_INIT_MSR_ARRAY_INDICES);
    for (msr_index = 0; msr_index < SNP_INIT_MSR_ARRAY_INDICES; msr_index++)
    {
        status |= sev_hal_check_msr(SNP_INIT_MSR_ARRAY[msr_index], &msrs_same[msr_index], &msr_values[msr_index]);
        if ((SEV_ERROR(status, EXT_ERR_067) != SEV_STATUS_SUCCESS) || (msrs_same[msr_index] != 1))
        {
            status = SEV_STATUS_INVALID_CONFIG;
            SEV_ERROR(status, EXT_ERR_068);
            goto end;
        }

        if (SNP_INIT_MSR_ARRAY[msr_index] == MSR_DEBUG_STATUS)     /* DEBUG_STATUS has more checks */
        {
            if ((msr_values[msr_index] & MSR_DEBUG_STATUS_MASK) != 0)
            {
                status = SEV_STATUS_INVALID_CONFIG;
                SEV_ERROR(status, EXT_ERR_070);
                goto end;
            }
        }
    }

    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        /* Check the MSRs on slave dies if any */
        if (gTotalDieNum > 1)
        {
            sev_scmd_t scmd;
            memset(&scmd, 0, sizeof(scmd));
            scmd.id = SEV_SCMD_CHECK_MSRS;
            status = sev_hal_master_to_slave(1, &scmd, sizeof(scmd));
            if (status != SEV_STATUS_SUCCESS)
            {
                status = SEV_STATUS_INVALID_CONFIG;
                goto end;
            }

            sev_hal_invalidate_dcache((uint32_t)&gpDram->p1_info.msrs, sizeof(gpDram->p1_info.msrs));

            /* Also check that the slave data matches master data */
            if (memcmp(msr_values, &gpDram->p1_info.msrs, sizeof(SNP_INIT_MSR_ARRAY)) != 0)
            {
                status = SEV_STATUS_INVALID_CONFIG;
                SEV_ERROR(status, EXT_ERR_071);
                goto end;
            }
        }
    }
    msrs_fetched = true;

end:
    return status;
}

/**
 * Checks that all SYSCFG values have SNPEn set on each thread
 */
bool snp_is_enabled_all_cores(void)
{
    uint64_t value;
    uint32_t is_same;

    if (sev_hal_check_msr(MSR_SYS_CFG, &is_same, &value) != SEV_STATUS_SUCCESS)
        return false;

    return (is_same != 0) && ((value & MSR_SYS_CFG_SNP_EN_FLAG) != 0);
}

/**
 * exclude_from_mem_map() does what is necessary, if anything, to exclude
 * a region from the map of reliable memory. Return false if failed.
 */
static bool exclude_from_mem_map(SYS_MEM_MAP *mem_map, uint64_t lo, uint64_t hi)
{
    if (hi < lo)
    {
        uint64_t temp = lo;
        lo = hi;
        hi = temp;
    }

    for (size_t i = 0; i < mem_map->DescNum; ++i)
    {
        MEM_DESC *mmd = &mem_map->MemRegion[i];
        if (mmd->Type != MEM_DESC_TYPE_DRAM)
            continue;
        /* If no overlap, continue */
        if (hi < mmd->Base || mmd->Limit < lo)
            continue;

        /* Some sort of overlap... 4 possibilities: */
        /* The excluded region covers the entre memory region */
        if (lo <= mmd->Base && mmd->Limit <= hi)
            /* Change type of region to be MMIO */
            mmd->Type = MEM_DESC_TYPE_MMIO;
        /* The excluded region covers the beginning of the memory region */
        else if (lo <= mmd->Base && hi < mmd->Limit)
            /* Adjust base of memory region to exclude MMIO */
            mmd->Base = hi + 1;
        /* The excluded region covers the end of the memory region */
        else if (mmd->Base < lo && mmd->Limit <= hi)
            /* Adjust limit of memory region to exlucde MMIO */
            mmd->Limit = lo - 1;
        /* The excluded region splits the memory region */
        else if (mmd->Base < lo && hi < mmd->Limit)
        {
            /* Find a free MEM_DESC */
            if (mem_map->DescNum >= MAX_MEM_DESC)
                return false;   /* We ran out of ability to describe this memory map */

            /* Create a new region to hold the sub-region after the MMIO */
            MEM_DESC *mmd_new = &mem_map->MemRegion[mem_map->DescNum++];
            mmd_new->Type = MEM_DESC_TYPE_DRAM;
            mmd_new->Base = hi + 1;
            mmd_new->Limit = mmd->Limit;
            /* Adjust the original region to hold the sub-region before the MMIO */
            mmd->Limit = lo - 1;
        }
        else
            return false; /* Don't know what case we missed */
    }

    return true;
}

#define PHYS_ADDR_MASK    0x000FFFFFFFFFFFFF
#define PHYS_ADDR_MASK_4K 0x000FFFFFFFFFF000

#define MSR_IORR_MASK_VALID     (1 << 11)
#define MSR_IORR_BASE_RDWRMEM   ((1 << 3) | (1 << 4))

/**
 * Check to be sure the IORRs haven't remapped addresses to MMIO.
 * IF they do, exclude the range from the memory map.
 * Returns true if the check is 'clean', false on a failure.
 */
static bool check_iorr(uint32_t iorr_msr, SYS_MEM_MAP *mem_map)
{
    uint64_t iorr_mask = 0;
    uint64_t iorr_base = 0;

    if (sev_hal_get_msr_value(iorr_msr + 1, &iorr_mask, NULL) != SEV_STATUS_SUCCESS)
        return false;

    /* Ordinarily, IORRs are unused... VALID bit is 0 */
    if ((iorr_mask & MSR_IORR_MASK_VALID) == 0)
        return true;

    if (sev_hal_get_msr_value(iorr_msr, &iorr_base, NULL) != SEV_STATUS_SUCCESS)
        return false;
    if ((iorr_base & MSR_IORR_BASE_RDWRMEM) == MSR_IORR_BASE_RDWRMEM)
        return true;    /* The IORR maps the area to memory for both read and write */

    /* IORR maps sPA to MMIO... exclude IORR range from the memory map */
    /* Mask has 0 for bits that are part of the range, 1 for upper bits that must match */
    iorr_mask &= PHYS_ADDR_MASK_4K; /* Ignore upper 12, lower 12 address bits */
    uint64_t base_addr = iorr_base & iorr_mask;
    uint64_t limit = base_addr + (~iorr_mask & PHYS_ADDR_MASK);
    if (!exclude_from_mem_map(mem_map, base_addr, limit))
        return false;

    return true;
}

sev_status_t get_memory_map(SYS_MEM_MAP *mem_map)
{
    uint32_t rc = BL_OK;
    sev_status_t status = SEV_STATUS_INVALID_CONFIG;
    uint64_t tom = 0;   // Top of memory below 4GB
    uint64_t tom2 = 0;  // Top of memory above 4GB
    MEM_DESC *hole = NULL;
    MEM_DESC *mmd = NULL;
    uint64_t syscfg = 0;

    if (!mem_map)
        return SEV_ERROR(ERR_INVALID_PARAMS, EXT_ERR_072);

    rc = Svc_GetSetSystemProperty(PROP_ID_SYS_MEM_MAP, (uint8_t *)mem_map, sizeof(*mem_map));
    if (rc != BL_OK)
        goto end_invalid;

    /* Verify we didn't have a memory overlow */
    if (MAX_MEM_DESC < mem_map->DescNum)
        goto end_invalid;

    /* Fetch SYSCFG MSR */
    sev_hal_get_msr_value(MSR_SYS_CFG, &syscfg, NULL);

    /* Coalesce adjacent memory ranges */
    for (size_t i = 0; i < mem_map->DescNum; ++i)
    {
        MEM_DESC *mmd = &mem_map->MemRegion[i];
        if (mmd->Type == MEM_DESC_TYPE_DRAM)
        {
            uint64_t NextBase = mmd->Limit + 1;
            for (size_t j = 0; j < mem_map->DescNum; ++j)
            {
                MEM_DESC *mms = &mem_map->MemRegion[j];
                if (mms->Type == MEM_DESC_TYPE_DRAM && NextBase == mms->Base)
                {
                    mmd->Limit = mms->Limit;
                    NextBase = mmd->Limit + 1;
                    mms->Type = MEM_DESC_TYPE_MERGED;
                    mms->Base = mms->Limit = UINT64_MAX;
                }
            }

        }
        else if (mmd->Type == MEM_DESC_TYPE_MMIO_HOLE)
        {
            hole = mmd;
        }
    }

    /* Exclude the MMIO hole (if any) from the memory map */
    if (hole && !exclude_from_mem_map(mem_map, hole->Base, hole->Limit))
        goto end_invalid;

    /* Verify all memory ranges are within either 0-tom or 4GB-tom2 */
    tom = mem_map->Tom;
    tom2 = mem_map->Tom2;
    for (size_t i = 0; i < mem_map->DescNum; ++i)
    {
        MEM_DESC *mmd = &mem_map->MemRegion[i];
        if (mmd->Type != MEM_DESC_TYPE_DRAM)
            continue;
        if (mmd->Base < SIZE_4GB && mmd->Limit < tom)
            continue;
        if (mmd->Base >= SIZE_4GB && mmd->Limit < tom2)
            continue;
        /* Odd situation... */
        goto end_invalid;
    }

    /* Now verify that all I/O ranges are NOT in any memory range */
    for (size_t i = 0; i < mem_map->DescNum; ++i)
    {
        MEM_DESC *iomd = &mem_map->MemRegion[i];
        if (iomd->Type != MEM_DESC_TYPE_MMIO)
            continue;
        for (size_t j = 0; j < mem_map->DescNum; ++j)
        {
            MEM_DESC *mmd = &mem_map->MemRegion[j];
            if (mmd->Type != MEM_DESC_TYPE_DRAM)
                continue;
            if (ranges_overlap(iomd->Base, iomd->Limit, mmd->Base, mmd->Limit))
                goto end_invalid;
        }
    }

    /* Now throw out non-memory pages from the memory map */
    mmd = &mem_map->MemRegion[0];
    for (size_t i = 0; i < mem_map->DescNum; ++i)
    {
        MEM_DESC *mms = &mem_map->MemRegion[i];
        if (mms->Type == MEM_DESC_TYPE_DRAM)
        {
            if (mmd != mms)
            {
                *mmd = *mms;
            }
            mmd++;
        }
    }
    mem_map->DescNum = mmd - &mem_map->MemRegion[0];

    if (!msrs_fetched)
    {
        status = SEV_STATUS_SUCCESS;
        goto end; /* MSRs aren't fetched yet, but map is good enough for SEV use */
    }

    /* IF the locked MSRs have been fetched, verify the TOM/TOM2 MSRs match the DF */
    uint64_t temp;
    status = sev_hal_get_msr_value(MSR_TOP_MEM, &temp, NULL);
    if (status != SEV_STATUS_SUCCESS || temp != tom)
        goto end_invalid;
    if (syscfg & MSR_SYS_CFG_TOM2_EN_FLAG)
    {
        status = sev_hal_get_msr_value(MSR_TOM2, &temp, NULL);
        if (status != SEV_STATUS_SUCCESS || temp != tom2)
            goto end_invalid;
    }
    else
    {
        if (!exclude_from_mem_map(mem_map, SIZE_4GB, PHYS_ADDR_MASK))
            goto end_invalid;
    }

    /* Now check the IORRs */
    if (!check_iorr(MSR_IORR_BASE_16, mem_map))
        goto end_invalid;
    if (!check_iorr(MSR_IORR_BASE_18, mem_map))
        goto end_invalid;

    /* Check SYSCFG[18] to see if ALL of 0-1MB is MMIO or is configured per the fixed MTRRs */
    if ((syscfg & MSR_SYS_CFG_MFDE_FLAG) == 0)
    {
        /* Entire 0-1MB range is MMIO */
        if (!exclude_from_mem_map(mem_map, 0, 0x100000 - 1))
            goto end_invalid;
    }
    else
    {
        /* Have to check each fixed MTRR */
        /* Encode table 7-6 from APM v2 (Fixed-Range MTRR Address Ranges) */
        static const struct {
            uint32_t MSR;
            uint32_t base;
            uint32_t size;
        } fixedMTRRs[] = {
            {MSR_MTRRFIX_64K,   0x00000, 0x10000},
            {MSR_MTRRFIX_16K_0, 0x80000, 0x04000},
            {MSR_MTRRFIX_16K_1, 0xA0000, 0x04000},
            {MSR_MTRRFIX_4K_0,  0xC0000, 0x01000},
            {MSR_MTRRFIX_4K_1,  0xC8000, 0x01000},
            {MSR_MTRRFIX_4K_2,  0xD0000, 0x01000},
            {MSR_MTRRFIX_4K_3,  0xD8000, 0x01000},
            {MSR_MTRRFIX_4K_4,  0xE0000, 0x01000},
            {MSR_MTRRFIX_4K_5,  0xE8000, 0x01000},
            {MSR_MTRRFIX_4K_6,  0xF0000, 0x01000},
            {MSR_MTRRFIX_4K_7,  0xF8000, 0x01000}
        };

        uint64_t msr = 0;
        for (size_t i = 0; i < arraysize(fixedMTRRs); ++i)
        {
            status = sev_hal_get_msr_value(fixedMTRRs[i].MSR, &msr, NULL);
            if (status != SEV_STATUS_SUCCESS)
                goto end_invalid;
            uint32_t base = fixedMTRRs[i].base;
            for (size_t j = 0; j < 8; ++j)
            {
                if ((msr & 0x18) != 0x18)
                {
                    if (!exclude_from_mem_map(mem_map, base, base + fixedMTRRs[i].size - 1))
                        goto end_invalid;
                }
                base += fixedMTRRs[i].size;
                msr >>= 8;
            }
        }
    }

    /* Now throw out non-memory pages (again) from the memory map */
    mmd = &mem_map->MemRegion[0];
    for (size_t i = 0; i < mem_map->DescNum; ++i)
    {
        MEM_DESC *mms = &mem_map->MemRegion[i];
        if (mms->Type == MEM_DESC_TYPE_DRAM)
        {
            if (mmd != mms)
            {
                *mmd = *mms;
            }
            mmd++;
        }
    }
    mem_map->DescNum = mmd - &mem_map->MemRegion[0];

    status = SEV_STATUS_SUCCESS;
    goto end;

end_invalid:
    status = SEV_STATUS_INVALID_CONFIG;

end:
    return status;
}

sev_status_t sev_hal_read_initpkg7(uint32_t *initpkg7)
{
    sev_status_t status = SEV_STATUS_INVALID_CONFIG;
    uint32_t ccd, complex, core;

    sev_scfctp_init_pkg_regs_t *initpkg = gPersistent.initpkg_addr;

    if (!initpkg)
        return status;

    for (ccd = 0; ccd < MAX_CCDS; ccd++)
    {
        for (complex = 0; complex < MAX_COMPLEXES; complex++)
        {
            /*
            * Note: We need only one initpkg7 to be read,
            * MIN(MAX_NUM_CORES_PER_CCD, MAX_NUM_CORES_PER_CCD_RSDN)
            */
            for (core = 0; core < MAX_NUM_CORES_PER_CCD; core++)
            {
                if (is_core_enabled(gCurrentDieID, ccd, complex, core) == false)
                    continue;
                *initpkg7 = initpkg->init_regs[gCurrentDieID].socket_info[ccd].ccd_info[core].initpkg7;
                status = SEV_STATUS_SUCCESS;
                return status;
            }
        }
    }
    return status;
}

sev_status_t sev_hal_get_skip_rsmus(void)
{
    uint32_t rc = BL_OK;

    rc = Svc_GetSetSystemProperty(PROP_ID_GET_SKIP_RSMU, (uint8_t *)&gPersistent.skip_rsmus[0], sizeof(gPersistent.skip_rsmus));
    if (rc != BL_OK)
        return SEV_STATUS_HARDWARE_UNSAFE;
    else
        return SEV_STATUS_SUCCESS;
}

sev_status_t sev_hal_update_msr(uint32_t msr, uint32_t bit1, enum bitop op1, uint32_t bit2, enum bitop op2)
{
    /* This operation is only available for 0xC001_xxxx MSRs */
    if ((msr & 0xFFFF0000) != 0xC0010000)
        return SEV_STATUS_INVALID_PARAM;

    msr &= 0xFFFF;

    bit1 &= 63;
    bit2 &= 63;

    op1 &= BITOP_MASK;
    op2 &= BITOP_MASK;

    if (op1 == BITOP_NOP)
        bit1 = 0;
    if (op2 == BITOP_NOP)
        bit2 = 0;

    uint32_t operand = msr | (bit1 << 16) | (op1 << 22) | (bit2 << 24) | (op2 << 30);
    if (Svc_SendPspSmuMsg(PSPSMC_MSG_UpdateC001MSR, operand, NULL, 0) != BL_OK)
        return SEV_STATUS_HARDWARE_PLATFORM;

    if (gTotalDieNum > 1 && gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        sev_scmd_t scmd;
        memset(&scmd, 0, sizeof(scmd));
        scmd.id = SEV_SCMD_SET_MSR;
        scmd.scmd.set_msr.val = operand;
        if (sev_hal_master_to_slave(1, &scmd, sizeof(scmd)) != SEV_STATUS_SUCCESS)
        {
            return SEV_STATUS_INVALID_CONFIG;
        }
    }

    return SEV_STATUS_SUCCESS;
}
