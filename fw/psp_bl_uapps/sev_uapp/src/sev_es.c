// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "crc.h"
#include "sev_es.h"
#include "sev_globals.h"
#include "sev_guest.h"
#include "sev_hal.h"
#include "sev_plat.h"
#include "sev_scmd.h"
#include "x86_copy.h"

typedef struct vmcb_save_area
{
    uint8_t  opaque[VMSA_OPAQUE_SIZE];
    uint64_t zeros;          /* 0x380 */
    uint64_t crc_paddr;      /* 0x388 */
} vmcb_save_area_t;

bool sev_es_platform_enabled(const sev_t *sev)
{
    return sev && (sev->sev.config_flags & SEV_CONFIG_ES_FLAG);
}

bool sev_es_guest_enabled(const sev_guest_t *guest)
{
    return guest && (guest->guest_flags & SEV_GUEST_FLAGS_ES_FLAG);
}

bool sev_es_allocation_guest_enabled(const sev_guest_t *guest)
{
    return guest && (guest->guest_flags & SEV_GUEST_FLAGS_ES_POOL_ALLOC_FLAG);
}

/**
 * Validate an ASID for SEV-ES operation
 */
sev_status_t sev_es_validate_asid(sev_guest_t *guest, size_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t min_sev_asid = 0;

    if (!guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_get_min_sev_asid(&min_sev_asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (sev_es_guest_enabled(guest))
    {
        /* For ES guests, 1 <= asid < MIN_SEV_ASID */
        if (asid < 1 || asid >= min_sev_asid)
            status = SEV_STATUS_INVALID_ASID;
    }
    else
    {
        /* For non-ES guests, MIN_SEV_ASID <= asid <= MAX_ASID */
        if (asid < min_sev_asid || asid > GetMaxSEVASID())
            status = SEV_STATUS_INVALID_ASID;
    }

end:
    return status;
}

/**
 * Reserve a Trusted Memory Region (TMR)
 */
sev_status_t sev_es_reserve_trusted_region(sev_es_platform_t *es, uint64_t base, size_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t flags = 0;
    uint32_t sdp_sec_level = TMR_SDP_MICROCODE_TRUST_LVL;
    uint32_t trust_level = 0;
    sev_scmd_t cmd;

    /* Used for notifying bootloader for TMR bounds */
    uint32_t BaseAddressLo = 0;
    uint32_t BaseAddressHi = 0;
    uint32_t LengthLo = 0;
    uint32_t LengthHi = 0;

    /* CSF-945: If SNP if enabled (RMP table is setup), TMR is 2M in size and
       alignment, else 1M in size and alignment */
    if (is_rmp_table_initialized())
    {
        if (!IS_ALIGNED_TO_2MB(base))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }

        if (size != SEV_ES_TMR_SIZE_SNP)    /* Must be exact size, according to spec */
        {
            status = SEV_STATUS_INVALID_LENGTH;
            goto end;
        }
    }
    else
    {
        if (!IS_ALIGNED_TO_1MB(base))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }

        if (size != SEV_ES_TMR_SIZE)    /* Must be exact size, according to spec */
        {
            status = SEV_STATUS_INVALID_LENGTH;
            goto end;
        }
    }

    /* Mask off C-Bit. */
    CLEAR_CBIT(base);

    status = validate_address_range(base, size); /* Do exclusive range checking */
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* CSF-961: Validate the memory map to make sure SEV-ES TMR doesn't overlap MMIO region */
    status = validate_memory_map(&gpDram->mem_map, base, base + size - 1ULL);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto end;
    }

    /*
     * A TMR is always 1MB-aligned. If the region between 'base' and 'limit'
     * crosses a 1MB boundary, then the data fabric will reserve 1MB on each
     * side of the boundary for the TMR. Since that exceeds the original 1MB
     * allocation of the OS, system instability results when the OS tries to
     * touch that memory.
     *
     * Decrement the size here to ensure that no more than 1MB is reserved.
     */
    es->enable_crc64 = true;

    /* Save "TMR SIZE" as passed in by the user */
    es->tmr_addr_start = base;
    es->tmr_addr_size = size - 1;

    /* First half of TMR block passed in by x86 is used for POOL INDEX */
    es->start_pool_addr = base;
    es->pool_block_size = (size / 2) - 1;

    /* Second half of TMR block is for actual CRC */
    es->start_crc_addr = base + (size / 2);
    es->crc_block_size = (size / 2) - 1;

    /* Get DF Security Level from DF::FtiSecLvlMapReg */
    /* This is needed for Genoa because on unsecure parts, the level would be 
       different based on security policy enablement (as well as secure parts).
       A lookup is required */
    status = get_df_sec_level(sdp_sec_level, &trust_level);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* In from Boot Loader of SEV-ES TMR so it can validate that C2P and
        other functions prevent access the SEV-ES TMR. */

    BaseAddressLo = (uint32_t)es->tmr_addr_start;
    BaseAddressHi = (uint32_t)(es->tmr_addr_start >> 32);
    LengthLo = (uint32_t)(es->tmr_addr_size + 1);
    LengthHi = (uint32_t)((es->tmr_addr_size + 1) >> 32);

    if (BL_OK != Svc_SevEsInfo(BaseAddressLo, BaseAddressHi, LengthLo, LengthHi))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Set up the pool TMR, half of TMR address space given by host */
    flags = TMR_CTRL_POOL_DEFAULTS;

    /* Disable TMR until pending writes to this region can be flushed */
    flags &= ~TMR_CTRL_VALID_FLAG;

    /* Setup the TMR on this die */
    status = sev_hal_set_tmr(SEV_ES_TMR_POOL, es->start_pool_addr, es->pool_block_size, trust_level, flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Set up the CRC TMR, half of TMR address space given by host */
    flags = TMR_CTRL_CRC_DEFAULTS_CRC64;

    /* Disable TMR until pending writes to this region can be flushed */
    flags &= ~TMR_CTRL_VALID_FLAG;

    /* Setup the TMR on this die */
    status = sev_hal_set_tmr(SEV_ES_TMR_CRC, es->start_crc_addr, es->crc_block_size, trust_level, flags);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Only send slave commands if this is the master die */
    if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
    {
        /* Setup the TMR on slave dies as well */
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_ID_SET_TMR;
        cmd.scmd.set_tmr.tmr_nr = SEV_ES_TMR_POOL;
        cmd.scmd.set_tmr.base = es->start_pool_addr;
        cmd.scmd.set_tmr.size = (es->pool_block_size >> TMR_X86_PHYS_ADDR_SHIFT);    /* Use the unaltered size here */
        cmd.scmd.set_tmr.trust_level = trust_level;
        cmd.scmd.set_tmr.flags = TMR_CTRL_POOL_DEFAULTS & ~TMR_CTRL_VALID_FLAG;
        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Setup the TMR on slave dies as well */
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_ID_SET_TMR;
        cmd.scmd.set_tmr.tmr_nr = SEV_ES_TMR_CRC;
        cmd.scmd.set_tmr.base = es->start_crc_addr;
        cmd.scmd.set_tmr.size = (es->crc_block_size >> TMR_X86_PHYS_ADDR_SHIFT);    /* Use the unaltered size here */
        cmd.scmd.set_tmr.trust_level = trust_level;
        cmd.scmd.set_tmr.flags = TMR_CTRL_CRC_DEFAULTS_CRC64 & ~TMR_CTRL_VALID_FLAG;

        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* Mark TMR address as reserved but not initialized so we can add it as
       a check in validate_address_range */
    es->reserved_tmr_base = base;
    es->reserved_tmr_end = base + size - 1;

end:
    return status;
}

/**
 * Initialize a reserved Trusted Memory Region (TMR)
 */
sev_status_t sev_es_init_trusted_region(sev_es_platform_t *es)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t tmr_base = 0, tmr_limit = 0;
    bool is_valid = false;

    if (!es)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Retrieve the address and length of the SEV-ES TMR region */
    status = sev_hal_get_tmr(SEV_ES_TMR_POOL, &tmr_base, &tmr_limit, &is_valid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (!is_valid)
    {
        sev_scmd_t cmd;

        /* Make sure it's the address we reserved */
        if (es->reserved_tmr_base != tmr_base)
        {
            status = ERR_INVALID_PARAMS;    /* Internal error */
            goto end;
        }
        es->reserved_tmr_base = PADDR_INVALID;
        es->reserved_tmr_end = PADDR_INVALID;

        /* Enable the TMR on the current die */
        status = sev_hal_enable_tmr(SEV_ES_TMR_CRC);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        /* Enable the TMR on the current die */
        status = sev_hal_enable_tmr(SEV_ES_TMR_POOL);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Enable the TMR on slave dies as well */
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_ID_ENABLE_TMR;
        cmd.scmd.enable_tmr.tmr_nr = SEV_ES_TMR_CRC;
        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Enable the TMR on slave dies as well */
        memset(&cmd, 0, sizeof(cmd));
        cmd.id = SEV_SCMD_ID_ENABLE_TMR;
        cmd.scmd.enable_tmr.tmr_nr = SEV_ES_TMR_POOL;
        status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* CSF-742 DECBRTL-18243 Write TMR Base Address to CPU TMR */
    status = write_sev_es_tmr_address_to_all_cores(tmr_base);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Initialize the CRC32 pool */
    status = pool_vcpu_init(&es->crc32_pool, tmr_base, es->start_crc_addr, tmr_limit - tmr_base + 1);

end:
    return status;
}

/**
 * Free a Trusted Memory Region (TMR)
 */
sev_status_t sev_es_release_trusted_region(sev_es_platform_t *es)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_scmd_t cmd;

    if (!es)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Clear the TMR contents */
    status = pool_vcpu_destroy(&es->crc32_pool);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Release the TMR on this die */
    status = sev_hal_reset_tmr(SEV_ES_TMR_CRC);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Release the TMR on this die */
    status = sev_hal_reset_tmr(SEV_ES_TMR_POOL);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Release the TMR on slave dies */
    memset(&cmd, 0, sizeof(cmd));
    cmd.id = SEV_SCMD_ID_RESET_TMR;
    cmd.scmd.reset_tmr.tmr_nr = SEV_ES_TMR_CRC;

    status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memset(&cmd, 0, sizeof(cmd));
    cmd.id = SEV_SCMD_ID_RESET_TMR;
    cmd.scmd.reset_tmr.tmr_nr = SEV_ES_TMR_POOL;

    status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Tell the bootloader the TMR is now released. Set all values to 0 */
    if (BL_OK != Svc_SevEsInfo( 0, 0, 0, 0 ))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

end:
    return status;
}

/**
 * Calculate the integrity checksum for the the VMCB state save area
 */
sev_status_t sev_es_setup_vmsa(sev_es_platform_t *es, sev_guest_t *guest,
                               uint8_t *psp_addr, size_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t allocated_block = 0;
    uint64_t tail_block = 0;
    uint32_t allocated_index = 0;
    es_vcpu_t *allocated_axi = NULL;
    es_vcpu_crc_t *allocated_crc = NULL;
    es_vcpu_t *tail_axi = NULL;

    uint64_t crc_block = 0;
    vmcb_save_area_t *vmsa = (vmcb_save_area_t *)psp_addr;

    if (!es || !guest || !psp_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (!sev_es_guest_enabled(guest))   // Works for SEV and SNP
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    if (length < VMSA_SIZE)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    /* SNP doesn't have a cpu pool because there's no TMR */
    if (guest->type == SEV_GUEST_TYPE_SEV)
    {
        /* Allocate a block from the VCPU pool */
        allocated_block = pool_vcpu_alloc(&es->crc32_pool, &allocated_index, &crc_block);
        if (allocated_block == 0)
        {
            status = SEV_STATUS_RESOURCE_LIMIT;
            goto end;
        }

        /* Set the checksum physical address */
        vmsa->zeros = 0;
        vmsa->crc_paddr = crc_block;

        /* Map the CRC block in the TMR */
        status = sev_hal_map_memory(allocated_block, (void **)&allocated_axi);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_free_block;

        /* Map the CRC block in the TMR */
        status = sev_hal_map_memory(crc_block, (void **)&allocated_crc);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_unmap;

        /* Calculate the CRC over the VMSA */
        status = crc64_vmsa((uint8_t *)vmsa, VMSA_CRC_SIZE, &allocated_crc->u.CRC64);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_unmap;

        /* Set the allocated block's next index to INVALID */
        allocated_axi->next_index = INVALID_BLOCK;

        /* Check the head index of the VCPU list in the guest.
         *   - If it's not initialized, initialize it and set it to the first index.
         *   - If it is initialized already, add it to the tail.
         */
        if (guest->es.head_index == INVALID_BLOCK)
        {
            /* Very first one, set both to the same index */
            guest->es.head_index = allocated_index;
            guest->es.tail_index = allocated_index;
        }
        else
        {
            /*
             * List already exist, add to the tail.
             * Map the tail index to u64 address so it can be mapped.
             */
            tail_block = pool_vcpu_index_to_addr64(&es->crc32_pool, guest->es.tail_index);
            if (tail_block == 0)
            {
                status = ERR_INVALID_PARAMS;
                goto exit_unmap;
            }

            /* Map the guest's tail VCPU block */
            status = sev_hal_map_memory(tail_block, (void **)&tail_axi);
            if (status != SEV_STATUS_SUCCESS)
                goto exit_unmap;

            /* Set the next index of the tail to the allocated index */
            tail_axi->next_index = allocated_index;
            sev_hal_clean_dcache((uint32_t)tail_axi, INDEX_BLOCK_SIZE);
            sev_hal_unmap_memory(tail_axi);

            /* Update tail index of the guest */
            guest->es.tail_index = allocated_index;
        }
        guest->es.num_vcpus++;
    }
    else                // SEV_GUEST_TYPE_SNP
    {
        vmsa->zeros = 0;
        vmsa->crc_paddr = (uint64_t)-1;
    }

exit_unmap:
    /* Unmap the VCPU block */
    if (allocated_axi)
        sev_hal_unmap_memory(allocated_axi);
    if (allocated_crc)
        sev_hal_unmap_memory(allocated_crc);

exit_free_block:
    /* On error, free the VCPU block */
    if (status != SEV_STATUS_SUCCESS && allocated_block > 0)
        pool_vcpu_free(&es->crc32_pool, allocated_block);

end:
    return status;
}

/**
 * Validate the integrity checksum for the the VMCB state save area
 */
sev_status_t sev_es_validate_vmsa(sev_es_platform_t *es, sev_guest_t *guest,
                                  uint8_t *psp_addr, uint32_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t crc_block = 0;
    void *crc_axi = NULL;
    uint32_t *crc32_axi = NULL;
    uint64_t *crc64_axi = NULL;
    uint32_t calculated_crc32 = 0;
    uint64_t calculated_crc64 = 0;
    bool found_crc_block = false;
    vmcb_save_area_t *vmsa = NULL;

    if (!es || !guest || !psp_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check and make sure the guest actually has allocated VCPUs to check */
    if (guest->es.num_vcpus == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (length < VMSA_SIZE)
    {
        status = SEV_STATUS_INVALID_LENGTH;
        goto end;
    }

    vmsa = (vmcb_save_area_t *)psp_addr;
    crc_block = vmsa->crc_paddr;
    if (crc_block == 0)
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /*
     * Search for a matching CRC block address in the guest's vcpu
     * list to make sure it is valid
     */
    status = pool_vcpu_find_crc_in_list(&es->crc32_pool, guest->es.head_index,
                                        guest->es.tail_index, crc_block,
                                        guest->es.num_vcpus, &found_crc_block);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (found_crc_block == false)
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* Map the CRC block in the TMR */
    status = sev_hal_map_memory(crc_block, (void **)&crc_axi);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    crc64_axi = (uint64_t *)crc_axi;
    /* Ensure that we read the latest data from DRAM */
    sev_hal_invalidate_dcache((uint32_t)crc64_axi, sizeof(uint64_t));

    /* Calculate the CRC over the VMSA */
    status = crc64_vmsa((uint8_t *)vmsa, VMSA_CRC_SIZE, &calculated_crc64);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_unmap;

    if (calculated_crc64 != *crc64_axi)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
        goto exit_unmap;
    }

exit_unmap:
    /* Unmap the CRC block */
    if (crc_axi)
        sev_hal_unmap_memory(crc_axi);

end:
    return status;
}

/**
 * Generate the bitmap to which the VMSA tweak will be applied. The kth bit of
 * the bitmap indicates that the kth quadword of the VMSA is tweaked.
 *
 * VMSA Register Protection feature enhancement DECBVRF-37257 states that
 * GPR/FPU/RIP registers are protected.
 *
 * GPR registers:
 *  RAX, RBX, RCX, RDX, RBP, RSI, RDI, RSP, R8, R9, R10, R11, R12, R13, R14, R15
 * FPU registers:
 *  FPREG_X87/FPREG_XMM/FPREG_YMM
 * RIP registers:
 *  RIP
 * FP registers:
 *  FPREG_KI, FPREG_ZMMHI, FPREG_HIZMM
 */
void sev_es_create_vmsa_bitmap(uint8_t *bitmap)
{
#if 1
    uint8_t vmsa_tweak_bitmap[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x88, // RIP, RSP, RAX
        0x00, 0x00, 0x00, 0x00, 0xEE, 0xFF, 0x00, 0x00, // RCX, RDX, RBX, RBP, RSI, RDI, R8-15
        0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // x87 Regs, XMM, YMM
        0xFF, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // YMM remainder
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00
    };
    memcpy(bitmap, vmsa_tweak_bitmap, VMSA_TWEAK_BITMAP_SIZE);
#else
    #define QUADWORD_SIZE(x) ((x) / sizeof(uint64_t))

    static const uint32_t REGISTERS[] = { VMSA_RAX, VMSA_RBX, VMSA_RCX, VMSA_RDX, VMSA_RBP,
                                          VMSA_RSI, VMSA_RDI, VMSA_RSP, VMSA_R8, VMSA_R9,
                                          VMSA_R10, VMSA_R11, VMSA_R12, VMSA_R13, VMSA_R14,
                                          VMSA_R15, VMSA_RIP, VMSA_FPREG_X87, VMSA_FPREG_XMM,
                                          VMSA_FPREG_YMM, VMSA_FPREG_KI, VMSA_FPREG_ZMMHI,
                                          VMSA_FPREG_HIZMM };
    static const uint32_t REGISTERS_SIZE[] = { 8, 8, 8, 8, 8,   /* Size in bytes */
                                               8, 8, 8, 8, 8,
                                               8, 8, 8, 8, 8,
                                               8, 8, 80, 256,
                                               256, 64, 512,
                                               1024 };
    #define REGISTERS_INDICES (sizeof(REGISTERS)/sizeof(REGISTERS[0]))

    uint32_t quadword_in_vmsa = 0, byte = 0, bit = 0;
    uint32_t i = 0, j = 0;
    memset(bitmap, 0, VMSA_TWEAK_BITMAP_SIZE);

    for (i = 0; i < REGISTERS_INDICES; i++)
    {
        for (j = 0; j < REGISTERS_SIZE[i]; j += 8)  // Some regs span multiple quadwords
        {
            /* Determine which quadword in the VMSA the register is in */
            quadword_in_vmsa = QUADWORD_SIZE(REGISTERS[i]+j);

            /* Figure out which bit in the bitmap to set */
            byte = quadword_in_vmsa / BITS_PER_BYTE;
            bit = quadword_in_vmsa % BITS_PER_BYTE;

            /* Set that bit in the bitmask */
            bitmap[byte] |= (1 << bit);
        }
    }
#endif
}

/* XOR the tweaked quadwords of the VMSA with the tweak value */
void sev_es_apply_vmsa_bitmap(uint8_t *vmsa, uint8_t *bitmap)
{
    uint64_t *vmsa_quadwords = (uint64_t *)vmsa;
    uint32_t byte_inc = 0, bit_inc = 0;
    uint8_t test_byte = 0, test_mask = 0;
    uint64_t random_tweak = 0;

    if (!vmsa || !bitmap)
    {
        return;
    }

    random_tweak = *(uint64_t *)(vmsa + VMSA_REG_PROT_NONCE);

    for (byte_inc = 0; byte_inc < VMSA_TWEAK_BITMAP_SIZE; byte_inc++) /* For each byte in the 64-byte bitmask */
    {
        test_byte = bitmap[byte_inc];
        for (bit_inc = 0; bit_inc < BITS_PER_BYTE; bit_inc++) /* For each bit in the byte */
        {
            test_mask = (1 << bit_inc);
            if (test_byte & test_mask) /* If bit is set, then tweak that quadword */
            {
                *vmsa_quadwords ^= random_tweak;
            }
            vmsa_quadwords++;
        }
    }
}

/**
 * Apply the XOR tweak to the VMSA
 */
sev_status_t sev_es_vmsa_xor_tweak(uint8_t *vmsa, uint8_t *bitmap)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!vmsa || !bitmap)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /*
     * If VmsaRegProt in the SEV_FEATURES field of VMSA is 1, then generate an
     * 8B random tweak value and write it to offset 300h of the VMSA. Then XOR
     * the tweaked quadwords of the VMSA with the tweak value. The quadwords of
     * the VMSA that are tweaked are determined by the family, model, stepping,
     * and microcode patch of the processor. This information is shared with the
     * guest via the PAGE_TYPE_SECRETS page.
     */
    if (VMSA_SEV_FEATURES_VMSA_REG_PROT_ENABLED(vmsa))
    {
        uint64_t random_tweak = 0;
        uint64_t *reg_prot_nonce = (uint64_t *)(vmsa + VMSA_REG_PROT_NONCE);

        /* Generate the 8B random tweak */
        status = sev_hal_trng((uint8_t *)&random_tweak, sizeof(random_tweak));
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Write the tweak to offset 300h of the VMSA */
        *reg_prot_nonce = random_tweak;

        /* Apply the bitmap to the VMSA */
        sev_es_apply_vmsa_bitmap(vmsa, bitmap);
    }

end:
    return status;
}
