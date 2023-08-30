// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sev_globals.h"
#include "sev_hal.h"
#include "x86_copy.h"

#define SEV_ASID_ADDR_MASK         (0x3FFull << (SEV_ASID_ADDR_SHIFT))
#define SEV_ASID_SME_ASID          (1023)

#define X86_HYPER_TRANSPORT_AREA   (12ull*1024ull*1024ull*1024ull)  /* Hyper Transport Area, 12 GB. Should compile to 0x3_0000_0000 */
#define X86_MAX_PHYS_ADDR          ((64ull*1024ull*1024ull*1024ull*1024ull) - X86_HYPER_TRANSPORT_AREA - 1ull) /* 64 TB. Should compile to 0x3FFC_FFFF_FFFF */

/**
 * When using this function, please pass in exclusive comparisons.
 * Note the difference in end values in the example memories below
 * Ex: inclusive is 0x0:0x500 - 0x500:0x1000
 * Ex: exclusive is 0x0:0x4FF - 0x500:0x0FFF
 */
bool ranges_overlap(uint64_t start1, uint64_t end1,
                    uint64_t start2, uint64_t end2)
{
    CLEAR_CBIT(start1);
    CLEAR_CBIT(end1);
    CLEAR_CBIT(start2);
    CLEAR_CBIT(end2);
    return (start1 <= end2) && (start2 <= end1);
}

static inline bool range_overlaps_aseg(uint64_t start, uint64_t end)
{
    return ranges_overlap(start, end, ASEG_BASE_ADDR, ASEG_LIMIT_ADDR);
}

static inline bool asid_bits_set(uint64_t addr)
{
    uint64_t mask = 0;

    /* Check to make sure all reserve range is not set, except for C-Bit */
    mask = SEV_ASID_ADDR_MASK & ~SEV_CBIT_MASK;
    return (addr & mask) > 0;
}

static inline bool x86_addresses_same(uint64_t addr1, uint64_t addr2)
{
    uint64_t mask = 0;

    mask = SEV_ASID_ADDR_MASK & ~SEV_CBIT_MASK;
    return ((addr1 & ~mask) == (addr2 & ~mask));
}

static unsigned skipRMPAddrValidation = 0;

void skip_rmp_addr_check(bool flag)
{
    if (flag)
        skipRMPAddrValidation++;
    else if (skipRMPAddrValidation > 0)
        skipRMPAddrValidation--;
}

void reset_rmp_addr_check(void)
{
    skipRMPAddrValidation = 0;
}

static bool skip_cpu_tmr_validation = false;
void skip_cpu_tmr_addr_check(bool flag)
{
    skip_cpu_tmr_validation = flag;
}

void reset_cpu_tmr_addr_check(void)
{
    skip_cpu_tmr_validation = false;
}

sev_status_t validate_address_range(uint64_t start, uint64_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    bool check_smm = true;
    uint64_t smm_limit = 0;
    uint64_t end = 0;
    size_t i = 0;

    if (size == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Exclude the c-bit from address checks */
    start &= ~SEV_CBIT_MASK;
    end = start + size - 1ULL;    /* Do exclusive range checking */

    /* Global vars get updated in sev_scmd_set_smm_range */
    smm_limit = gPersistent.smm_base + gPersistent.smm_length - 1ULL;    /* Do exclusive range checking */

    if (gPersistent.smm_base == 0 && gPersistent.smm_length == 0)
    {
        check_smm = false;
    }

    /*
     * The firmware must check that any given address or range of addresses
     * do not have the following properties:
     *  - Bits 46:43 != 0
     *  - Overlaps TSeg
     *  - Overlaps ASeg
     *  - Is above the max physical address (7FD_0000_0000)
     *  - Lies within any TMR that disallows x86 software access
     */
    if (asid_bits_set(start) ||                         /* ASID bits */
        asid_bits_set(end) ||
        start > X86_MAX_PHYS_ADDR ||                    /* Max address */
        end > X86_MAX_PHYS_ADDR   ||
        start > end ||                                  /* BUG! */
        gPersistent.smm_base > smm_limit ||             /* BUG! */
        range_overlaps_aseg(start, end))                /* ASEG */
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    /* Check against TMRs that are reserved but DFFlush has not been called
       to initialize them (not valid yet) */
    if (gSev.sev.context_initialized)
    {
        if (ranges_overlap(start, end, gSev.sev.es.reserved_tmr_base, gSev.sev.es.reserved_tmr_end))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }
    }

    if (check_smm)
    {
        if (ranges_overlap(start, end, gPersistent.smm_base, smm_limit))   /* TSEG */
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }
    }

    /* Check Ring Buffer Ranges */
    if (gpDram->perm.rb_config.rb_enable)
    {
        uint64_t check_start = 0;
        uint64_t check_end = 0;

        if (gpDram->perm.rb_config.low_priority_queue_size)
        {
            check_start = gpDram->perm.rb_config.cmd_ptr_low_priority_addr;
            check_end = gpDram->perm.rb_config.cmd_ptr_low_priority_addr + ((uint64_t)gpDram->perm.rb_config.low_priority_queue_size * PAGE_SIZE_4K) - 1ULL;
            if (ranges_overlap(start, end, check_start, check_end))
            {
                status = SEV_STATUS_INVALID_ADDRESS;
                goto end;
            }

            check_start = gpDram->perm.rb_config.status_ptr_low_priority_addr;
            check_end = gpDram->perm.rb_config.status_ptr_low_priority_addr + ((uint64_t)gpDram->perm.rb_config.low_priority_queue_size * PAGE_SIZE_4K) - 1ULL;
            if (ranges_overlap(start, end, check_start, check_end))
            {
                status = SEV_STATUS_INVALID_ADDRESS;
                goto end;
            }
        }

        if (gpDram->perm.rb_config.high_priority_queue_size)
        {
            check_start = gpDram->perm.rb_config.cmd_ptr_high_priority_addr;
            check_end = gpDram->perm.rb_config.cmd_ptr_high_priority_addr + ((uint64_t)gpDram->perm.rb_config.high_priority_queue_size * PAGE_SIZE_4K) - 1ULL;
            if (ranges_overlap(start, end, check_start, check_end))
            {
                status = SEV_STATUS_INVALID_ADDRESS;
                goto end;
            }

            check_start = gpDram->perm.rb_config.status_ptr_high_priority_addr;
            check_end = gpDram->perm.rb_config.status_ptr_high_priority_addr + ((uint64_t)gpDram->perm.rb_config.high_priority_queue_size * PAGE_SIZE_4K) - 1ULL;
            if (ranges_overlap(start, end, check_start, check_end))
            {
                status = SEV_STATUS_INVALID_ADDRESS;
                goto end;
            }
        }
    }

    /* Check TMRs */
    for (i = 0; i < TMR_NR_MAX; i++)
    {
        uint64_t tmr_base = 0, tmr_limit = 0;
        bool tmr_is_valid = false;

        if (skip_cpu_tmr_validation && (SEV_CPU_TMR == i || SEV_CPU_TMR2 == i))
            continue;

        status = sev_hal_get_tmr(i, &tmr_base, &tmr_limit, &tmr_is_valid);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Skip checking for SNP_RMP_CPU_TMR access when it's active as it is only used during SNP init and
           TMR address ranges will be passed in for checking */
        if (!tmr_is_valid || (i == SNP_RMP_CPU_TMR && tmr_is_valid) || (i == SNP_RMP_IOMMU_TMR && tmr_is_valid))
            continue;

        if (ranges_overlap(start, end, tmr_base, tmr_limit))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }
    }

    /* Check RMP */
    if (!skipRMPAddrValidation && ranges_overlap(start, end, gpDram->perm.rmp_base, gpDram->perm.rmp_end))
    {
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }
    /* Check memory map */
    status = validate_memory_map(&gpDram->mem_map, start, end);

end:
    return status;
}

inline uint64_t set_asid(x86_copy_op_t op, uint64_t addr, uint64_t asid)
{
    uint64_t address = addr;

    /* Clear ASID bits */
    address &= ~SEV_ASID_ADDR_MASK;

    /* if CBIT is set, then SME is enabled. Use the right key */
    if ((addr & SEV_CBIT_MASK) && (op == COPY_PLAINTEXT_IN || op == COPY_PLAINTEXT_OUT || op == COPY_PLAINTEXT_IN_OUT))
      asid = SEV_ASID_SME_ASID;

    /* Set the ASID bits */
    address |= (asid << SEV_ASID_ADDR_SHIFT);

    return address;
}

sev_status_t convert_x86_address(uint64_t *x86_addr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    if (x86_addr == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /*
     * This will set it with the appropriate ASID (511/255),
     * if the CBIT is not set, it will be set to ASID 0 which is
     * the same as before
     */
    *x86_addr = set_asid(COPY_PLAINTEXT_IN, *x86_addr, 0);

end:
    return status;
}

/**
 * psp_addr can be NULL if copying to x86 from x86
 */
static sev_status_t x86_copy(uint64_t x86_addr, void *psp_addr,
                             uint64_t x86_addr_inout_dest,
                             uint64_t size, uint32_t asid, x86_copy_op_t op)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    void *x86_buffer = NULL;
    void *x86_inout_dest_buffer = NULL;
    uint64_t start_address = 0, end_address = 0;
    uint64_t process_addr = 0;
    uint32_t process_size = 0;

    if (size == 0)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (op != COPY_CIPHERTEXT_IN_OUT && op != COPY_PLAINTEXT_IN_OUT)
    {
        /*
         * Validate if x86 memory crosses over more than one 64 megabyte range
         *   - PSP BL requires that memory mapped fit within a
         * 64 mb aligned boundary. We need to make sure the user
         * does not request for memory copy that will exceed the boundary.
         */
        if ((((x86_addr + size - 1) & X86_64MB_MASK) - (x86_addr & X86_64MB_MASK)) > X86_64MB_SIZE)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }
    }
    else
    {
        /* COPY_CIPHERTEXT_IN_OUT/COPY_PLAINTEXT_IN_OUT are only used by PAGE_MOVE
           and COPY, no crossing of 64MB is possible, so reject it if it is */
        /*
         * Validate if x86 memory crosses over 64 megabyte range
         *   - PSP BL requires that memory mapped fit within a
         * 64 mb aligned boundary. We need to make sure the user
         * does not request for memory copy that will exceed the boundary.
         */
        if ((x86_addr & X86_64MB_MASK) != ((x86_addr + size - 1) & X86_64MB_MASK))
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        if (x86_addr_inout_dest != 0)
        {
            if ((x86_addr_inout_dest & X86_64MB_MASK) != ((x86_addr_inout_dest + size - 1) & X86_64MB_MASK))
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto end;
            }
        }
    }

    /* Validate the address range before mapping it. */
    status = validate_address_range(x86_addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    start_address = x86_addr;
    end_address = x86_addr + size - 1ULL;

    /*
     * Genoa - we need to set ASID value to the appropriate system value if
     * C bit is already set. For encrypted memory for guest, set the
     * guest asid in the physical address
     */
    if (op == COPY_CIPHERTEXT_IN || op == COPY_CIPHERTEXT_OUT ||
        op == COPY_CIPHERTEXT_IN_OUT || CBIT_IS_SET(x86_addr))
    {
        x86_addr = set_asid(op, x86_addr, asid);
        start_address = set_asid(op, start_address, asid);
        end_address = set_asid(op, end_address, asid);
    }

    /* Map the x86 buffer */
    status = sev_hal_map_memory(start_address, &x86_buffer);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    switch (op)
    {
    case COPY_CIPHERTEXT_IN:
    case COPY_PLAINTEXT_IN:
    {
        if ((start_address & X86_64MB_MASK) == (end_address & X86_64MB_MASK))
        {
            /* Ensure that we're reading the latest data from DRAM */
            sev_hal_invalidate_dcache((uint32_t)x86_buffer, size);
            memcpy(psp_addr, x86_buffer, size);
        }
        else
        {
            uint8_t *chunk = (uint8_t *)psp_addr;

            process_addr = (start_address & X86_64MB_MASK) + X86_64MB_SIZE;
            process_size = (uint32_t)(process_addr - start_address);
            sev_hal_invalidate_dcache((uint32_t)x86_buffer, process_size);
            memcpy(chunk, x86_buffer, process_size);
            sev_hal_unmap_memory(x86_buffer);

            chunk += process_size;

            status = sev_hal_map_memory(process_addr, &x86_buffer);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
            process_size = (uint32_t)(end_address - process_addr + 1);
            sev_hal_invalidate_dcache((uint32_t)x86_buffer, process_size);
            memcpy(chunk, x86_buffer, process_size);
        }
        break;
    }
    case COPY_CIPHERTEXT_OUT:
    case COPY_PLAINTEXT_OUT:
        if ((start_address & X86_64MB_MASK) == (end_address & X86_64MB_MASK))
        {
            memcpy(x86_buffer, psp_addr, size);

            /* Ensure that the data is visible to the x86 */
            sev_hal_clean_dcache((uint32_t)x86_buffer, size);
        }
        else
        {
            uint8_t *chunk = (uint8_t *)psp_addr;
            process_addr = (start_address & X86_64MB_MASK) + X86_64MB_SIZE;
            process_size = (uint32_t)(process_addr - start_address);

            memcpy(x86_buffer, chunk, process_size);
            /* Ensure that the data is visible to the x86 */
            sev_hal_clean_dcache((uint32_t)x86_buffer, process_size);
            sev_hal_unmap_memory(x86_buffer);

            chunk += process_size;

            status = sev_hal_map_memory(process_addr, &x86_buffer);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            process_size = (uint32_t)(end_address - process_addr + 1);
            memcpy(x86_buffer, chunk, process_size);
            /* Ensure that the data is visible to the x86 */
            sev_hal_clean_dcache((uint32_t)x86_buffer, size);
        }
        break;
    case COPY_CIPHERTEXT_IN_OUT:
    case COPY_PLAINTEXT_IN_OUT:
        /* Validate the destination address range before mapping it. */
        status = validate_address_range(x86_addr_inout_dest, size);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_unmap_buf1;

        /* Ensure that the destination ASID is set */
        x86_addr_inout_dest = set_asid(op, x86_addr_inout_dest, asid);

        /* If source and destination the same, return Success */
        if (x86_addresses_same(x86_addr, x86_addr_inout_dest))
            goto exit_unmap_buf1;    /* Return success */

        /* Map the destination x86 buffer */
        status = sev_hal_map_memory(x86_addr_inout_dest, &x86_inout_dest_buffer);
        if (status != SEV_STATUS_SUCCESS)
            goto exit_unmap_buf1;

        /* Ensure that we're reading the latest data from DRAM */
        sev_hal_invalidate_dcache((uint32_t)x86_buffer, size);
        /* Source and destination may overlap, use move. */
        memmove(x86_inout_dest_buffer, x86_buffer, size);

        /* Ensure that the data is visible to the x86 */
        sev_hal_clean_dcache((uint32_t)x86_inout_dest_buffer, size);
        break;
    default:
        status = SEV_STATUS_UNSUPPORTED;    /* Unsupported operation */
    }

    if (x86_inout_dest_buffer)
    {
        sev_hal_invalidate_dcache((uint32_t)x86_inout_dest_buffer, size);
        sev_hal_unmap_memory(x86_inout_dest_buffer);
    }

exit_unmap_buf1:
    if (x86_buffer)
    {
        sev_hal_invalidate_dcache((uint32_t)x86_buffer, size);
        sev_hal_unmap_memory(x86_buffer);
    }

end:
    return status;
}

sev_status_t copy_to_x86(uint64_t x86_addr, void *psp_addr, uint64_t size)
{
    return x86_copy(x86_addr, psp_addr, NULL, size, 0, COPY_PLAINTEXT_OUT);
}

sev_status_t copy_from_x86(uint64_t x86_addr, void *psp_addr, uint64_t size)
{
    return x86_copy(x86_addr, psp_addr, NULL, size, 0, COPY_PLAINTEXT_IN);
}

sev_status_t copy_to_x86_from_x86(uint64_t x86_dest, uint64_t x86_src, uint64_t size)
{
    return x86_copy(x86_src, NULL, x86_dest, size, 0, COPY_PLAINTEXT_IN_OUT);
}

sev_status_t copy_to_x86_encrypted(uint64_t x86_addr, void *psp_addr,
                                   uint64_t size, uint32_t asid)
{
    return x86_copy(x86_addr, psp_addr, NULL, size, asid, COPY_CIPHERTEXT_OUT);
}

sev_status_t copy_from_x86_encrypted(uint64_t x86_addr, void *psp_addr,
                                     uint64_t size, uint32_t asid)
{
    return x86_copy(x86_addr, psp_addr, NULL, size, asid, COPY_CIPHERTEXT_IN);
}

sev_status_t copy_to_x86_encrypted_from_x86_encrypted(uint64_t x86_dest,
                                                      uint64_t x86_src,
                                                      uint64_t size,
                                                      uint32_t asid)
{
    return x86_copy(x86_src, NULL, x86_dest, size, asid, COPY_CIPHERTEXT_IN_OUT);
}

/* Always preceed with set_misc_read_sized_wrbkinvd() */
sev_status_t encrypt_memory(uint64_t x86_src, uint64_t x86_dest,
                            void *psp_addr, uint32_t size, uint32_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t dst_addr = x86_dest;

    /* (CSF-698) Dummy read from x86_dest (with c-bit) and throw away the result */
    SET_CBIT(dst_addr);
    status = copy_from_x86(dst_addr, psp_addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* (CSF-698) Dummy read from x86_dest (without c-bit) and throw away the result */
    CLEAR_CBIT(dst_addr);
    status = copy_from_x86(dst_addr, psp_addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = copy_from_x86(x86_src, psp_addr, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = copy_to_x86_encrypted(x86_dest, psp_addr, size, asid);

end:
    return status;
}

sev_status_t decrypt_memory(uint64_t x86_src, uint64_t x86_dest,
                            void *psp_addr, uint32_t size, uint32_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = copy_from_x86_encrypted(x86_src, psp_addr, size, asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = copy_to_x86(x86_dest, psp_addr, size);

end:
    return status;
}
