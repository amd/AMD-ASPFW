// Copyright(C) 2019-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "crypto.h"
#include "sev_extended_errors.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_rmp.h"
#include "sscb.h"
#include "x86_copy.h"

/**
 * Populate the global variables with the RMP base and end addresses
 * 4. RMP_BASE and RMP_END must be set identically across all cores
 * 5. RMP_BASE must be 1 MB aligned
 * 6. RMP_END - RMP_BASE + 1 must be a multiple of 1 MB
 */
sev_status_t get_rmp_bounds()
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    uint64_t rmp_base = 0;
    uint64_t rmp_end = 0;

    /*
     * The RMP is located at the sPA specified in the MSR RMP_BASE (C001_0132)
     * and extends to the sPA specified in RMP_END (C001_0133).
     * 4. RMP_BASE and RMP_END must be set identically across all cores
     */
    status = get_rmp_base_end(&rmp_base, &rmp_end);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Make sure params passed in by the OS are within valid ranges */
    skip_rmp_addr_check(true);
    status = validate_address_range(rmp_base, rmp_end-rmp_base);
    skip_rmp_addr_check(false);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * 5. RMP_BASE must be 1 MB aligned
     * 6. RMP_END - RMP_BASE + 1 must be a multiple of 1 MB
     */
    if (!IS_ALIGNED_TO_1MB(rmp_base) ||
        !IS_ALIGNED_TO_1MB(rmp_end - rmp_base + 1))
    {
        status = SEV_STATUS_INVALID_CONFIG;
        goto end;
    }

    /*
     * 7. RMP_BASE and RMP_END must NOT have the C-bit set.
     * This is an errata... we SHOULD support having the RMP
     * encrypted using the host "key 0" UMC key... but the
     * other MPs are not yet up-to-speed on how to support
     * that and it's a security hole to permit it until they do.
     */
    if ((rmp_base | rmp_end) & SEV_CBIT_MASK)
    {
        status = SEV_STATUS_UNSUPPORTED;
        goto end;
    }

    gpDram->perm.rmp_base = rmp_base;
    gpDram->perm.rmp_end  = rmp_end;

end:
    return status;
}

/**
 * Takes in the system pAddr given to us by the hypervisor (right out of the
 * cmdbuf) and returns the RMP entry
 */
static sev_status_t local_get_rmp_paddr(uint64_t sPA, uint64_t *rmp_paddr)
{
    uint64_t sPA_no_cbit = sPA;

    /* Don't use C-bit in calculations. The RMP is indexed by physical page
       index, which does not include the C-bit (which is more of an attribute) */
    CLEAR_CBIT(sPA_no_cbit);

    /* Integer Overflow validation */
    if ((UINT64_MAX - RMP_ASID_COUNTERS_SIZE - (sPA_no_cbit >> ALIGNMENT_BITS_4K)*RMP_ENTRY_SIZE) < gpDram->perm.rmp_base)
        return SEV_ERROR(ERR_INVALID_PARAMS, EXT_ERR_048);

    *rmp_paddr = gpDram->perm.rmp_base + RMP_ASID_COUNTERS_SIZE + (sPA_no_cbit >> ALIGNMENT_BITS_4K)*RMP_ENTRY_SIZE;

    /* If they request an addr that's beyond the range that's mapped (Default pages) */
    /* This can be the ONLY time we return SEV_STATUS_INVALID_PAGE_STATE when calling
       get_rmp_paddr to know it's a Default page. Every other error must return
       something else */
    if (*rmp_paddr > gpDram->perm.rmp_end)
    {
        *rmp_paddr = 0;
        return SEV_ERROR(SEV_STATUS_INVALID_PAGE_STATE, EXT_ERR_049);
    }

    return SEV_STATUS_SUCCESS;
}

/**
 * Takes in the system pAddr given to us by the hypervisor (right out of the
 * cmdbuf) and returns the RMP entry
 * This is the normal function that you would call
 */
sev_status_t get_rmp_paddr(uint64_t sPA, uint64_t *rmp_paddr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t sPA_no_cbit = sPA;
    uint64_t rmp_base_no_cbit = gpDram->perm.rmp_base;
    uint64_t rmp_end_no_cbit = gpDram->perm.rmp_end;

    CLEAR_CBIT(sPA_no_cbit);
    CLEAR_CBIT(rmp_base_no_cbit);
    CLEAR_CBIT(rmp_end_no_cbit);

    /* Make sure address passed in is not the part of the RMP that covers itself
       The hypervisor should never be pointing the PSP at the RMP, no matter what */
    if (sPA_no_cbit >= rmp_base_no_cbit && sPA_no_cbit <= rmp_end_no_cbit)
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    status = local_get_rmp_paddr(sPA, rmp_paddr);

end:
    return status;
}

/**
 * This ONLY gets called in setup_and_validate_initial_rmp_table where we want to pass
 * in an address that is an overlapping entry of the RMP itself
 */
static sev_status_t get_rmp_paddr_overlap(uint64_t sPA, uint64_t *rmp_paddr)
{
    return local_get_rmp_paddr(sPA, rmp_paddr);
}

/**
 * This function takes in the physical address of an RMP entry (after calling
 *  get_rmp_paddr on the sPA gotten from the cmdbuf) and copies
 *  the data from it (x86 memory) into input param
 */
sev_status_t rmp_entry_read(uint64_t rmp_paddr, rmp_entry_t *rmp_data)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    skip_rmp_addr_check(true);
    status = copy_from_x86(rmp_paddr, rmp_data, RMP_ENTRY_SIZE);
    skip_rmp_addr_check(false);

    return status;
}

/**
 * Write back to x86 memory
 */
sev_status_t rmp_entry_write(uint64_t rmp_paddr, rmp_entry_t *rmp_data)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    skip_rmp_addr_check(true);

    /*
     * When you write to an RMP entry for a 4kB page that is 2MB aligned, you
     * need to do the following:
     * 1. Read the entry and set RMP.ASID=0x3ff, which will lock the entry from uCode
     *   a. Only write bytes 4-8 containing the ASID; don't clobber the Subpage
     *      count in case uCode writes from under us it between our read and write
     *      (to lock the entry).
     * 2. Re-read the entry, in case the Subpage count changed
     * 3. Write the desired RMP entry in the following order and manner:
     *   a. Write bytes 0-3 and 8-16 of the RMP as desired
     *   b. Write bytes 4-7 with a single 32-bit write, restoring RMP.ASID to its original value
     * Note: 0x3ff is an invalid ASID used specifically here to prevent the x86
     *       from racing to the 2MB RMP entry and updating RMP.Sub_Pages count
     * Note: This is mentioned at the end of Appendix A of the SNP hw spec
     */
    if ((rmp_data->q1.f.page_size == DRAM_PAGE_SIZE_4K) && IS_ALIGNED_TO_8KB(rmp_paddr))
    {
        rmp_entry_t rmp_invalid_asid;

        /* 1. Read the entry */
        status = rmp_entry_read(rmp_paddr, &rmp_invalid_asid);  /* Read the entry */
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* 1a. Set RMP.ASID=0x3ff. Write just the bytes 4-8 containing the ASID; don't clobber subpage count */
        rmp_invalid_asid.q1.f.asid = RMP_INVALID_ASID;  /* Set the asid to 0x3ff */
        status = copy_to_x86(rmp_paddr+4, ((uint8_t *)&rmp_invalid_asid)+4, 4);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* 2. Re-read the entry in case Subpage count changed from under us */
        status = rmp_entry_read(rmp_paddr, &rmp_invalid_asid);  /* Read the entry */
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        rmp_data->q1.f.subpage_count = rmp_invalid_asid.q1.f.subpage_count;

        /* 3a. Write (new) bytes 0-3 and 8-16 of the RMP as desired */
        status = copy_to_x86(rmp_paddr, rmp_data, 4);  /* Bytes 0-3 */
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = copy_to_x86(rmp_paddr+sizeof(rmp_quadword1_t), &rmp_data->q2, RMP_QUADPAGE_SIZE); /* Bytes 8-16 */
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* 3b. Write (new) bytes 4-7 with a single 32-bit write, restoring RMP.ASID to its original value */
        /* Also ensuring the lock bit is written last to prevent anyone else from
           touching the entry (RMPUPDATE) until we're done writing */
        status = copy_to_x86(rmp_paddr+4, ((uint8_t *)rmp_data)+4, 4); /* Bytes 4-7 */
    }
    else
    {
        /* Write the second quadword before writing the first quad word (with immutable bit) */
        status = copy_to_x86(rmp_paddr+sizeof(rmp_quadword1_t), &rmp_data->q2, RMP_QUADPAGE_SIZE);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = copy_to_x86(rmp_paddr, rmp_data, RMP_QUADPAGE_SIZE);
    }

end:
    skip_rmp_addr_check(false);
    return status;
}

/**
 * Write back to x86 memory always, without checking and overwriting subpagecount
 * Used for update_rmp_2mb_subpage_count that is called in SNP INIT which just requires
 * the entry to be updated as is (i.e. with the new subpage count)
 */
static sev_status_t rmp_entry_write_direct(uint64_t rmp_paddr, rmp_entry_t *rmp_data)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!(gSSCB.SSCB_Control & SSCB_RMP_MASK))
         return SEV_STATUS_INVALID_CONFIG;

    /* Write the second quadword before writing the first quad word (with immutable bit) */
    status = copy_to_x86(rmp_paddr+sizeof(rmp_quadword1_t), &rmp_data->q2, RMP_QUADPAGE_SIZE);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    status = copy_to_x86(rmp_paddr, rmp_data, RMP_QUADPAGE_SIZE);

end:
    return status;
}

/**
 * This function takes in the system physical address of am mdata entry in a
 * metadata page (right out of the cmd buffer) and copies the data from it
 * (x86 memory) into input param
 */
sev_status_t mdata_entry_read(uint64_t mdata_paddr, snp_metadata_page_t *mdata_data)
{
    return copy_from_x86(mdata_paddr, mdata_data, sizeof(snp_metadata_page_t));
}

/**
 * Write back to x86 memory
 */
sev_status_t mdata_entry_write(uint64_t mdata_paddr, snp_metadata_page_t *mdata_data)
{
    return copy_to_x86(mdata_paddr, mdata_data, sizeof(snp_metadata_page_t));
}

/**
 * Given an RMP entry, return the state using the snp_page_state table
 * SNP_PAGE_STATE_FIRMWARE_IOMMU should return INVALID. That is locked once set
 *  and should never be passed into firmware again
 */
snp_page_state_t rmp_entry_get_state(rmp_entry_t *entry)
{
    snp_page_state_t result = SNP_PAGE_STATE_INVALID;
    rmp_fields_t *f = &entry->q1.f;

    if (f->assigned == 0 && f->validated == 0 && f->asid == 0 && f->immutable == 0)
    {
        result = SNP_PAGE_STATE_HYPERVISOR;
    }
    else if (f->assigned == 0 && f->validated == 0 && f->asid == 0 && f->immutable == 1)
    {
        result = SNP_PAGE_STATE_HV_FIXED;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid == 0 && f->immutable == 1 &&
             f->gpa == 0 && f->vmsa == 0)
    {
        result = SNP_PAGE_STATE_FIRMWARE;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid == 0 && f->immutable == 0 &&
             f->lock == 0)
    {
        result = SNP_PAGE_STATE_RECLAIM;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid == 0 && f->immutable == 1 &&
             f->gpa == 0 && f->vmsa == 1)
    {
        result = SNP_PAGE_STATE_CONTEXT;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid == 0 && f->immutable == 1 &&
             RMP_GET_GPA(f->gpa) > 0 && RMP_GET_GPA_STATE(f->gpa) == RMP_GPA_STATE_METADATA)
    {
        result = SNP_PAGE_STATE_METADATA;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid > 0 && f->immutable == 1)
    {
        result = SNP_PAGE_STATE_PRE_GUEST;
    }
    else if (f->assigned == 1 && f->validated == 1 && f->asid > 0 && f->immutable == 1)
    {
        result = SNP_PAGE_STATE_PRE_SWAP;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid > 0 && f->immutable == 0)
    {
        result = SNP_PAGE_STATE_GUEST_INVALID;
    }
    else if (f->assigned == 1 && f->validated == 1 && f->asid > 0 && f->immutable == 0)
    {
        result = SNP_PAGE_STATE_GUEST_VALID;
    }
    else if (f->assigned == 1 && f->validated == 0 && f->asid == 0 && f->immutable == 1 &&
             RMP_GET_GPA(f->gpa) == 1 && RMP_GET_GPA_STATE(f->gpa) == RMP_GPA_STATE_FW_IOMMU && f->vmsa == 0)
    {
        result = SNP_PAGE_STATE_FIRMWARE_IOMMU;
    }
    else
    {
        result = SNP_PAGE_STATE_INVALID;
    }

    return result;
}

/**
 * Call get_rmp_paddr, rmp_entry_read, and rmp_entry_get_state all at once
 * Takes the x86_addr (sPA) and returns the corresponding RMP entry address,
 * RMP entry, and page state according to that RMP entry
 *
 * Note that it's this function's job to determine that this is a DEFAULT page
 *      and will return SUCCESS with a state of DEFAULT. It's up to the user to
 *      know that DEFAULT pages don't have rmp entries or RMP pAddrs
 */
inline sev_status_t rmp_get_addr_entry_state(uint64_t x86_paddr, uint64_t *rmp_paddr,
                                             rmp_entry_t *rmp_entry, snp_page_state_t *state)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    status = get_rmp_paddr(x86_paddr, rmp_paddr);   /* Get RMP entry for page given sPA */
    if (status == SEV_STATUS_INVALID_PAGE_STATE)
    {
        *state = SNP_PAGE_STATE_DEFAULT;
        status = SEV_STATUS_SUCCESS; /* Be careful with this! DEFAULT pages don't have rmp_entries */
        goto end;
    }
    else if (status == SEV_STATUS_SUCCESS)
    {
        status = rmp_entry_read(*rmp_paddr, rmp_entry); /* Do x86 copy to pull RMP entry into readable memory */
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        *state = rmp_entry_get_state(rmp_entry);
    }
    else
        goto end;

end:
    return status;
}

/**
 * Returns the state of the RMPBase. Only to be used in sev init_common.
 * This skips the usual check in get_rmp_paddr of returning an error when
 * you try to get the address of a page covering the RMP itself
 */
snp_page_state_t rmp_get_state_rmp_base(void)
{
    uint64_t rmp_paddr = 0;
    rmp_entry_t rmp_entry;

    if (local_get_rmp_paddr(gpDram->perm.rmp_base, &rmp_paddr) != SEV_STATUS_SUCCESS)
        return SNP_PAGE_STATE_INVALID;
    if (rmp_entry_read(rmp_paddr, &rmp_entry) != SEV_STATUS_SUCCESS)
        return SNP_PAGE_STATE_INVALID;
    return rmp_entry_get_state(&rmp_entry);
}

static sev_status_t map_rmp_table(uint64_t x86_addr, void **x86_buffer, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    void *axi_buffer = NULL;

    /* Map the x86 buffer */
    status = sev_hal_map_memory_ccp(x86_addr, &axi_buffer, size);
    if (status != SEV_STATUS_SUCCESS)
         goto end;
    *x86_buffer = axi_buffer;

end:
    return status;
}

#define ADDRESS_LO(X) (uint32_t)(X)
#define ADDRESS_HI(X) 0

/**
 * Note, the way this is works is we set a 4K page to 0 as our 'source' and
 * then we set the Fixed bit (bit 31) in the source pointer, so that instead of copying
 * x bytes from source to dest, we copy 4B of source over and over instead of
 * advancing to the next source address. It's an AXI feature.
 * See section 12.1.4 of CCP TRM. Setting Fixed causes CCP to use an AXI burst
 * type of FIXED with a data size of 32 bits
 */
sev_status_t fill_zeroes(const uint32_t *pSource, uint32_t *pDest, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    bl_ccp_cmd_desc cmds;
    bl_ccp_cmd_desc *pCcpCmd = &cmds;

    uint32_t eids = 0;

    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCcpCmd->cmd0.fields.hoc = 0;
    pCcpCmd->cmd0.fields.ioc = 1;  // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som = 0;  // 1;
    pCcpCmd->cmd0.fields.eom = 1;
    pCcpCmd->cmd0.fields.prot = 0;
    pCcpCmd->cmd0.fields.engine = CCP_ENGINE_PT;
    pCcpCmd->cmd0.fields.function = 0;

    pCcpCmd->cmd1.length = size;

    pCcpCmd->cmd2.source_pointer_lo = ADDRESS_LO(pSource);
    pCcpCmd->cmd3.fields.source_pointer_hi = ADDRESS_HI(pSource);
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id = 0;
    pCcpCmd->cmd3.data |= CCP_DWORD3_FIXED_BIT; /* Set source address to fixed - need to put this bitfield into BL */

    pCcpCmd->cmd4.dest_pointer_lo = ADDRESS_LO(pDest);
    pCcpCmd->cmd5.fields.dest_pointer_hi = 0;
    pCcpCmd->cmd5.fields.dest_mem = CCP_MEM_LOCAL;

    /* No need to wait for CCP to complete the command, so we can continue. */
    status = sev_hal_enqueue_and_run_commands(&cmds, &eids, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Wait for HMAC commands to complete */
    status = sev_hal_query_commands(&eids, 1, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

/**
 *  fill_rmp_block_zeros
 *  Parameters:   start_address (64 bit starting address)
 *                end_address   (64 bit ending address, inclusive)
 *
 *  Fill a block of RMP tables with 0's. The function will take care of
 *  64 MB boundaries as required by bootloader mapping
 */
static sev_status_t fill_rmp_block_zeroes(uint64_t start_address, uint64_t end_address)
{
    uint64_t process_addr = 0;
    void *x86_buffer = NULL;
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t process_size = 0;
    const uint32_t zero = 0;

    /*
     * If it's within the same 64 megabyte boundary, just check it once
     * Inclusive check for 'if' (0x1000 - 0x2000), so need the +1
     * The 'else' bracket shouldn't be +1 because it's calculating the next
     *    aligned address, so it'll be 64 megabyte already.
     */
    if ((start_address & X86_64MB_MASK) == (end_address & X86_64MB_MASK))
    {
        process_size = (uint32_t)(end_address - start_address) + 1;

        /* Both are within 64 megabyte boundary */
        status = map_rmp_table(start_address, &x86_buffer, process_size);
        if (SEV_ERROR(status, EXT_ERR_050) != SEV_STATUS_SUCCESS)
            goto end;

        status = fill_zeroes(&zero, x86_buffer, process_size);
        if (SEV_ERROR(status, EXT_ERR_051) != SEV_STATUS_SUCCESS)
            goto end;

        sev_hal_unmap_memory(x86_buffer);
    }
    else
    {
        /* Not in the same 64MB x86 boundary, do the first unaligned x86 first */
        process_addr = (start_address & X86_64MB_MASK) + X86_64MB_SIZE;

        process_size = (uint32_t)(process_addr - start_address);
        status = map_rmp_table(start_address, &x86_buffer, process_size);
        if (SEV_ERROR(status, EXT_ERR_052) != SEV_STATUS_SUCCESS)
            goto end;

        status = fill_zeroes(&zero, x86_buffer, process_size);
        if (SEV_ERROR(status, EXT_ERR_053) != SEV_STATUS_SUCCESS)
            goto end;
        sev_hal_unmap_memory(x86_buffer);

        /* Now the buffer is aligned, validate the rest, 64 MB at a time */
        while (process_addr < end_address)
        {
            if ((end_address - process_addr) < X86_64MB_SIZE)
                process_size = (uint32_t)(end_address - process_addr) + 1;
            else
                process_size = X86_64MB_SIZE;

            status = map_rmp_table(process_addr, &x86_buffer, process_size);
            if (SEV_ERROR(status, EXT_ERR_054) != SEV_STATUS_SUCCESS)
                goto end;

            status = fill_zeroes(&zero, x86_buffer, process_size);
            if (SEV_ERROR(status, EXT_ERR_055) != SEV_STATUS_SUCCESS)
                goto end;
            sev_hal_unmap_memory(x86_buffer);

            process_addr += X86_64MB_SIZE;
        }
    }

end:
    return status;
}

static sev_status_t initialize_rmp_entries_range(uint64_t rmp_entry_start,
                                                 uint64_t rmp_entry_end,
                                                 snp_page_state_t page_state)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    rmp_entry_t rmp_entry;
    uint32_t entry_size = RMP_ENTRY_SIZE;

    /* Create Initialization Struct */
    memset(&rmp_entry, 0, sizeof(rmp_entry));
    switch (page_state)
    {
        case SNP_PAGE_STATE_FIRMWARE:
            rmp_entry.q1.f.assigned = 1;
            rmp_entry.q1.f.validated = 0;
            rmp_entry.q1.f.asid = 0;
            rmp_entry.q1.f.immutable = 1;
            rmp_entry.q1.f.lock = rmp_entry.q1.f.immutable;
            rmp_entry.q1.f.gpa = PADDR_TO_GPA_FIELD((uint64_t)0ULL << RMP_ENTRY_GPA_SHIFT, RMP_GPA_STATE_FIRMWARE);
            rmp_entry.q1.f.vmsa = 0;
            break;
        case SNP_PAGE_STATE_FIRMWARE_IOMMU:
            rmp_entry.q1.f.assigned = 1;
            rmp_entry.q1.f.validated = 0;
            rmp_entry.q1.f.asid = 0;
            rmp_entry.q1.f.immutable = 1;
            rmp_entry.q1.f.lock = rmp_entry.q1.f.immutable;
            rmp_entry.q1.f.gpa = PADDR_TO_GPA_FIELD((uint64_t)1ULL << RMP_ENTRY_GPA_SHIFT, RMP_GPA_STATE_FW_IOMMU);
            rmp_entry.q1.f.vmsa = 0;
            break;
        case SNP_PAGE_STATE_RECLAIM:
            rmp_entry.q1.f.assigned = 1;
            rmp_entry.q1.f.validated = 0;
            rmp_entry.q1.f.asid = 0;
            rmp_entry.q1.f.immutable = 0;
            rmp_entry.q1.f.lock = 0;
            rmp_entry.q1.f.gpa = 0;
            rmp_entry.q1.f.vmsa = 0;
            break;
        default:
            /* If Hypervisor do nothing and clear page tables, else return error */
            if (page_state != SNP_PAGE_STATE_HYPERVISOR)
            {
                status = ERR_INVALID_PARAMS;
                goto end;
            }
            break;
    }

    while (rmp_entry_start <= rmp_entry_end)
    {
        /* Use a local copy as rmp_entry_write modifies the data passed in */
        rmp_entry_t local_entry = rmp_entry;
        status = rmp_entry_write(rmp_entry_start, &local_entry);
        if (status != SEV_STATUS_SUCCESS)
             goto end;
        rmp_entry_start += entry_size;
    }

end:
    return status;
}

#if 0
/* Unused, save until release */
static sev_status_t compare_initial_rmp_entries_range(uint64_t rmp_entry_start,
                                                      uint64_t rmp_entry_end)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    rmp_vmpl_entry_t rmp_entry;
    rmp_vmpl_entry_t *x86_rmp_vmpl_entry = NULL;
    void *x86_addr = NULL;
    uint64_t process_addr = 0;
    uint32_t entry_size = RMP_VMPL_ENTRY_SIZE;
    uint32_t process_size = 0;

    /* Create Comparison Struct */
    memset(&rmp_entry, 0, sizeof(rmp_entry));
    rmp_entry.q1.f.immutable = 1;
    rmp_entry.q1.f.lock = rmp_entry.q1.f.immutable;
    rmp_entry.q1.f.assigned = 1;

    /* If both are within the same 64MB range, do not have to worry about overlap */
    if ((rmp_entry_start & X86_64MB_MASK) == (rmp_entry_end & X86_64MB_MASK))
    {
        process_size = (uint32_t)(rmp_entry_end - rmp_entry_start) + 1;

        /* Both are within 64 megabyte boundary */
        status = map_rmp_table(rmp_entry_start, &x86_addr, process_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        x86_rmp_vmpl_entry = (rmp_vmpl_entry_t *)x86_addr;
        while (rmp_entry_start <= rmp_entry_end)
        {
            if (x86_rmp_vmpl_entry->rmp.val != rmp_entry.q1.val)
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto exit_unmap;
            }
            x86_rmp_vmpl_entry++;
            rmp_entry_start += entry_size;
        }
        /* Unmap */
        sev_hal_unmap_memory(x86_addr);
        x86_addr = NULL;
    }
    else
    {
        /* Not in the same 64MB x86 boundary, do the first unaligned x86 first */
        process_addr = (rmp_entry_start & X86_64MB_MASK) + X86_64MB_SIZE;

        process_size = (uint32_t)(process_addr - rmp_entry_start);
        status = map_rmp_table(rmp_entry_start, &x86_addr, process_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        x86_rmp_vmpl_entry = (rmp_vmpl_entry_t *)x86_addr;
        while (rmp_entry_start < rmp_entry_end)
        {
            if (x86_rmp_vmpl_entry->rmp.val != rmp_entry.q1.val)
            {
                status = SEV_STATUS_INVALID_PARAM;
                goto exit_unmap;
            }
            x86_rmp_vmpl_entry++;
            rmp_entry_start += entry_size;
        }
        sev_hal_unmap_memory(x86_addr);

        /* Now the buffer is aligned, validate the rest, 64 MB at a time */
        while (process_addr <= rmp_entry_end)
        {
            if ((rmp_entry_end - process_addr) < X86_64MB_SIZE)
                process_size = (uint32_t)(rmp_entry_end  - process_addr);
            else
                process_size = X86_64MB_SIZE;

            status = map_rmp_table(process_addr, &x86_addr, process_size);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            x86_rmp_vmpl_entry = (rmp_vmpl_entry_t *)x86_addr;
            while (process_addr < (process_addr + process_size))
            {
                if (x86_rmp_vmpl_entry->rmp.val != rmp_entry.q1.val)
                {
                    status = SEV_STATUS_INVALID_PARAM;
                    goto exit_unmap;
                }
                x86_rmp_vmpl_entry++;
                process_addr += entry_size;
            }
            sev_hal_unmap_memory(x86_addr);

            process_addr += X86_64MB_SIZE;
        }
    }
    goto end;

exit_unmap:
    if (x86_addr)
    {
        sev_hal_unmap_memory(x86_addr);
    }

end:
    return status;
}
#endif

/**
 * Initialize the RMP table
 * The firmware alters the RMP such that:
 *   Pages of the RMP are in the Firmware state
 *   All other pages covered by the RMP are in the Hypervisor state
 * The firmware also initializes any microarchitectural data structures within the RMP
 *
 *  Option 1: RMP is in middle of DRAM      Option 2: RMP is at very end of DRAM
 *
 * --------------  rmp base                 -------------- rmp base
 * | 16KB offset|  <- hypervisor            | 16KB offset|  <- hypervisor
 * --------------                           --------------
 * |   (DRAM)   |  <- hypervisor            |   (DRAM)   |  <- hypervisor
 * -------------- rmp_entry_start           -------------- rmp_entry_start
 * | overlapping|                           | overlapping|
 * | RMP        |  <- firmware              | RMP        |  <- firmware
 * | entries    |                           | entries    |
 * -------------- rmp_entry_end             -------------- rmp end/rmp_entry_end
 * |   (DRAM)   |  <- hypervisor
 * -------------- rmp end
 *
 * In Option 1, DRAM and the 16KB portion get set to hypervisor, the overlapping
 *  RMP gets set to firmware, and everything after the overlapping RMP gets set
 *  to hypervisor.
 * In Option 2: all DRAM including the 16KB portion get set to hypervisor, and
 *  then the overlapping RMP gets set to firmware.
 */
#if 0
sev_status_t setup_and_validate_initial_rmp_table(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    uint64_t rmp_base_start = 0;
    uint64_t rmp_base_end = 0;
    uint64_t rmp_entry_start = 0;   /* Where is the RMP base inside of the RMP table (overlapping ranges) */
    uint64_t rmp_entry_end = 0;     /* Where is the RMP end inside of the RMP table (overlapping ranges) */

    rmp_base_start = gpDram->perm.rmp_base;
    rmp_base_end = gpDram->perm.rmp_end;

    memset(gpSevScratchBuf, 0, 4096);

    status = get_rmp_paddr_overlap(rmp_base_start, &rmp_entry_start);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_PARAM;      /* RMP does not cover itself */
        goto end;
    }

    /*
     * Get overlapping entry ending point. Ending point is pointing to the
     * beginning of the RMP entry, we need to get to the end
     */
    status = get_rmp_paddr_overlap(rmp_base_end, &rmp_entry_end);
    if (status != SEV_STATUS_SUCCESS)
    {
        status = SEV_STATUS_INVALID_PARAM;      /* RMP does not cover itself */
        goto end;
    }

    /*
     * Note: rmp_entry_end contains the BEGINNING address for the end of the overlap
     * rmp entry. Need to adjust for the actual end address of the rmp_entry
     */
    rmp_entry_end += sizeof(rmp_entry_t) - 1;

    /*
     * RMP address entries can be:
     *      - Somewhere in the middle
     *      - At the end of the rmp table
     * RMP address entries cannot be:
     *      - The beginning because there is an offset of zero of buffers
     *      - Out of range completely
     */
#if 0
    /* Fill from RMP_BASE_START to RMP_BASE_END */
    status = fill_rmp_block_zeroes(rmp_base_start, rmp_base_end);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
#endif
    /* Set the rmp_entry_start to rmp_entry_end to FIRMWARE state (RMP entries that cover the RMP) */
    status = initialize_rmp_entries_range(rmp_entry_start, rmp_entry_end, SNP_PAGE_STATE_FIRMWARE);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* RMP entry is either at the end or the middle, either case, fill from rmp_base_start to rmp_entry start - 1 with 0s */
    /* Fill from RMP_BASE_START to before entry start */
    status = fill_rmp_block_zeroes(rmp_base_start, rmp_entry_start - 1);
    if (status != SEV_STATUS_SUCCESS)
         goto end;

    if (rmp_base_end != rmp_entry_end)
    {
        /* Fill from end of rmp entry to before entry start */
        status = fill_rmp_block_zeroes(rmp_entry_end+1, rmp_base_end);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    /* CSF-860: Mark 2MB subpage count for the RMP overlapping entries */
    status = set_rmp_sub_page_count(rmp_base_start, rmp_base_end, true);

end:
    return status;
}
#endif

/**
 * Uses the 16KB region at the start of RMP_BASE to get the counter for
 * the input ASID.
 */
sev_status_t check_rmp_for_asid(uint32_t asid, uint64_t *count)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    rmp_asid_counters_t *counter_map = NULL;

    if (asid >= RMP_NUM_ASID_COUNTERS)
        return SEV_STATUS_INVALID_ASID;

    skip_rmp_addr_check(true);
    status = sev_hal_map_memory_ccp(gpDram->perm.rmp_base, (void **)&counter_map, sizeof(rmp_asid_counters_t));
    skip_rmp_addr_check(false);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    *count = counter_map->counters[asid];

unmap:
    sev_hal_unmap_memory(counter_map);

    return status;
}

static bool is_rmp_initialized = false;

/**
 * Has SNP Init been called to set up the RMP
 */
bool is_rmp_table_initialized(void)
{

    /* For most cases, this is true. However Download firmware can happen in-
       between but table isn't initalized, so we need to check it as well */
    if (is_rmp_initialized)
    {
        return true;
    }
    else
    {
        sev_snp_globals_t snp_globals;
        memset (&snp_globals, 0, sizeof(snp_globals));
        sev_hal_read_snp_globals(&snp_globals.val[0]);

        is_rmp_initialized = (snp_globals.f.rmp_initialized == 1);
        return is_rmp_initialized;
    }
}

void rmp_is_uninitialized(void)
{
    is_rmp_initialized = false;
}

sev_status_t snp_reclaim_buffer(uint64_t address)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t page_rmp_paddr = 0;
    rmp_entry_t page_rmp_entry;
    snp_page_state_t page_state;

    if (is_rmp_table_initialized())
    {
        status = rmp_get_addr_entry_state(address, &page_rmp_paddr, &page_rmp_entry, &page_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Set the Ring Buffer State from Firmware to Reclaim */
        page_rmp_entry.q1.f.immutable = 0;
        page_rmp_entry.q1.f.lock = page_rmp_entry.q1.f.immutable;

        /* Write all our RMP changes back to x86 memory */
        status = rmp_entry_write(page_rmp_paddr, &page_rmp_entry);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

end:
    return status;
}

sev_status_t set_rmp_range_to_firmware_iommu_state(uint64_t rmp_entry_start,
                                                   uint64_t rmp_entry_end)
{
    return initialize_rmp_entries_range(rmp_entry_start, rmp_entry_end, SNP_PAGE_STATE_FIRMWARE_IOMMU);
}

sev_status_t set_rmp_range_to_hypervisor_state(uint64_t rmp_entry_start, uint64_t rmp_entry_end)
{
    return initialize_rmp_entries_range(rmp_entry_start, rmp_entry_end, SNP_PAGE_STATE_HYPERVISOR);
}

sev_status_t set_rmp_range_to_reclaim_state(uint64_t rmp_entry_start, uint64_t rmp_entry_end)
{
    return initialize_rmp_entries_range(rmp_entry_start, rmp_entry_end, SNP_PAGE_STATE_RECLAIM);
}

/**
 * Determines if the RMP table needs to be re-initialized.
 * Example: If the RMP was initially initialized by firmware that was determined
 *          to be unsecure, we may require a full re-init after dlfw'ing the
 *          new/safe firmware. (Or if a uCode version was determined to be unsecure)
 */
sev_status_t require_rmp_reinit(sev_t *sev, sev_snp_globals_t *snp_globals, bool *required_init)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    snp_tcb_version_t current_tcb;

    if (!sev || !snp_globals || !required_init)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Calculate the current tcb version using the latest uCode SVN */
    get_committed_tcb(&current_tcb);

    /* sev_t contains the running/new tcb_version and snp_globals contains the previous/old version */
    if (current_tcb.val != snp_globals->f.tcb.val)
    {
        *required_init = true;
    }
    else
    {
        *required_init = false;
    }

end:
    return status;
}

static sev_status_t update_rmp_2mb_subpage_count(uint64_t x86_2mb_addr, uint32_t subpage_count,
                                                 bool inc, bool overlap_range)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    uint64_t page_rmp_paddr = 0;
    rmp_entry_t page_rmp_entry;

    if (overlap_range)
    {
        status = get_rmp_paddr_overlap(x86_2mb_addr, &page_rmp_paddr); /* Get RMP entry for page given sPA */
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        status = get_rmp_paddr(x86_2mb_addr, &page_rmp_paddr);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    status = rmp_entry_read(page_rmp_paddr, &page_rmp_entry); /* Do x86 copy to pull RMP entry into readable memory */
    if (status != SEV_STATUS_SUCCESS)
       goto end;

    /* Update subpage count */
    if (inc)
    {
        page_rmp_entry.q1.f.subpage_count += subpage_count;
    }
    else
    {
        if (page_rmp_entry.q1.f.subpage_count < subpage_count)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        }
        page_rmp_entry.q1.f.subpage_count -= subpage_count;
    }

    /* Write all our RMP changes back to x86 memory */
    status = rmp_entry_write_direct(page_rmp_paddr, &page_rmp_entry);

end:
    return status;
}

sev_status_t set_rmp_sub_page_count(uint64_t x86_buffer_start,
                                    uint64_t x86_buffer_end, bool overlap_range)
{
    /* We are expecting x86_buffer_end to be inclusive of the LAST address.
       For example, if x86_buffer_start ix 0x4000 and it goes to 0x4FFF,
       x86_buffer_end must be 0x4FFF. The size would be x86_buffer_end + 1 - x86_buffer_start */
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t subpage_count = 0;
    uint64_t process_addr = 0;

    /* Process it 2MB at a time */
    /* If both are within the same 2MB range, just do it once. Most common case for usage */
    if ((x86_buffer_start & X86_2MB_MASK) == (x86_buffer_end & X86_2MB_MASK))
    {
        subpage_count = x86_buffer_end - x86_buffer_start + 1ULL;
        subpage_count = subpage_count / PAGE_SIZE_4K;
        /* Sub page count does not include the 2MB aligned buffer, if the start
           is the first 2MB page, don't increment it */
        if ((x86_buffer_start & X86_2MB_MASK) == x86_buffer_start)
            subpage_count--;
        /* Increment 2mb subpage count */
        status = update_rmp_2mb_subpage_count((x86_buffer_start & X86_2MB_MASK), subpage_count, true, overlap_range);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }
    else
    {
        uint64_t end_addr = 0;
        /* They are not within the same 2MB, so do the first unaligned 2MB first,
           then 2MB at a time, then the last part */

        /* 1. First part (unaligned or aligned to first 2MB chunk) */
        process_addr = x86_buffer_start;
        end_addr = (x86_buffer_start & X86_2MB_MASK) + X86_2MB_SIZE;
        subpage_count = (end_addr - process_addr) / PAGE_SIZE_4K;
        /* Sub page count does not include the 2MB aligned buffer, if the start
           is the first 2MB page, don't increment it */
        if ((process_addr & X86_2MB_MASK) == x86_buffer_start)
            subpage_count--;
        /* Increment 2mb subpage count */
        status = update_rmp_2mb_subpage_count((process_addr & X86_2MB_MASK), subpage_count, true, overlap_range);
        if (status != SEV_STATUS_SUCCESS)
           goto end;

        /* 2. Go through all 2MB chunks one at a time until the end, process_addr
              should be aligned to 2MB here */
        process_addr = end_addr;

        /* process_addr in the loop is now 2MB aligned */
        while (process_addr != (x86_buffer_end + 1))
        {
            /* 3. Last chunk */
            if (((x86_buffer_end + 1) - process_addr)  <= X86_2MB_SIZE)
            {
                subpage_count = x86_buffer_end - process_addr + 1;
                subpage_count = subpage_count / PAGE_SIZE_4K;
                /* Sub page count does not include the 2MB aligned buffer since
                   the process_addr is aligned to 2mb, do not include it */
                subpage_count--;

                /* Increment 2mb subpage count */
                status = update_rmp_2mb_subpage_count(process_addr, subpage_count, true, overlap_range);
                if (status != SEV_STATUS_SUCCESS)
                   goto end;

                break;
            }
            else
            {
                /* each 2MB has 511 subpages (2*1024*1024 / 4096 - 1) */
                subpage_count = 511;
                /* Increment 2mb subpage count */
                status = update_rmp_2mb_subpage_count(process_addr, subpage_count, true, overlap_range);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
                process_addr += X86_2MB_SIZE;
            }
        }
    }

end:
    return status;
}

/**
 * Confirms all pages within range (start_paddr + length) are FIRMWARE or DEFAULT
 */
sev_status_t check_page_range_firmware_writable(uint64_t start_paddr, uint32_t length)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t rmp_paddr = 0;
    rmp_entry_t rmp_entry;
    snp_page_state_t rmp_state;
    uint32_t page_size = 0;
    int64_t bytes_remaining = length; /* Can go negative if pass in a 4K length and a 2M page */
    uint64_t cur_page = start_paddr;

    do
    {
        /* Verify that the page is in the FIRMWARE or DEFAULT state */
        status = rmp_get_addr_entry_state(cur_page, &rmp_paddr, &rmp_entry, &rmp_state);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        if (rmp_state != SNP_PAGE_STATE_FIRMWARE && rmp_state != SNP_PAGE_STATE_DEFAULT)
        {
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        }

        page_size = (rmp_entry.q1.f.page_size == DRAM_PAGE_SIZE_4K) ? PAGE_SIZE_4K : PAGE_SIZE_2M;
        bytes_remaining -= page_size;
        cur_page += page_size;
    } while (bytes_remaining > 0);

end:
    return status;
}

/**
 * Pass in an address range (RMP base/end, SEV-ES TMR, GCTX page, etc) and goes
 * through array of MemRegion MEM_DESC's in SYS_MEM_MAP and verifies that range
 * is in only one MEM_DESC and the MEM_DESC.type is DRAM and NOT MMIO
 */
sev_status_t validate_memory_map(SYS_MEM_MAP *mem_map, uint64_t base_addr, uint64_t limit_addr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!mem_map)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    CLEAR_CBIT(base_addr);
    CLEAR_CBIT(limit_addr);

    for (MEM_DESC *mmd = mem_map->MemRegion; mmd < &mem_map->MemRegion[mem_map->DescNum]; mmd++)
    {
        /* Range must be entirely within a single MemRegion */
        if (mmd->Base <= base_addr && limit_addr <= mmd->Limit)
            goto end;
    }

    status = SEV_STATUS_INVALID_CONFIG;

end:
    return status;
}

#if 0
// Pending information from CCP team...
/**
 * Note, the way this is works is caller sets the first 16B at p as our 'source' and
 * then we set 'dest' to be 16B past p, and copy size bytes from p to p+16.
 */
static sev_status_t fast_fill(uint8_t *p, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    bl_ccp_cmd_desc cmds;
    bl_ccp_cmd_desc *pCcpCmd = &cmds;

    uint32_t eids = 0;

    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCcpCmd->cmd0.fields.soc = 0;
    pCcpCmd->cmd0.fields.ioc = 1;  // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.init = 0; // 1;
    pCcpCmd->cmd0.fields.eom = 1;
    pCcpCmd->cmd0.fields.prot = 0;
    pCcpCmd->cmd0.fields.engine = CCP_ENGINE_PT;
    pCcpCmd->cmd0.fields.function = 0;

    pCcpCmd->cmd1.length = size;

    pCcpCmd->cmd2.source_pointer_lo = ADDRESS_LO(p);
    pCcpCmd->cmd3.fields.source_pointer_hi = 0;
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id = 0;

    pCcpCmd->cmd4.dest_pointer_lo = ADDRESS_LO(p + 16);
    pCcpCmd->cmd5.fields.dest_pointer_hi = 0;
    pCcpCmd->cmd5.fields.dest_mem = CCP_MEM_LOCAL;

    /* No need to wait for CCP to complete the command, so we can continue. */
    status = sev_hal_enqueue_and_run_commands(&cmds, &eids, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Wait for HMAC commands to complete */
    status = sev_hal_query_commands(&eids, 1, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}
#endif

static uint64_t rmp_limit = 0;

typedef struct rmp_range
{
    uint64_t base;
    uint64_t end;
    uint64_t val;
} rmp_range_t;

/* Below are #defines for the few types of pages that SNP_INIT can create */
#define RMP_ENTRY_VAL_HV       0x0000000000000000 /* A normal HYPERVISOR page */
#define RMP_ENTRY_VAL_HV_FIXED 0x0000000000000004 /* Immutable. A HYPERVISOR_FIXED page */
#define RMP_ENTRY_VAL_FIRMWARE 0x8000000000000005 /* Locked, Immutable, and Assigned. A FIRMWARE page */

typedef struct rmp_ranges
{
    size_t count;
    size_t limit;
    rmp_range_t range[1];
} rmp_ranges_t;

/**
 * @brief initialize the area of memory used to hold the rmp_ranges_t
 */
static bool init_ranges(rmp_ranges_t **ppRanges)
{
    /* Align rmp_base and rmp_end and compute rmp_limit */
    uint64_t rmp_base = gpDram->perm.rmp_base & ~(PAGE_SIZE_4K - 1);
    uint64_t rmp_end  = gpDram->perm.rmp_end  |  (PAGE_SIZE_4K - 1);
    if (rmp_base >= rmp_end)
        return false; /* RMP base and end are grotesquely wrong */
    if (rmp_end + 1 - rmp_base < RMP_ASID_COUNTERS_SIZE + RMP_ENTRY_SIZE)
        return false; /* Not big enough for an RMP that covers even 1 4K page @ 0 */

    rmp_limit = (rmp_end + 1 - (rmp_base + RMP_ASID_COUNTERS_SIZE)) / RMP_ENTRY_SIZE * PAGE_SIZE_4K - 1;

    if (ppRanges == NULL)
        return false;

    rmp_ranges_t *pRanges = (rmp_ranges_t *)gpSevScratchBuf;

    pRanges->limit = (SEV_SCRATCH_BUF_LEN - offsetof(rmp_ranges_t, range)) / sizeof(rmp_range_t);
    pRanges->count = 0;
    memset(&pRanges->range, 0, pRanges->limit * sizeof(rmp_range_t));

    *ppRanges = pRanges;

    return true;
}

/**
 * @brief Add a range at the end of the ranges
 *
 * @param base base address of new range
 * @param end end address of new range
 * @param val RMP page type of new range
 * @return true Successfully added
 * @return false Failed to add
 */
static bool append_range(rmp_ranges_t *pRanges, uint64_t base, uint64_t end, uint64_t val)
{
    if (pRanges->count >= pRanges->limit)
        return false;

    pRanges->range[pRanges->count].base = base;
    pRanges->range[pRanges->count].end  = end;
    pRanges->range[pRanges->count].val  = val;
    pRanges->count++;

    return true;
}

/**
 * @brief Adds a range to the list of ranges, splitting as necessary
 *
 * @param base start of the range (ends in 000)
 * @param end end of the range (ends in FFF)
 * @param val the value that goes in this range
 * @return true
 * @return false
 */
static bool add_range(rmp_ranges_t *pRanges, uint64_t base, uint64_t end, uint64_t val)
{
    size_t count = pRanges->count;
    bool overlap = false;

    if (end > rmp_limit)
        end = rmp_limit;

    if (base > rmp_limit)
        return true;

    for (size_t i = 0; i < count; ++i)
    {
        rmp_range_t *pr = &pRanges->range[i];

        if (end < pr->base || base > pr->end)
            continue;   /* No overlap with this one */

        overlap = true;

        if (val == pr->val)
            continue;   /* No change to this range */

        /* 4 Kinds of overlap possible: */
        /* Full overlap: new range completely covers this old range */
        if (base <= pr->base && pr->end <= end)
        {
            /* Change type of old range to be the new range and move along */
            pr->val = val;
            continue;
        }

        /* Create a new range */
        if (!append_range(pRanges, base, end, val))
            return false;

        /* Now adjust the existing range to account for the new range */
        /* The new range covers the beginning of the old range */
        if (base <= pr->base && end < pr->end)
        {
            /* Adjust base of old range to end of new one */
            pr->base = end +1;
        }
        /* The new range covers the end of this old range */
        else if (pr->base < base && pr->end <= end)
        {
            /* Adjust end of old range to beginning of new one */
            pr->end = base - 1;
        }
        /* The new range splits this old range */
        else if (pr->base < base && end < pr->end)
        {
            /* Create a new range for the end of this old range */
            append_range(pRanges, end + 1, pr->end, pr->val);
            /* Adjust this old range's end to be base of new range */
            pr->end = base - 1;
            return true; /* It isn't possible to overlap with anything else */
        }
        /* I don't think there's another possibility... but just in case */
        else
            return false;
    }

    if (!overlap)
        return append_range(pRanges, base, end, val);

    return true;
}

/**
 * @brief Checks pRanges subset for an RMP value
 *
 * @param pRanges pointer to the rmp_ranges_t to check
 * @param base base address to check for in pRanges
 * @param end limit to check for in pRanges
 * @param rmp_val value to check for in pRanges
 * @return true All addresses from addr to end == rmp_val in pRanges
 * @return false Some addresses aren't rmp_val
 */
static bool check_range(rmp_ranges_t *pRanges, uint64_t base, uint64_t end, uint64_t rmp_val)
{
    size_t count = pRanges->count;
    bool ret_val = false;

    if (end > rmp_limit)
        return rmp_val == RMP_ENTRY_VAL_HV_FIXED; /* The range is all DEFAULT/HV_FIXED */

    for (size_t i = 0; i < count; ++i)
    {
        rmp_range_t *pr = &pRanges->range[i];

        if (end < pr->base || base > pr->end)
            continue;   /* No overlap with this rmp_range */

        if (pr->val != rmp_val)
            return false; /* This entry doesn't match the expected value */

        ret_val = true; /* At least one range matches */
    }

    return ret_val;
}

typedef enum scan_result
{
    SCAN_RES_FINISHED     = 0,  // Finished scanning the RMP for the address range
    SCAN_RES_HIT_RMP_END  = 1,  // The address range isn't completely covered by the RMP
    SCAN_RES_TERMINATED   = 2,  // The callback function returned false, ending the scan
    SCAN_RES_BAD_PADDR    = 3,  // Something went wrong getting the address of the RMP entry for address
    SCAN_RES_SCAN_TOO_BIG = 4   // Scan covers more than 2^32 4K pages (16TB of address range!)
} scan_result_t;

/**
 * @brief Scans the portion of the RMP corresponding to a range of system addresses
 *
 * @param addr Starting address of the range
 * @param end Ending address of the range
 * @param arg Arbitrary pointer passed through to func
 * @param func Function called for each RMP entry for the address range
 * @return scan_result_t What caused the scan to end.
 */
static scan_result_t scan_rmp(uint64_t addr, uint64_t end,
                              void *arg, size_t (*func)(volatile rmp_entry_t *p, void *arg, size_t req_size))
{
    uint64_t size = end + 1 - addr;
    scan_result_t ret_val = SCAN_RES_TERMINATED;
    uint32_t num_pages = (uint32_t)(size >> ALIGNMENT_BITS_4K);
    const uint32_t low_bits = PAGE_SIZE_4K - 1;

    if (size == 0)
        return SCAN_RES_FINISHED;
    if (size != (uint64_t)num_pages << ALIGNMENT_BITS_4K)
        return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_056), SCAN_RES_SCAN_TOO_BIG;

    /*
     * Account for possible lost page and a potential extra page crossing
     * +0 if low bits of size + low bits of addr is == 0
     * +1 if low bits of size + low bits of addr is <= PAGE_SIZE_4K
     * +2 if low bits of size + low bits of addr is > PAGE_SIZE_4K
     */
    num_pages += (((uint32_t)addr & low_bits) + (size & low_bits) + low_bits) >> ALIGNMENT_BITS_4K;

    // Calculate the address of the RMP entry for addr...
    uint64_t rmp_paddr = 0;
    switch (local_get_rmp_paddr(addr, &rmp_paddr))
    {
        case SEV_STATUS_SUCCESS:
            break;
        case SEV_STATUS_INVALID_PAGE_STATE:
            /* Indicates addr is past the end of the RMP */
            return SCAN_RES_HIT_RMP_END;
        default:
            return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_057), SCAN_RES_BAD_PADDR;
    }

    uint64_t rmp_end = gpDram->perm.rmp_end;

    rmp_entry_t *p = NULL;
    void *p_map = NULL;
    size_t mappable_size = 0;

    while (num_pages)
    {
        size_t entries_done = 0;

        // Check if we're past the end of the RMP.
        if (rmp_paddr > rmp_end)
        {
            ret_val = SCAN_RES_HIT_RMP_END;
            break;
        }

        if (p_map == NULL)
        {
            // We need to map the RMP. Let's map as much of it as we can...
            // Or need, whichever is smaller.
            mappable_size = SYSHUB_TLB_WINDOW_SIZE - (rmp_paddr & (SYSHUB_TLB_WINDOW_SIZE-1));
            size_t needed_size = num_pages * RMP_ENTRY_SIZE;
            if (needed_size < mappable_size)
                mappable_size = needed_size;
            if (sev_hal_map_memory_ccp(rmp_paddr, &p_map, mappable_size) != SEV_STATUS_SUCCESS)
                break;
            if (p_map == NULL)
                break;
            p = (rmp_entry_t *)p_map;
        }

        /* Call the scanning function */
        if ((entries_done = func(p, arg, mappable_size / sizeof(*p))) == 0)
        {
            SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_058);
            ret_val = SCAN_RES_TERMINATED;
            break;
        }

        num_pages -= entries_done;
        rmp_paddr += entries_done * RMP_ENTRY_SIZE;
        p += entries_done;
        if ((rmp_paddr & (SYSHUB_TLB_WINDOW_SIZE - 1)) == 0)
        {
            sev_hal_unmap_memory(p_map);
            p_map = NULL;
        }
    }

    if (num_pages == 0)
        ret_val = SCAN_RES_FINISHED;

    if (p_map)
        sev_hal_unmap_memory(p_map);

    return ret_val;
}

/**
 * @brief Updates a number of RMP entries with a value
 * This function is safe even if the RMP is live and the x86
 * is free to update it at will.
 *
 * @param p Pointer to mapped RMP entry, ready for use
 * @param arg Pointer to the value to write
 * @param req_size Number of entries to fill
 * @return 0 = an error occurred
 * @return number of entries written
 */
static size_t update_rmp_entry(volatile rmp_entry_t *p, void *arg, size_t req_size)
{
    uint64_t val = *(uint64_t *)arg;
    volatile rmp_entry_t *base_p = p; /* Preserve pointer to 2M entry */
    /* This function is currently implemented ONLY for the SNP_PAGE_SET_STATE use case.
     * That is updating a FW page (0x8000_0000_0000_0005) to HV_FIXED (0x0000_0000_0000_0004).
     * Make sure the parameters are consistent with that. Not double checking the entry
     * itself. That was verified as a FW page earlier in SNP_PAGE_SET_STATE.
     */
    if (val != RMP_ENTRY_VAL_HV_FIXED || ((uint32_t)p & SNP_PAGE_SET_STATE_ADDR_RESERVED_MASK*16/4096) != 0)
        return 0;
    /* Limit this call to 512 4K pages. Each 2M region in a range should be a separate call. */
    req_size = req_size > 512 ? 512 : req_size;
    /* Lock the 2M RMP entry */
    base_p->q1.f.asid = RMP_INVALID_ASID;
    /* Fetch the now-frozen RMP entry for the 2M aligned page */
    rmp_quadword1_t rmp_entry = base_p->q1;
    /* Save the sub-page count */
    uint32_t subpage_count = rmp_entry.f.subpage_count;
    /* Check the subpage count has at least req_size assigned pages */
    if (subpage_count +1 < req_size)
        goto unlock;
    /* For each of req_size entries, AFTER the initial 2M entry */
    p++;
    for (size_t i = 1; i < req_size; ++i, ++p)
    {
        p->q1.val = val;
        p->q2.val = 0;
    }
    /* Set the value for the first RMP entry */
    rmp_entry.val = val; /* Clobbers the subpage_count field */
    base_p->q2.val = 0;
    /* Update subpage count (the 2M entry itself isn't part of the subpage count) */
    rmp_entry.f.subpage_count = subpage_count - (req_size -1);
unlock:
    rmp_entry.f.asid = 0;
    base_p->q1 = rmp_entry;
    return p - base_p;
}

/**
 * @brief Writes a number of RMP entries with a value
 *
 * @param p Pointer to mapped RMP entry, ready for use
 * @param arg Pointer to the value to write
 * @param req_size Number of entries to fill
 * @return 0 = an error occurred
 * @return number of entries written
 */
static size_t write_rmp_entry(volatile rmp_entry_t *p, void *arg, size_t req_size)
{
    uint64_t val = *(uint64_t *)arg;
    // p->q2.val = 0;

    for (size_t i = 0; i < req_size; ++i, ++p)
    {
        p->q1.val = val;
        p->q2.val = 0;
    }

    return req_size;
}

/**
 * @brief Write to a range of the RMP
 *
 * @param pr provides base, end, and entry value
 * @return true success
 * @return false failure
 */
static bool write_rmp_range(const rmp_range_t *pr)
{
    /*
     * Special case for RMP_ENTRY_VAL_HV (which is 0) to take
     * advantage of the much faster fill_rmp_block_zeroes()
     * which uses the CCP to clear memory faster than the ARM can.
     */
    if (pr->val == RMP_ENTRY_VAL_HV)
    {
        uint64_t base, end;
        if (local_get_rmp_paddr(pr->base, &base) != SEV_STATUS_SUCCESS ||
            local_get_rmp_paddr(pr->end,  &end)  != SEV_STATUS_SUCCESS)
            return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_059), false;
        return SEV_ERROR(fill_rmp_block_zeroes(base, end+RMP_ENTRY_SIZE-1), EXT_ERR_060) == SEV_STATUS_SUCCESS;
    }

    /*
     * write_rmp_entry() can only be used when the RMP TMR is in place, protecting
     * the RMP from writes by everyone else. If the RMP TMR is NOT in place, we
     * need to check to see if the update is legal before updating the RMP.
     */
    size_t (*fn)(volatile rmp_entry_t *, void *, size_t) = write_rmp_entry;
    if ((gSSCB.SSCB_Control & SSCB_RMP_MASK) == 0)
        fn = update_rmp_entry;
    /* Write every RMP entry in the range with the value */
    switch (scan_rmp(pr->base, pr->end, (void *)&pr->val, fn))
    {
        case SCAN_RES_FINISHED:
        case SCAN_RES_HIT_RMP_END:
            return true;
        default:
            return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_061), false;
    }
}

/**
 * @brief Comparison function for qsort
 *
 * @param p1 rmp_range_t pointer to element1
 * @param p2 rmp_range_t pointer to element2
 * @return int p1 </==/> p2
 */
static int range_compare(const void *p1, const void *p2)
{
    const rmp_range_t *v1 = p1;
    const rmp_range_t *v2 = p2;
    if (v1->base < v2->base)
        return -1;
    if (v2->base < v1->base)
        return 1;
    return 0; /* Should never happen! */
}

/**
 * @brief Walks the list of reserved memory ranges, making them HV_FIXED
 *
 * @param pRanges rmp_ranges_t to add the HV_FIXED ranges to
 * @param reserved_list_paddr X86 Physical address of the SNP RANGE_LIST structure
 * @param base_mbz_bits BASE address bits that must be 0
 * @return sev_status_t
 */
static sev_status_t walk_reserved_list(rmp_ranges_t *pRanges, uint64_t reserved_list_paddr, uint64_t base_mbz_bits)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    volatile snp_range_list_t *reserved_list = NULL;
    volatile snp_range_t *p = NULL;

    /* Enhance readability */
    uint64_t rmp_base = gpDram->perm.rmp_base;
    uint64_t rmp_end  = gpDram->perm.rmp_end;
    uint32_t count = 0;
    uint64_t end = 0;

    if (reserved_list_paddr == PADDR_INVALID ||
        validate_address_range(reserved_list_paddr, PAGE_SIZE_4K) != SEV_STATUS_SUCCESS)
        return SEV_STATUS_INVALID_ADDRESS;

    reserved_list_paddr = set_asid(COPY_PLAINTEXT_IN, reserved_list_paddr, 0);

    /* Map the reserved list in to ARM memory */
    status = sev_hal_map_memory(reserved_list_paddr, (void **)&reserved_list);
    if (status != SEV_STATUS_SUCCESS)
        return status;

    if (reserved_list == NULL)
        return SEV_STATUS_INVALID_ADDRESS;

    /* Read reserved_list->n precisely once */
    uint32_t rln = reserved_list->n;

    /* Make sure entire list fits is on the same 4K page and
     * that the reserved field in the list is 0. */
    if (reserved_list->reserved != 0 || rln > SNP_RANGE_LIST_MAX_COUNT ||
        (rln * sizeof(snp_range_t) + offsetof(snp_range_list_t, ranges) +
         (reserved_list_paddr & (PAGE_SIZE_4K - 1)) > PAGE_SIZE_4K))
    {
        status = SEV_STATUS_INVALID_PARAM;
        goto end;
    }

    /* Walk the list, adding each range as a HV_FIXED range */
    p = (snp_range_t *)&reserved_list->ranges;
    for (size_t i = 0; i < rln; ++i, ++p)
    {
        uint64_t base = p->base & ~SEV_CBIT_MASK;
        if (p->reserved != 0 ||
            (base & base_mbz_bits) != 0)
        {
            status = SEV_STATUS_INVALID_PARAM;
            goto end;
        }

        count = p->page_count;
        end = base + (uint64_t)count*PAGE_SIZE_4K -1;

        /* Exclude the RMP from the list. For the INIT case, we want to ensure
         * that the RMP is over memory. For the PAGE_SET_STATE case, we want
         * to prevent converting the RMP to HV_FIXED.
         */
        if (ranges_overlap(base, end, rmp_base, rmp_end))
        {
            /* There's an overlap of this range with the RMP... exclude it. */
            /* Add from base up to rmp_base, if any */
            if (base < rmp_base)
                add_range(pRanges, base, rmp_base -1, RMP_ENTRY_VAL_HV_FIXED);
            /* Add from rmp_end to end, if any */
            if (rmp_end < end)
                add_range(pRanges, rmp_end +1, end, RMP_ENTRY_VAL_HV_FIXED);
        } else if (count)
           add_range(pRanges, base, end, RMP_ENTRY_VAL_HV_FIXED);
    }

end:
    if (reserved_list)
        sev_hal_unmap_memory((void *)reserved_list);

    return status;
}

/**
 * @brief Adds well-known HV_FIXED areas to the RMP
 *
 * @param pRanges
 */
void add_known_hvfixed_ranges(rmp_ranges_t *pRanges)
{
    extern sscb_t gSSCB;

    /* Ensure the TSEG can't be accessed as guest memory */
    if (gSSCB.SSCB_Control & SSCB_TSEG_MASK)
        add_range(pRanges, gSSCB.SMM_Base, gSSCB.SMM_End, RMP_ENTRY_VAL_HV_FIXED);

    if (gSSCB.SSCB_Control & SSCB_ASEG_MASK)
        add_range(pRanges, ASEG_BASE_ADDR, ASEG_LIMIT_ADDR, RMP_ENTRY_VAL_HV_FIXED);

    /* Add the Legacy HT area because there's still some risk associated with it */
    add_range(pRanges, 0xFD00000000, 0xFDFFFFFFFF, RMP_ENTRY_VAL_HV_FIXED);
}

/**
 * @brief Configure the RMP
 *
 * @param reserved_list list of ranges of memory to be reserved or PADDR_INVALID
 * @return true if successful
 * @return false if failure
 */
bool configure_rmp(uint64_t reserved_list_paddr)
{
    /* The process is to build a list of ranges first
     * then populate the ranges with the appropriate values.
     */
    SYS_MEM_MAP *pMemMap = &gpDram->mem_map;

    rmp_ranges_t *pRanges = NULL;
    if (!init_ranges(&pRanges) || pRanges == NULL)
        return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_062), false;

    /* Start by filling the entire RMP-covered area with HV-FIXED */
    add_range(pRanges, 0, rmp_limit, RMP_ENTRY_VAL_HV_FIXED);

    /* Now walk the memory map, inserting "real" memory */
    if (pMemMap->DescNum == 0)
        return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_063), false;

    for (size_t i = 0; i < pMemMap->DescNum; ++i)
    {
        add_range(pRanges, pMemMap->MemRegion[i].Base, pMemMap->MemRegion[i].Limit, RMP_ENTRY_VAL_HV);
    }

    /* Now walk the (optional) list of ranges the OS wants/needs to mark reserved */
    if (reserved_list_paddr != PADDR_INVALID)
        walk_reserved_list(pRanges, reserved_list_paddr, SNP_ADDR_RESERVED_MASK);

    /* Now prevent other well-known areas from being used for guest memory */
    add_known_hvfixed_ranges(pRanges);

    /* Finally set the RMP itself to FW state after making sure the area is usable for the RMP. */
    if (!check_range(pRanges, gpDram->perm.rmp_base, gpDram->perm.rmp_end, RMP_ENTRY_VAL_HV))
        return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_073), false;
    add_range(pRanges, gpDram->perm.rmp_base, gpDram->perm.rmp_end, RMP_ENTRY_VAL_FIRMWARE);

    /* The list is complete... sort it */
    qsort(pRanges->range, pRanges->count, sizeof(pRanges->range[0]), &range_compare);

    /* Now actually generate the RMP */
    for (size_t i = 0; i < pRanges->count; ++i)
    {
        if (!write_rmp_range(&pRanges->range[i]))
            return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_064), false;
    }

    /* Clear the ASID counters array */
    if (fill_rmp_block_zeroes(gpDram->perm.rmp_base, gpDram->perm.rmp_base + RMP_ASID_COUNTERS_SIZE - 1) != SEV_STATUS_SUCCESS)
        return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_065), false;

    /* RMP pages are "assigned" and have to be accounted for in 2MB RMP entry 'sub page' counts */
    if (set_rmp_sub_page_count(gpDram->perm.rmp_base, gpDram->perm.rmp_end, true) != SEV_STATUS_SUCCESS)
        return SEV_ERROR(SEV_STATUS_LIMIT, EXT_ERR_066), false;

    return true;
}

/**
 * @brief Scanner "core" for checking FW state
 *
 * @param p Pointer to the RMP entry
 * @param arg Unused
 * @param req_size Number of entries to test
 * @return 1 Entry is a firmware page
 * @return 0 Entry is not a firmware page
 */
static size_t check_fw(volatile rmp_entry_t *p, void *arg, size_t req_size)
{
    rmp_quadword1_t q1 = p->q1;
    q1.f.subpage_count = 0;
    return (q1.val == RMP_ENTRY_VAL_FIRMWARE) ? 1 : 0;
}

#define RMP_RANGE_OFFSET_IN_SCRATCH 8192

/**
 * @brief Sets a list of page ranges to HV_FIXED
 *
 * @param list_paddr x86 Address of the list of ranges
 * @return sev_status_t
 */
sev_status_t page_set_hv_fixed(uint64_t list_paddr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Initialize the empty ranges list */
    rmp_ranges_t *pRanges = NULL;
    if (!init_ranges(&pRanges) || pRanges == NULL)
        return SEV_STATUS_INVALID_ADDRESS;

    /* Insert the ranges */
    status = walk_reserved_list(pRanges, list_paddr, SNP_PAGE_SET_STATE_ADDR_RESERVED_MASK);
    if (status != SEV_STATUS_SUCCESS)
        return status;

    /* Sort the list */
    qsort(pRanges->range, pRanges->count, sizeof(pRanges->range[0]), &range_compare);

    /* Make sure lower-level code expects us to be modifying the RMP */
    skip_rmp_addr_check(true);

    /* Verify every page in every range is in Firmware state,
     * and not part of the RMP (which is itself in Firmware state) */
    for (size_t i = 0; i < pRanges->count; ++i)
    {
        if (ranges_overlap(pRanges->range[i].base, pRanges->range[i].end,
                            gpDram->perm.rmp_base, gpDram->perm.rmp_end))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        }
        switch (scan_rmp(pRanges->range[i].base, pRanges->range[i].end, NULL, check_fw)) {
        case SCAN_RES_TERMINATED:
            status = SEV_STATUS_INVALID_PAGE_STATE;
            goto end;
        case SCAN_RES_BAD_PADDR:
        case SCAN_RES_SCAN_TOO_BIG:
            status = SEV_STATUS_INVALID_ADDRESS;
            goto end;
        case SCAN_RES_HIT_RMP_END:
        case SCAN_RES_FINISHED:
            break;
        }
    }

    /* Update the RMP */
    for (size_t i = 0; i < pRanges->count; ++i)
    {
        if (!write_rmp_range(&pRanges->range[i]))
        {
            status = SEV_STATUS_INVALID_ADDRESS;
            break;
        }
    }

end:
    /* Re-enabled low-level RMP address checks */
    skip_rmp_addr_check(false);

    return status;
}
