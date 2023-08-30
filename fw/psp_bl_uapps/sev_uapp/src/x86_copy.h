// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef X86_COPY_H
#define X86_COPY_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

/* MASK for multiple of 2mb */
#define X86_2MB_SIZE        (2*1024*1024ull)
#define X86_2MB_MASK       ~(X86_2MB_SIZE - 1ull)

/* MASK for multiple 64 mb */
#define X86_64MB_SIZE       (64*1024*1024ull)
#define X86_64MB_MASK      ~(X86_64MB_SIZE - 1ull)

/* CBIT is located on bit 51 */
#define SEV_CBIT_SHIFT      (51)
#define SEV_CBIT_MASK       (1ull << (SEV_CBIT_SHIFT))

/* CBIT_IS_SET - True if C-bit is set. False otherwise. */
/* CLEAR_CBIT  - Takes in a x86_address to remove the C-bit */
/* SET_CBIT    - Takes in a x86_address to set the C-bit */
#define CBIT_IS_SET(x86_addr)   ((bool)((x86_addr) & SEV_CBIT_MASK))
#define CLEAR_CBIT(p)           ((p) &= ~SEV_CBIT_MASK)
#define SET_CBIT(p)             ((p) |= SEV_CBIT_MASK)

typedef enum x86_copy_op
{
    COPY_PLAINTEXT_IN      = 0,
    COPY_PLAINTEXT_OUT     = 1,
    COPY_PLAINTEXT_IN_OUT  = 2,
    COPY_CIPHERTEXT_IN     = 3,
    COPY_CIPHERTEXT_OUT    = 4,
    COPY_CIPHERTEXT_IN_OUT = 5,
    INFLATE_PLAINTEXT_OUT  = 6,
    INFLATE_CIPHERTEXT_OUT = 7,
} x86_copy_op_t;

/**
 * Checks for overlap between two addresses and ignores the c-bit
 *
 * Parameters:
 * When using this function, please pass in exclusive comparisons.
 * Note the difference in end values in the example memories below
 * Ex: inclusive is 0x0:0x500 - 0x500:0x1000
 * Ex: exclusive is 0x0:0x4FF - 0x500:0x0FFF
 *
 *  Return value:
 *      true: ranges overlap, false: ranges don't overlap
 */
bool ranges_overlap(uint64_t start1, uint64_t end1,
                    uint64_t start2, uint64_t end2);

/**
 *  Convert X86 address to data fabric address for SME
 *
 *  Parameters:
 *      x86_addr : pointer to x86 address and will be overwritten
 *                 with data fabric address for SME if enabled
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success.
 *      ERR_INVALID_PARAMS on invalid x86_addr pointer
 */
sev_status_t convert_x86_address(uint64_t *x86_addr);

/**
 *  Manage the way validate_address_range() checks
 *  When doing 'internal' work, we need to avoid RMP
 *  overlap checks. E.g., during rmp state lookups.
 */
void skip_rmp_addr_check(bool flag);

/**
 *  Ensure each command starts with RMP addr checks enforced
 */
void reset_rmp_addr_check(void);

/**
 * Indicate whether to enforce CPU TMR address check or not
 *
 */
void skip_cpu_tmr_addr_check(bool flag);

/**
 * Ensure each commmand starts with cpu TMR checks enforced
 */
void reset_cpu_tmr_addr_check(void);

/**
 *  Validate an address range from the x86.
 *
 *  Parameters:
 *      start : Starting address of the range to validate. (in)
 *      size  : Size of the range. (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_INVALID_ADDRESS if the address fails a check,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t validate_address_range(uint64_t start, uint64_t size);

/**
 *  Set the asid of an x86 address
 *
 *  Parameters:
 *      op   : Operating being used. In certain cases, may use c-bit asid
 *             instead of asid param
 *      addr : x86 physical address
 *      asid : ASID to append to addr
 *
 *  Return value:
 *      The value of addr with the asid appended
 */
uint64_t set_asid(x86_copy_op_t op, uint64_t addr, uint64_t asid);

/**
 *  Copy unencrypted data to/from x86 memory only if the address range is valid.
 *
 *  Parameters:
 *      x86_addr : Address to copy to/from. (in/out)
 *      psp_addr : Address of a buffer in PSP private memory. (in/out)
 *      size     : Size of the region to copy. (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_INVALID_ADDRESS if the address fails a check,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t copy_to_x86(uint64_t x86_addr, void *psp_addr, uint64_t size);
sev_status_t copy_from_x86(uint64_t x86_addr, void *psp_addr, uint64_t size);

/**
 *  Copy/move non asid-encrypted data from x86 memory to non asid-encrypted x86
 *  memory only if the address ranges are valid. Source and destination may overlap.
 *
 *  Parameters:
 *      x86_src  : Address to copy from. (in)
 *      x86_dest : Address to copy to. (out)
 *      size     : Size of the region to copy. (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_INVALID_ADDRESS if the address fails a check,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t copy_to_x86_from_x86(uint64_t x86_dest, uint64_t x86_src, uint64_t size);

/**
 *  Copy encrypted data to/from x86 memory only if the address range is valid.
 *
 *  Parameters:
 *      x86_addr : Address to copy to/from. (in/out)
 *      psp_addr : Address of a buffer in PSP private memory. (in/out)
 *      size     : Size of the region to copy. (in)
 *      asid     : ASID to use when accessing the memory. (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_INVALID_ADDRESS if the address fails a check,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t copy_to_x86_encrypted(uint64_t x86_addr, void *psp_addr,
                                   uint64_t size, uint32_t asid);
sev_status_t copy_from_x86_encrypted(uint64_t x86_addr, void *psp_addr,
                                     uint64_t size, uint32_t asid);

/**
 *  Copy/move encrypted data from x86 memory to encrypted x86 memory only if
 *  the address ranges are valid. Source and destination may overlap.
 *
 *  Parameters:
 *      x86_src  : Address to copy from. (in)
 *      x86_dest : Address to copy to. (out)
 *      size     : Size of the region to copy. (in)
 *      asid     : ASID to use when accessing the memory. (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_INVALID_ADDRESS if the address fails a check,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t copy_to_x86_encrypted_from_x86_encrypted(uint64_t x86_dest, uint64_t x86_src,
                                                      uint64_t size, uint32_t asid);

/**
 *  Encrypt/Decrypt a memory region using the UMC.
 *
 *  Parameters:
 *      x86_src  : Address to copy from. (in)
 *      x86_dest : Address to copy to. (out)
 *      psp_addr : Address of an intermediate buffer in PSP private memory. (in/out)
 *      size     : Size of the region to copy. (in)
 *      asid     : ASID to use when accessing the memory. (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_INVALID_ADDRESS if the address fails a check,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t encrypt_memory(uint64_t x86_src, uint64_t x86_dest,
                            void *psp_addr, uint32_t size, uint32_t asid);
sev_status_t decrypt_memory(uint64_t x86_src, uint64_t x86_dest,
                            void *psp_addr, uint32_t size, uint32_t asid);

#endif /* X86_COPY_H  */
