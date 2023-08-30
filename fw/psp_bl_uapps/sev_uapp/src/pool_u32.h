// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#ifndef POOL_U32_H
#define POOL_U32_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "sev_errors.h"

typedef struct es_vcpu
{
    uint32_t next_index;
} es_vcpu_t;

typedef struct es_vcpu_crc
{
    union {
        uint64_t CRC64;
        uint32_t CRC32;
    } u;
} es_vcpu_crc_t;

#define ES_VCPU_CRC_OFFSET (offsetof(es_vcpu_t, CRC))

#define CRC_BLOCK_SIZE      (sizeof(es_vcpu_crc_t))
#define INDEX_BLOCK_SIZE    (sizeof(es_vcpu_t))
#define INVALID_BLOCK       (0xFFFFFFFF)

/**
 * See CSF-395/CSF-396 (comments/attachments) for how/why this was implemented
 */
typedef struct pool_vcpu
{
    uint64_t start_crc_addr;    /* Start address of the memory region to manage */
    uint64_t end_crc_addr;      /* End address of the memory region to manage */
    uint64_t start_pool_addr;
    uint64_t end_pool_addr;
    size_t nr_blocks;           /* Number of blocks in the pool */
    size_t free_head_idx;       /* Free list head */
    size_t free_tail_idx;       /* Free list tail */
    bool is_initialized;        /* State variable */
} pool_vcpu_t;

/**
 * Initialize the pool. 'start_addr' points to the memory to use for the
 * pool.
 */
sev_status_t pool_vcpu_init(pool_vcpu_t *pool, uint64_t start_addr_pool,
                            uint64_t start_addr_crc, uint64_t size);

/**
 * Destroy the pool and clear its contents.
 */
sev_status_t pool_vcpu_destroy(pool_vcpu_t *pool);

/**
 * Allocate a VCPU block from the trusted memory region. Returns a 64-bit x86
 * address for both the block and the CRC location that needs to
 * be mapped with sev_hal_map_memory() before use.
 *
 * On error, returns 0.
 */
uint64_t pool_vcpu_alloc(pool_vcpu_t *pool, uint32_t *index, uint64_t *crc_block_paddr);

/**
 * Free a trusted block back to the pool.
 */
void pool_vcpu_free(pool_vcpu_t *pool, uint64_t block);

/**
 * Free a user "linked" list of vcpu entries back into the pool.
 */
sev_status_t pool_vcpu_free_list(pool_vcpu_t *pool, uint32_t start_index,
                                 uint32_t end_index, uint32_t expected_entries);

/**
 * Map a VCPU Index to its 64 bit physical address
 */
uint64_t pool_vcpu_index_to_addr64(pool_vcpu_t *pool, size_t idx);

/**
 *  Find a CRC entry in a user list. Return true or false or error code.
 */
sev_status_t pool_vcpu_find_crc_in_list(pool_vcpu_t *pool, uint32_t start_index,
                                        uint32_t end_index, uint64_t crc,
                                        uint32_t expected_entries, bool *found);

#endif /* POOL_U32_H */
