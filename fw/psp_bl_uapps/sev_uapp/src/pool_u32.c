// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "pool_u32.h"
#include "secure_ops.h"
#include "sev_hal.h"

static uint64_t idx_to_addr64(pool_vcpu_t *pool, size_t idx)
{
    return pool != NULL ? pool->start_pool_addr + idx*sizeof(es_vcpu_t) : 0;
}

static uint64_t idx_crc_block_to_addr64(pool_vcpu_t *pool, size_t idx)
{
    return pool != NULL ? (pool->start_crc_addr + (idx*sizeof(es_vcpu_crc_t))) : 0;
}

static size_t addr64_to_idx(pool_vcpu_t *pool, uint64_t addr64)
{
    /*
     * addr64 is expected to be aligned 8 bytes, and any other address would be
     * rounded down to the nearest index
     */
    return pool != NULL ? (addr64 - pool->start_pool_addr)/sizeof(es_vcpu_t) : 0;
}

/* Returns the index of a CRC address in the pool */
static sev_status_t addr64_crc_to_idx(pool_vcpu_t *pool, uint64_t addr64, uint32_t *index)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    if (pool == NULL || addr64 == 0 || index == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Make sure it's within valid range */
    if (addr64 > pool->end_crc_addr || addr64 < pool->start_crc_addr)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *index = (addr64 - pool->start_crc_addr)/sizeof(es_vcpu_crc_t);

end:
    return status;
}

static bool pool_is_empty(pool_vcpu_t *pool)
{
    return pool != NULL ? pool->free_head_idx == pool->free_tail_idx : true;
}

static sev_status_t list_get_next_index(pool_vcpu_t *pool, size_t idx, uint32_t *next_index)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    es_vcpu_t *blocks = NULL;

    if (!pool)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Map the memory pool to access the free list */
    status = sev_hal_map_memory(pool->start_pool_addr, (void **)&blocks);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Ensure that we read the latest data from DRAM */
    sev_hal_invalidate_dcache((uint32_t)(blocks + idx), INDEX_BLOCK_SIZE);
    *next_index = blocks[idx].next_index;

    /* Unmap the memory */
    (void)sev_hal_unmap_memory(blocks);

end:
    return status;
}

static sev_status_t list_set_next_index(pool_vcpu_t *pool, size_t idx, uint32_t next_index)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    es_vcpu_t *blocks = NULL;

    if (!pool)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Map the memory pool to access the free list */
    status = sev_hal_map_memory(pool->start_pool_addr, (void **)&blocks);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    blocks[idx].next_index = next_index;

    /* Ensure that the data is written to DRAM */
    sev_hal_clean_dcache((uint32_t)(blocks + idx), INDEX_BLOCK_SIZE);

    /* Unmap the memory */
    (void)sev_hal_unmap_memory(blocks);

end:
    return status;
}

/**
 * Advances the head to the next node in the list and returns the
 * index of the previous head. Returns a negative number on error.
 */
static int list_remove_head(pool_vcpu_t *pool)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    int rc = 0, prev_head = 0;

    if (!pool)
    {
        rc = -ERR_INVALID_PARAMS;
        goto end;
    }

    prev_head = pool->free_head_idx;

    /* Advance the head to the next index in the free list */
    status = list_get_next_index(pool, pool->free_head_idx, &pool->free_head_idx);
    if (status != SEV_STATUS_SUCCESS)
    {
        rc = -status;
        goto end;
    }

    rc = prev_head;

end:
    return rc;
}

static int list_add_tail(pool_vcpu_t *pool, size_t idx)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    int rc = 0;

    if (!pool)
    {
        rc = -ERR_INVALID_PARAMS;
        goto end;
    }

    /* Update the current tail to point to the new item */
    status = list_set_next_index(pool, pool->free_tail_idx, idx);
    if (status != SEV_STATUS_SUCCESS)
    {
        rc = -status;
        goto end;
    }

    pool->free_tail_idx = idx;

    /* The tail always points to an invalid block */
    status = list_set_next_index(pool, pool->free_tail_idx, INVALID_BLOCK);
    if (status != SEV_STATUS_SUCCESS)
    {
        rc = -status;
        goto end;
    }

end:
    return rc;
}

/**
 * Initialize the memory pool.
 */
sev_status_t pool_vcpu_init(pool_vcpu_t *pool, uint64_t start_addr_pool,
                            uint64_t start_addr_crc, uint64_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t i = 0;
    es_vcpu_t *blocks = NULL;

    if (!pool || size == 0 || !IS_ALIGNED_BYTES(start_addr_pool, INDEX_BLOCK_SIZE) ||
        !IS_ALIGNED_BYTES(size, INDEX_BLOCK_SIZE))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Number of blocks is determined by the CRC block size, could be smaller than pool index */
    pool->nr_blocks = size/CRC_BLOCK_SIZE;
    pool->start_pool_addr = start_addr_pool;
    pool->end_pool_addr = start_addr_pool + size;
    pool->start_crc_addr = start_addr_crc;
    pool->end_crc_addr = start_addr_crc + size;
    pool->free_head_idx = 0;

    /* Map the memory pool to access the free list. */
    status = sev_hal_map_memory(pool->start_pool_addr, (void **)&blocks);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Initialize the free list so that each block contains the index of
     * the next block in the list.
     */
    for (i = 0; i < pool->nr_blocks; i++)
    {
        blocks[i].next_index = i+1;
    }

    pool->free_tail_idx = i-1;
    blocks[pool->free_tail_idx].next_index = INVALID_BLOCK;
    pool->is_initialized = true;

    /* Unmap the memory. */
    sev_hal_clean_dcache((uint32_t)blocks, size);
    (void)sev_hal_unmap_memory(blocks);

end:
    return status;
}

/**
 * Destroy the memory pool.
 */
sev_status_t pool_vcpu_destroy(pool_vcpu_t *pool)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t *pool_blocks = NULL;
    uint32_t *crc_blocks = NULL;

    if (!pool)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (pool->is_initialized)
    {
        const size_t pool_size = pool->nr_blocks*INDEX_BLOCK_SIZE;
        const size_t crc_size = pool->nr_blocks*CRC_BLOCK_SIZE;

        /* Map the memory pool to access the free list. */
        status = sev_hal_map_memory(pool->start_pool_addr, (void **)&pool_blocks);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
        status = sev_hal_map_memory(pool->start_crc_addr, (void **)&crc_blocks);
        if (status != SEV_STATUS_SUCCESS)
            goto unmap;

        /* Delete any sensitive data in the pool (only the part being used) */
        secure_memzero(pool_blocks, pool_size);
        secure_memzero(crc_blocks, crc_size);

        /* Flush pending writes to the UMC */
        sev_hal_clean_invalidate_dcache((uint32_t)pool_blocks, pool_size);
        sev_hal_clean_invalidate_dcache((uint32_t)crc_blocks, crc_size);
        status = sev_hal_df_write_flush();
    }

    /* Reset the pool metadata */
    secure_memzero(pool, sizeof(*pool));

unmap:
    /* Unmap the memory. */
    (void)sev_hal_unmap_memory(pool_blocks);
    (void)sev_hal_unmap_memory(crc_blocks);

end:
    return status;
}

/**
 * Allocate a block from the trusted memory region. Returns a 64-bit x86
 * address that needs to be mapped with sev_hal_map_memory() before use.
 * On error, returns 0.
 */
uint64_t pool_vcpu_alloc(pool_vcpu_t *pool, uint32_t *index, uint64_t *crc_block_paddr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t rc = 0;
    int block_idx = 0;

    if (index == NULL || crc_block_paddr == NULL)
        goto end;

    if (!pool || !pool->is_initialized)
        goto end;

    if (pool_is_empty(pool))
        goto end;

    /* Remove a block from the free list */
    block_idx = list_remove_head(pool);
    if (block_idx < 0)
        goto end;

    /* Set next index to invalid */
    status = list_set_next_index(pool, block_idx, INVALID_BLOCK);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    *index = block_idx;
    *crc_block_paddr = idx_crc_block_to_addr64(pool, block_idx);

    rc = idx_to_addr64(pool, block_idx);

end:
    return rc;
}

/**
 * Free a trusted block back to the pool.
 */
void pool_vcpu_free(pool_vcpu_t *pool, uint64_t block)
{
    if (pool != NULL && block >= pool->start_pool_addr && block < pool->end_pool_addr)
        list_add_tail(pool, addr64_to_idx(pool, block));
}

uint64_t pool_vcpu_index_to_addr64(pool_vcpu_t *pool, size_t idx)
{
    return idx_to_addr64(pool, idx);
}

/**
 * Walk through the list the user passed in and free it back to the pool
 */
sev_status_t pool_vcpu_free_list(pool_vcpu_t *pool, uint32_t start_index,
                                 uint32_t end_index, uint32_t expected_entries)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    es_vcpu_t *blocks = NULL;
    uint32_t index = start_index;
    uint32_t free_count = 0;

    if (!pool)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (index == INVALID_BLOCK || end_index == INVALID_BLOCK)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Map the memory pool to access the free list */
    status = sev_hal_map_memory(pool->start_pool_addr, (void **)&blocks);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Ensure that we read the latest data from DRAM */
    sev_hal_invalidate_dcache((uint32_t)blocks, (INDEX_BLOCK_SIZE * pool->nr_blocks));

    do {
        blocks[pool->free_tail_idx].next_index = index;

        pool->free_tail_idx = index;

        free_count++;
        if (index == end_index)
            break;
        else
        {
            /* This should never happen */
            if (free_count >= expected_entries)
            {
                status = ERR_INVALID_PARAMS;
                goto unmap;
            }
            /* Go to the next index in the list from the user */
            index = blocks[index].next_index;
        }
    } while (index != INVALID_BLOCK);

    /* Flush pending writes to the UMC */
    sev_hal_clean_invalidate_dcache((uint32_t)blocks, (pool->nr_blocks*INDEX_BLOCK_SIZE));

unmap:
    /* Unmap the memory. */
    (void)sev_hal_unmap_memory(blocks);
end:
    return status;
}

sev_status_t pool_vcpu_find_crc_in_list(pool_vcpu_t *pool, uint32_t start_index,
                                        uint32_t end_index, uint64_t crc,
                                        uint32_t expected_entries, bool *found)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    es_vcpu_t *blocks = NULL;
    uint32_t index = 0;
    uint32_t search_index = 0;
    uint32_t search_count = 0;

    if (!pool)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (start_index == INVALID_BLOCK || end_index == INVALID_BLOCK)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = addr64_crc_to_idx(pool, crc, &search_index);
    if (status != SEV_STATUS_SUCCESS)
    {
        /* If it's out of range then it's an invalid address */
        status = SEV_STATUS_INVALID_ADDRESS;
        goto end;
    }

    *found = false;
    /* Map the memory pool to access the free list */
    status = sev_hal_map_memory(pool->start_pool_addr, (void **)&blocks);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Ensure that we read the latest data from DRAM */
    sev_hal_invalidate_dcache((uint32_t)blocks, (INDEX_BLOCK_SIZE * pool->nr_blocks));

    index = start_index;
    /* Search the user list to find if it matches */
    do {
        if (index == search_index)
        {
            *found = true;
            break;
        }

        search_count++;
        if (index == end_index)
            break;
        else
        {
            /* exit if it reach the end of the list */
            if (search_count >= expected_entries)
            {
                status = ERR_INVALID_PARAMS;
                break;
            }

            /* Go to the next index in the list from the user */
            index = blocks[index].next_index;
        }
    } while (index != INVALID_BLOCK);

    /* Unmap the memory. */
    (void)sev_hal_unmap_memory(blocks);

end:
    return status;
}
