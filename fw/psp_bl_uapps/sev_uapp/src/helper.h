// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#ifndef HELPER_H
#define HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "sev_errors.h"
#include "sev_status.h"

static inline uint64_t to_addr64(uint32_t lo, uint32_t hi)
{
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static inline bool flags_valid(uint32_t flags, uint32_t mbz_mask)
{
    return (flags & mbz_mask) == 0;
}

static inline uint64_t read_reg64(void *addr)
{
    return *(volatile uint64_t *)addr;
}

static inline void write_reg64(void *addr, uint64_t value)
{
    *(volatile uint64_t *)addr = value;
}

/**
 * Test if an object is empty (i.e. all zeros).
 */
bool is_empty(const void *object, size_t size);

/**
 * Reverse 'size' bytes from the byte string pointed to by 'bytes'.
 */
sev_status_t reverse_bytes(uint8_t *bytes, size_t size);

#endif /* HELPER_H */
