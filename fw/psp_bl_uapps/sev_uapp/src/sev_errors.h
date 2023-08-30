// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_ERRORS_H
#define SEV_ERRORS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "sev_status.h"

#define is_external_status(e)  ((e) <  SEV_STATUS_LIMIT)
#define is_internal_error(e)   ((e) >= ERR_UNKNOWN)
#define is_hardware_error(e)   ((e) >= ERR_HAL_SLAVE_DIE)

// Note: To catch a programmer's coding mistakes, debug assertion would be more appropriate
void sev_fatal_error(const char *filename, const char *function, int line);

#ifdef DBG_ASSERT
void sev_assert(bool condition);
#else
#define sev_assert(condition)    ((void)0)
#endif

#define sev_panic()    sev_fatal_error(__FILE__, __FUNCTION__, __LINE__)

inline void wait_for_debugger(void)
{
    volatile bool wait = true;

    while (wait);
}

#endif /* SEV_ERRORS_H */
