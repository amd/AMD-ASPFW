// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#include "sev_errors.h"
#include "sev_trace.h"

void sev_fatal_error(const char *filename, const char *function, int line)
{
    SEV_TRACE("SEV ASSERT!!!");
    SEV_TRACE(filename);
    SEV_TRACE(function);
    SEV_TRACE_EX(line, 0, 0, 0);

    /* Soft hang here */
    while (1);
}

#ifdef DBG_ASSERT
void sev_assert(bool condition)
{
    if (!condition)
    {
        sev_fatal_error(__FILE__, __FUNCTION__, __LINE__);
    }
}
#endif    /* DBG_ASSERT */
