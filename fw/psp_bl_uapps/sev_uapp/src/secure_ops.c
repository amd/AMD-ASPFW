// Copyright(C) 2017-2018 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "secure_ops.h"

int secure_compare(const void *left, const void *right, size_t size)
{
    int result = 0;
    const uint8_t *l = left, *r = right;
    size_t i = 0;

    if (!l || !r)
    {
        result = 0x200;     /* (0x200 + 0xff >> 8) = 2 */
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        result |= l[i] ^ r[i];
    }

end:
    return (result + 0xff) >> 8;    // 0=equal, 1=not-equal, 2=error
}

int secure_array_compare_le(const void *left, const void *right, size_t size)
{
    uint8_t gt = 0;
    uint8_t eq = 1;
    const uint8_t *l = left, *r = right;
    size_t i = size;

    /* Compare the numbers */
    while (i != 0)
    {
        i--;
        gt |= ((r[i] - l[i]) >> 8) & eq;
        eq &= ((r[i] ^ l[i]) - 1) >> 8;
    }

    return (2 - (gt + eq + eq));    // 0=equal, 1=left>right, 2=left<right
}

void secure_memzero(void *buffer, size_t size)
{
    if (size > 0)
    {
// MEHDI: Statements below are true only when this function is declared inline.
//        You can safely use memset here without worrying from being optimized.
//        Optimization happens when memset done on a memory just before getting
//        freed or going out of scope.
//#ifdef __STDC_LIB_EXT1__
//        /* Use memset_s() from C11 which cannot be optimized away. */
//        memset_s(buffer, 0, size);
//#elif defined(__GNUC__) || defined(__clang__)
//        /*
//         * Define a memory clobber to prevent the memset() from being optimized
//         * away.
//         */
        memset(buffer, 0, size);
//        __asm__ __volatile__("" : : "r" (buffer) : "memory");
//#else
//        /* Zero the data by accessing it through a volatile pointer */
//        volatile char *p = buffer;
//        size_t len = size;
//
//        while (len--) *p++ = 0;
//#endif
    }
}
