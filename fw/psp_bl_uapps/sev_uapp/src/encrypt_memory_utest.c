// Copyright(C) 2017-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sev_globals.h"
#include "x86_copy.h"

#define TEST_X86_ADDR    (0x130000000)

sev_status_t encrypt_memory_utest(void)
{
    char plaintext[] = "Jesse Rules!!!!";    /* 16 byte-aligned */
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t x86_addr = TEST_X86_ADDR;
    size_t asid = 1;

    /* Copy the plaintext to the scratch buffer */
    memcpy(gpSevScratchBuf, plaintext, sizeof(plaintext));

    /* Copy the scratch buffer contents to x86 memory with the C-bit set */
    status = copy_to_x86_encrypted(x86_addr, gpSevScratchBuf, sizeof(plaintext), asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Decrypt the x86 memory and copy it to a neighboring location */
    status = decrypt_memory(x86_addr, x86_addr + sizeof(plaintext),
                            gpSevScratchBuf+sizeof(plaintext),
                            sizeof(plaintext), asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the unencrypted bytes back to the scratch buffer */
    status = copy_from_x86_encrypted(x86_addr, gpSevScratchBuf, sizeof(plaintext), asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* The unencrypted bytes should be identical to the plaintext */
    if (memcmp(plaintext, gpSevScratchBuf, sizeof(plaintext)) != 0)
        status = ERR_UNKNOWN;

end:
    return status;
}
