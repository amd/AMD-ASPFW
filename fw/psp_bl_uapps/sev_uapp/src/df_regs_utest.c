// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>

#include "df_regs.h"
#include "df_regs_utest.h"

/**
 * D18F0x040 [Fabric Block Instance Count] (DF::FabricBlockInstanceCount)
 * FabricBlockInstanceCount is a read-only register, so it's value
 * will never change from the reset value.
 */
#define FABRIC_BLOCK_INSTANCE_COUNT_FUNC    (0)
#define FABRIC_BLOCK_INSTANCE_COUNT_OFFSET  (0x40)
#define FABRIC_BLOCK_INSTANCE_COUNT         (0x61)  /* Reset value (Genoa only) */
#define FABRIC_BLOCK_INSTANCE_COUNT_MASK    (0xFF)

/**
 * D18F6x380...D18F6x3FC [Scratch Register Area] (DF::ScratchRegister)
 * A block of 32 scratch registers are implemented for use by BIOS,
 * x86 microcode, PSP or SMU. We will use these to safely test register writes.
 */
#define SCRATCH_REGISTER_AREA_FUNC      (3)
#define SCRATCH_REGISTER_AREA_OFFSET    (0xE00)
#define SCRATCH_REGISTER_VALUE          (0xdeadbeef)

bool df_test_read32(void)
{
    uint32_t function = FABRIC_BLOCK_INSTANCE_COUNT_FUNC;
    uint32_t offset = FABRIC_BLOCK_INSTANCE_COUNT_OFFSET;
    uint32_t value = 0;

    read_df_reg32(PIE_INSTANCE_ID, function, offset, &value);

    return (value & FABRIC_BLOCK_INSTANCE_COUNT_MASK) == FABRIC_BLOCK_INSTANCE_COUNT;
}

bool df_test_read_bcast32(void)
{
    uint32_t function = FABRIC_BLOCK_INSTANCE_COUNT_FUNC;
    uint32_t offset = FABRIC_BLOCK_INSTANCE_COUNT_OFFSET;
    uint32_t value = 0;

    read_df_reg_bcast32(function, offset, &value);

    return (value & FABRIC_BLOCK_INSTANCE_COUNT_MASK) == FABRIC_BLOCK_INSTANCE_COUNT;
}

bool df_test_write32(void)
{
    /*
     * In case the register addressing code is incorrect, write to a register
     * in the middle of the bank. This way, if we write to the wrong register,
     * there is less likelihood that we will clobber something important.
     */
    uint32_t offset = SCRATCH_REGISTER_AREA_OFFSET + 16*sizeof(uint32_t);
    uint32_t function = SCRATCH_REGISTER_AREA_FUNC;
    uint32_t value = SCRATCH_REGISTER_VALUE;

    write_df_reg32(PIE_INSTANCE_ID, function, offset, value);
    read_df_reg32(PIE_INSTANCE_ID, function, offset, &value);

    return value == SCRATCH_REGISTER_VALUE;
}

bool df_test_write_bcast32(void)
{
    /*
     * In case the register addressing code is incorrect, write to a register
     * in the middle of the bank. This way, if we write to the wrong register,
     * there is less likelihood that we will clobber something important.
     */
    uint32_t offset = SCRATCH_REGISTER_AREA_OFFSET + 16*sizeof(uint32_t);
    uint32_t function = SCRATCH_REGISTER_AREA_FUNC;
    uint32_t value = SCRATCH_REGISTER_VALUE;

    write_df_reg_bcast32(function, offset, value);
    read_df_reg_bcast32(function, offset, &value);

    return value == SCRATCH_REGISTER_VALUE;
}

static bool (* const test_table[])(void) = {
        [0] = df_test_read32,
        [1] = df_test_read_bcast32,
        [2] = df_test_write32,
        [3] = df_test_write_bcast32,
};

void df_utest(size_t *nr_tests, size_t *nr_passed)
{
    size_t i = 0;
    size_t passed = 0;
    size_t tests = sizeof(test_table)/sizeof(test_table[0]);
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!nr_tests || !nr_passed)
        goto end;

    status = df_access_lock();
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    for (i = 0; i < tests; i++)
    {
        /* Run the test */
        passed += test_table[i]();
    }
    *nr_tests = tests;
    *nr_passed = passed;

    df_access_unlock();

end:
    return;
}
