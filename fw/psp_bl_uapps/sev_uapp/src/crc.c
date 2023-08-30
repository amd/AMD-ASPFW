// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>

#include "crc.h"

#define CRC32C_POLY     (0x1EDC6F41ull)
#define INITIAL_POLY    (0xFFFFFFFFull)

/* Reverses (reflects) bits in a 32-bit dword. */
static uint32_t reverse_bits(uint32_t x)
{
    x = ((x & 0x55555555) <<  1) | ((x >>  1) & 0x55555555);
    x = ((x & 0x33333333) <<  2) | ((x >>  2) & 0x33333333);
    x = ((x & 0x0F0F0F0F) <<  4) | ((x >>  4) & 0x0F0F0F0F);
    x = (x << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | (x >> 24);
    return x;
}

/**
 * This is the basic CRC algorithm with no optimizations. It follows the
 * logic circuit as closely as possible and uses the Castagnoli polynomial.
 */
static sev_status_t crc32c(uint8_t *buffer, size_t size, uint32_t *crc32)
{
    size_t i = 0, j = 0;
    uint32_t crc = INITIAL_POLY;
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!buffer || size == 0 || !crc32)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    for (i = 0; i < size; i++)
    {
        uint32_t byte = buffer[i];
        byte = reverse_bits(byte);
        for (j = 0; j < 8; j++)
        {
            if ((int)(crc ^ byte) < 0)
                crc = (crc << 1) ^ CRC32C_POLY;
            else
                crc <<= 1;
            byte <<= 1;
        }
    }
    *crc32 = reverse_bits(~crc);

end:
    return status;
}

#define FIRST_ORDER_OFFSET  (0)
#define SECOND_ORDER_OFFSET (8)
#define THIRD_ORDER_OFFSET  (16)
#define CRC_SKIP            (24)

/**
 * For Genoa, the calculation of checksum for the VSMA block
 * is to calculate based on an offset, accumulate 8 byte chunks of CRC,
 * then combine the 3 different CRCs. The CRC calculation is
 * modeled based on the CRC32 instruction.
 *
 *  CRC0 - calculates CRC of bytes of offset 0-7, 24-31, etc.
 *  CRC1 - calculates CRC of bytes of offset 8-15, 32-39, etc.
 *  CRC2 - calculates CRC of bytes offset 16-23, 40, 47, etc.
 *
 * Any remaining bytes not multiple of (24) or CRC_SKIP is accumulated into CRC2.
 */
static sev_status_t crc32c_offset(uint8_t *buffer, size_t size, size_t offset, uint32_t *crc32)
{
    uint32_t i, j, k;
    uint32_t crc = INITIAL_POLY;
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t n_blocks = 0;
    uint32_t remainder = 0;
    uint32_t offset_index = 0;

    if (!buffer || size == 0 || !crc32)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Size must be multiple of 8 and at least CRC_SKIP (24) bytes */
    if ((size & 0x7) || (size < CRC_SKIP))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (offset != FIRST_ORDER_OFFSET && offset != SECOND_ORDER_OFFSET &&
        offset != THIRD_ORDER_OFFSET)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Find the number of blocks of CRC_SKIP (24 bytes) to process, rounding down */
    n_blocks = size / CRC_SKIP;

    /* Calculate CRC up to the highest multiple of CRC_SKIP (24), starting from offset value */
    for (i = 0; i < n_blocks; i++)
    {
        offset_index = (i * CRC_SKIP) + offset;

        /* Calculate CRC for 8 bytes at a time */
        for (j = offset_index; j < offset_index + 8; j++)
        {
            uint32_t byte = buffer[j];
            byte = reverse_bits(byte);
            for (k = 0; k < 8; k++)
            {
                if ((int)(crc ^ byte) < 0)
                    crc = (crc << 1) ^ CRC32C_POLY;
                else
                    crc <<= 1;
                byte <<= 1;
            }
        }
    }

    remainder = size - (n_blocks * CRC_SKIP);
    if (remainder != 0)
    {
        if (offset == THIRD_ORDER_OFFSET)
        {
            /*
             * The remainder of the values goes to the third
             * offset calculation in multiple of 8 bytes
             */
            for (i = n_blocks * CRC_SKIP; i < size; i += 8)
            {
                /* Calculate CRC for 8 bytes at a time */
                for (j = i; j < i + 8; j++)
                {
                    uint32_t byte = buffer[j];
                    byte = reverse_bits(byte);
                    for (k = 0; k < 8; k++)
                    {
                        if ((int)(crc ^ byte) < 0)
                            crc = (crc << 1) ^ CRC32C_POLY;
                        else
                            crc <<= 1;
                        byte <<= 1;
                    }
                }
            }
        }
    }

    *crc32 = reverse_bits(~crc);

end:
    return status;
}

/**
 *  Calculates CRC64 of the VMSA block
 *    - 3 CRC calculations up to the size of the block, with starting offsets at 0, 8, and 16
 *      and accumulates every 8 bytes. The remainder of the bytes that is not multiple of 24
 *      goes into the 3rd CRC
 *    - The 3 CRC results are combined together to calculate the final CRC32 value.
 *
 *   Final CRC64 is [CRC0 ^ CRC1 ^ CRC2][Combined CRC]
 */
sev_status_t crc64_vmsa(uint8_t *buffer, size_t size, uint64_t *crc64)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t temp_crc[3] = {0};
    uint32_t crc0 = 0;
    uint32_t crc1 = 0;
    uint32_t crc2 = 0;
    uint32_t crc32 =  0;

    if (size == 0 || buffer == NULL || crc64 == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = crc32c_offset(buffer, size, FIRST_ORDER_OFFSET, &crc0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    temp_crc[0] = crc0;

    status = crc32c_offset(buffer, size, SECOND_ORDER_OFFSET, &crc1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    temp_crc[1] = crc1;

    status = crc32c_offset(buffer, size, THIRD_ORDER_OFFSET, &crc2);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    temp_crc[2] = crc2;

    /* Calculate the combined CRC */
    status = crc32c((uint8_t *)temp_crc, sizeof(temp_crc), &crc32);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Get upper 32 bits, CRC0 ^ CRC1 ^ CRC2 */
    *crc64 = (uint64_t)(crc0 ^ crc1 ^ crc2) << 32ULL;

    *crc64 |= (uint64_t)crc32;

end:
    return status;
}
