// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_UAPP_CRC_H
#define SEV_UAPP_CRC_H

#include "sev_status.h"

/**
 * Calculate the 64-bit CRC of the input buffer
 */
sev_status_t crc64_vmsa(uint8_t *buffer, size_t size, uint64_t *crc64);

#endif /* SEV_UAPP_CRC_H */
