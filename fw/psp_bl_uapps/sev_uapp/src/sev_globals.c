// Copyright(C) 2016-2018 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>

#include "sev_globals.h"

/* Included from /fw/common/ to access AMD root public key */
#include "psp_key_image.h"
#include "dram_map.h"

/* Note that gSev and gPersistent are completely unique to each socket and data
   is only shared between sockets through gpDram */
uint32_t gTotalDieNum = 0;
uint32_t gCurrentDieID = 0xFFFFFFFF;
sev_persistent_globals_t gPersistent;

/* Note: moved from .bss to zero_init once section. */
sev_t gSev __attribute__((section ("init_once"), zero_init));

sev_rsvd_dram_t *gpDram __attribute__((section ("init_once"), zero_init));

/**
 * SEV_UAPP_SCRATCH_AREA can be used as a static buffer.
 * SEV user app scratch buffer, can be used as intermediate buffer for
 * compression, AES, SHA, etc.
 *
 * This buffer is NOT persistent.
 */
uint8_t gSevScratchBuf[SEV_SCRATCH_BUF_LEN] __attribute__((section ("scratch_space"), zero_init));
uint8_t *gpSevScratchBuf = gSevScratchBuf;
