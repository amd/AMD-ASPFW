// Copyright(C) 2016-2018 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_GLOBALS_H
#define SEV_GLOBALS_H

#include <stddef.h>
#include <stdint.h>

#include "sev_plat.h"

extern uint32_t Image$$SEV_UAPP_STACK$$ZI$$Base;
extern uint32_t Image$$SEV_UAPP_STACK$$ZI$$Limit;
extern uint32_t Image$$SEV_UAPP_DATA$$ZI$$Base;
extern uint32_t Image$$SEV_UAPP_DATA$$ZI$$Length;

extern uint32_t gTotalDieNum;
extern uint32_t gCurrentDieID;

extern sev_persistent_globals_t gPersistent;
extern sev_t gSev;

/* There's a 20KB scratch area */
#define SEV_SCRATCH_BUF_LEN 0x5000
extern uint8_t *gpSevScratchBuf;

extern sev_rsvd_dram_t *gpDram;

#endif /* SEV_GLOBALS_H */
