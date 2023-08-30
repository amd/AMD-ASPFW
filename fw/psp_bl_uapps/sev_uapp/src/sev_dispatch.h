// Copyright(C) 2016-2019 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_DISPATCH_H
#define SEV_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"
#include "sev_mcmd.h"

/**
 * Dispatches an SEV slave command.
 *
 * The 'sev_svc_slave()' function calls this function.
 */
sev_status_t sev_dispatch_slave(void *pCmd);

/**
 * Dispatches an SEV API (aka master) command.
 *
 * The 'sev_svc_master()' function calls this function. Once called,
 * this function performs the following steps:
 *
 *   1. Reads the command ID from 'CmdResp' to determine which command
 *      is being called.
 *
 *   2. Validates the pointer+length of the command buffer.
 *
 *   3. Copies the command buffer (but not any data that the command
 *      buffer may point to) into private memory.
 *
 *   4. Passes the command buffer to the correct command handler.
 *
 *   5. Writes the returned status code into the CmdResp
 *      register. (XXX Should this be done in the sev_svc.h functions
 *      instead?)
 *
 *   6. Returns.
 */
sev_status_t sev_dispatch_master(sev_mcmd_id_t CmdId, uint32_t CmdBuf_Lo, uint32_t CmdBuf_Hi);

/**
 * Function that wipes out the dispatch master table, except for
 * the command ID provided as a parameter. This is used by DLFW_EX_CONTINUED
 * in the awkward case where the new/current FW can't abide the system
 * configuration, but the Boot Loader can't restore the old FW (1.0.0.4 to
 * 1.0.0.6 boot loaders had a bug in the RESTORE subop for cache_new_image.)
 * Rather than add code to every command to check for the rare case, we
 * instead levarage the existing tests in sev_dispatch_master() to prevent
 * execution of any command except DLFW_EX, which will expect the committed
 * old FW to be restored by the HV.
 */
sev_status_t clear_dispatch_master(sev_mcmd_id_t CmdId);

#endif /* SEV_DISPATCH_H */
