// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sev_extended_errors.h"
#include "sev_globals.h"
#include "sev_hal.h"
#include "sev_ring_buffer.h"

void sev_rb_copy_mailbox(sev_rb_state_t *state)
{
    state->x86_control.u.val = ReadReg32(SEV_CMD_RESP_REG); /* CmdResp       -> rb_ctl */
    state->x86_tail.u.val = ReadReg32(SEV_CMD_RB_X86_TAIL); /* CmdBufAddr_Hi -> rb_tail */
    /* Don't read rb_head - it's controlled solely by firmware */
}

static sev_status_t sev_rb_dequeue(sev_rb_queue_type queue_type, sev_rb_state_t *state,
                                   uint32_t *cmd_id, uint32_t *cmd_low, uint32_t *cmd_high)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t index = 0;
    uint64_t queue_base_addr = 0;
    volatile sev_rb_cmd_ptr_entry_t *base_entry = NULL;
    void *axi_addr = NULL;
    uint64_t cmd_buffer_ptr = 0;

    if (!state || !cmd_id || !cmd_low || !cmd_high)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (queue_type == HIGH_PRIORITY)
    {
        index = (uint32_t)state->sev_head.u.field.hi_q_index;
        queue_base_addr = gpDram->perm.rb_config.cmd_ptr_high_priority_addr;
    }
    else
    {
        index = (uint32_t)state->sev_head.u.field.lo_q_index;
        queue_base_addr = gpDram->perm.rb_config.cmd_ptr_low_priority_addr;
    }

    status = sev_hal_map_memory(queue_base_addr, &axi_addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    base_entry = (sev_rb_cmd_ptr_entry_t *)axi_addr;
    //sev_hal_invalidate_dcache(axi_addr, SEV_RB_CMD_BUFFER_MAX_SIZE * sizeof(sev_rb_cmd_ptr_entry_t));
    cmd_buffer_ptr = base_entry[index].cmd_buffer_ptr;

    *cmd_id = base_entry[index].cmd_id;
    *cmd_low = (uint32_t)(cmd_buffer_ptr & 0xFFFFFFFFULL);
    *cmd_high = (uint32_t)(cmd_buffer_ptr >> 32ULL);

    /* Save the flag for use later. Save state for post processing */
    state->process_state.cmd_flags = base_entry[index].cmd_flags;
    state->process_state.queue_in_process = queue_type;
    state->process_state.queue_index = index;

    sev_hal_unmap_memory(axi_addr);

end:
    return status;
}

static sev_status_t sev_rb_save_status(sev_rb_state_t *state, sev_status_t status_save)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint64_t queue_base_addr = NULL;
    uint32_t index = 0;
    void *axi_addr = NULL;
    sev_rb_cmd_status_entry_t *base_entry = NULL;

    if (!state)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    index = state->process_state.queue_index;
    if (state->process_state.queue_in_process == HIGH_PRIORITY)
    {
        queue_base_addr = gpDram->perm.rb_config.status_ptr_high_priority_addr;
    }
    else
    {
        queue_base_addr = gpDram->perm.rb_config.status_ptr_low_priority_addr;
    }

    status = sev_hal_map_memory(queue_base_addr, &axi_addr);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    base_entry = (sev_rb_cmd_status_entry_t *)axi_addr;
    base_entry[index].status = (uint16_t)status_save;
    base_entry[index].error_stack = sev_error_stack;
    sev_hal_unmap_memory(axi_addr);

    /* Status is updated. Now update Mailbox */
    /* Wrap around if it is at maximum */
    index++;
    if (index >= SEV_RB_CMD_BUFFER_MAX_SIZE)
        index = 0;
    if (state->process_state.queue_in_process == HIGH_PRIORITY)
    {
        state->sev_head.u.field.hi_q_index = index;
    }
    else
    {
        state->sev_head.u.field.lo_q_index = index;
    }

end:
    return status;
}

static void check_queue_depth(uint32_t head, uint32_t tail, uint32_t depth_check,
                              bool *triggered_thresh)
{
    uint32_t depth = 0;
    *triggered_thresh = false;

    if (depth_check == 0)
        return;

    /* Tail should be bigger than head unless it's wrap around */
    if (head > tail)
    {
        tail += SEV_RB_CMD_BUFFER_MAX_SIZE;
    }

    /* depth measures how many are queued up */
    depth = tail - head;

    /* Trigger an interrupt for each completed command as long as the
     * number of commands is fewer than the HV tries to keep in the Q */
    if (depth < depth_check)
        *triggered_thresh = true;
}

/**
 * sev_rb_get_cmd:
 *  1. Handling Queue Pause Recovery.
 *  2. Handling Queue Depth checking
 *  3. Calls DEQUEUE function to fetch the CMD.
 */
static sev_status_t sev_rb_get_cmd(sev_rb_state_t *state, uint32_t *cmd,
                                   uint32_t *cmd_low, uint32_t *cmd_high,
                                   bool *cmd_fetched)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_rb_queue_type queue_type = LOW_PRIORITY;
    bool hi_queue_paused = true, low_queue_paused = true;
    bool queue_valid = false;
    bool triggered_thresh = false;

    *cmd_fetched = false;

    /*
     * Let's find out which queue is still paused.
     *   State machine:
     *      when QUEUE RUNNING = 0, we wait for RESUME_QUEUE
     *      to be set. Then we set QUEUE_RUNNING = 1, write back
     *      to mailbox (previous function).
     *      Then we wait for RESUME QUEUE to be cleared before
     *      we process the queue.
     *
     *      Therefore, RESUME_QUEQUE must be zero and QUEUE_RUNNING
     *      must be 1 before we dequeue
     */

    /* If normal state, then process the queue */
    if ((state->x86_control.u.field.resume_lo_queue == 0) &&
        (state->sev_head.u.field.lo_queue_running == 1))
    {
        low_queue_paused = false;
    }

    if ((state->x86_control.u.field.resume_hi_queue == 0) &&
        (state->sev_head.u.field.hi_queue_running == 1))
    {
        hi_queue_paused = false;
    }

    if (hi_queue_paused == false)
    {
        /* Check Queue Depth */
        check_queue_depth(state->sev_head.u.field.hi_q_index,
                          state->x86_tail.u.field.hi_q_index,
                          gpDram->perm.rb_config.high_queue_threshold,
                          &triggered_thresh);
        if (triggered_thresh && state->x86_control.u.field.hi_queue_empty_int)
        {
            if (state->sev_head.u.field.q_free_int_stat == 0)
            {
                state->sev_head.u.field.q_free_int_stat = 1;
            }
            state->process_state.generate_q_free_int = 1;
        }
        if (state->x86_tail.u.field.hi_q_index != state->sev_head.u.field.hi_q_index)
        {
            /* Check Queue Depth */
            check_queue_depth(state->sev_head.u.field.hi_q_index,
                              state->x86_tail.u.field.hi_q_index,
                              gpDram->perm.rb_config.high_queue_threshold,
                              &triggered_thresh);
            if (triggered_thresh && state->x86_control.u.field.hi_queue_empty_int)
            {
                if (state->sev_head.u.field.q_free_int_stat == 0)
                {
                    state->sev_head.u.field.q_free_int_stat = 1;
                }
                state->process_state.generate_q_free_int = 1;
            }
            /* Process higher priority queue */
            queue_type = HIGH_PRIORITY;
            queue_valid = true;
        }
    }

    /* Check low priority queue if nothing is in the higher queues */
    if (low_queue_paused == false && queue_valid == false)
    {
        /* Check Queue Depth */
        check_queue_depth(state->sev_head.u.field.lo_q_index,
                          state->x86_tail.u.field.lo_q_index,
                          gpDram->perm.rb_config.low_queue_threshold,
                          &triggered_thresh);
        if (triggered_thresh && state->x86_control.u.field.lo_queue_empty_int)
        {
            if (state->sev_head.u.field.q_free_int_stat == 0)
            {
                state->sev_head.u.field.q_free_int_stat = 1;
            }
            state->process_state.generate_q_free_int = 1;
        }

        if (state->x86_tail.u.field.lo_q_index != state->sev_head.u.field.lo_q_index)
        {
            /* Check Queue Depth */
            check_queue_depth(state->sev_head.u.field.lo_q_index,
                              state->x86_tail.u.field.lo_q_index,
                              gpDram->perm.rb_config.low_queue_threshold,
                              &triggered_thresh);
            if (triggered_thresh && state->x86_control.u.field.lo_queue_empty_int)
            {
                if (state->sev_head.u.field.q_free_int_stat == 0)
                {
                    state->sev_head.u.field.q_free_int_stat = 1;
                }
                state->process_state.generate_q_free_int = 1;
            }

            queue_type = LOW_PRIORITY;
            queue_valid = true;
        }
    }

    if (queue_valid == false)
    {
        if (gpDram->perm.rb_config.int_on_empty)
        {
            state->sev_head.u.field.all_queue_empty_int_stat = 1;
            state->process_state.generate_queue_empty_int = 1;
        }
        *cmd_fetched = false;
        goto end;
    }

    status = sev_rb_dequeue(queue_type, state, cmd, cmd_low, cmd_high);
    if (status == SEV_STATUS_SUCCESS)
    {
        *cmd_fetched = true;
    }

end:
    return status;
}

static sev_status_t sev_rb_pre_cmd_error_handling(sev_rb_state_t *state)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool update_sev_head = false;

    if (!state)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (state->sev_head.u.field.hi_queue_running == 0 && gpDram->perm.rb_config.high_priority_queue_size != 0)
    {
        if (state->x86_control.u.field.resume_hi_queue == 1)
        {
            /* Recovery - write queue_running. X86 will have to set resume_hi_queue = 0 */
            state->sev_head.u.field.hi_queue_running = 1;
            update_sev_head = true;
        }
    }

    if (state->sev_head.u.field.lo_queue_running == 0)
    {
        if (state->x86_control.u.field.resume_lo_queue == 1)
        {
            /* Recovery - write queue_running. X86 will have to set resume_hi_queue = 0 */
            state->sev_head.u.field.lo_queue_running = 1;
            update_sev_head = true;
        }
    }

    if (update_sev_head)
    {
        WriteReg32(SEV_CMD_RB_SEV_HEAD, state->sev_head.u.val);
    }

end:
    return status;
}

sev_status_t sev_rb_pre_cmd_process(sev_rb_state_t *state, uint32_t *cmd,
                                    uint32_t *cmd_low, uint32_t *cmd_high,
                                    bool *cmd_fetched)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!state || !cmd || !cmd_low || !cmd_high || !cmd_fetched)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check if Ring Buffer is still valid */
    if (state->x86_control.u.field.rb_mode_active == 0 ||
        state->x86_control.u.field.x86_control == 0)
    {
        *cmd_fetched = false;
        gpDram->perm.rb_config.rb_enable = false;

        goto end;
    }

    /* Clear the internal interrupt trackers */
    state->process_state.generate_cmd_done_int = 0;
    state->process_state.generate_queue_empty_int = 0;
    state->process_state.generate_q_free_int = 0;
    state->process_state.generate_q_pause_int = 0;

    /* Check if interrupt clear has been written, if so clear it */
    if (state->x86_control.u.field.clear_int_bits)
    {
        state->sev_head.u.field.all_queue_empty_int_stat = 0;
        state->sev_head.u.field.cmd_done_int_stat = 0;
        state->sev_head.u.field.q_free_int_stat = 0;
        state->sev_head.u.field.q_paused_int_stat = 0;

        /* Write back */
        WriteReg32(SEV_CMD_RB_SEV_HEAD, state->sev_head.u.val);
    }

    /* Process the state machine for error handling, if any */
    status = sev_rb_pre_cmd_error_handling(state);
    if (status != SEV_STATUS_SUCCESS)
    {
        *cmd_fetched = false;
        goto end;
    }

    /* This function is called before dispatching to SEV */
    /* This function needs to handle error handling and dequeue */
    /* For now, just fetch */
    status = sev_rb_get_cmd(state, cmd, cmd_low, cmd_high, cmd_fetched);
    if (*cmd_fetched == false)
    {
        /* No valid command, just update the HEAD register */
        WriteReg32(SEV_CMD_RB_SEV_HEAD, state->sev_head.u.val);
    }

end:
    return status;
}

sev_status_t sev_rb_generate_interrupt(sev_rb_state_t *state)
{
    uint32_t generate_int = 0;
    uint8_t interrupt = SEV_MAILBOX_INTERRUPT;
    uint32_t rc = BL_OK;

    /* Generate interrupt if any of these actions are set */
    generate_int = state->process_state.generate_cmd_done_int    |
                   state->process_state.generate_queue_empty_int |
                   state->process_state.generate_q_free_int      |
                   state->process_state.generate_q_pause_int;

    if (generate_int)
    {
        if (gPersistent.bl_fw_version >= MIN_BL_VERSION_ASPT) {
            /* Generate interrupt to x86 via PCI MSI/MSIX or via ASPT based on mode applied */
            rc = Svc_GetSetSystemProperty(PROP_ID_GENERATE_INTR_x86,&interrupt,sizeof(uint8_t));
            if (rc != BL_OK)
                return SEV_STATUS_INVALID_PARAM;
        } else {
            /* Writing any value to this register will interrupt the x86 */
            WriteReg32(SEV_X86_RESPONSE_IOC_REG, 1);
        }
    }
    return SEV_STATUS_SUCCESS;
}

sev_status_t sev_rb_post_cmd_process(sev_rb_state_t *state, sev_status_t status_save)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool continue_process = true;

    status = sev_rb_save_status(state, status_save);
    if (status_save != SEV_STATUS_SUCCESS)
    {
        if (state->process_state.cmd_flags & SEV_RB_CMD_FLAG_CONT_ON_ERROR)
        {
            continue_process = true;
        }
        else
        {
            continue_process = false;
        }
    }

    if (continue_process == false)
    {
        /* Turn off the queue */
        if (state->process_state.queue_in_process == HIGH_PRIORITY)
        {
            state->sev_head.u.field.hi_queue_running = 0;
        }
        else
        {
            state->sev_head.u.field.lo_queue_running = 0;
        }

        if (state->sev_head.u.field.q_paused_int_stat == 0)
        {
            state->sev_head.u.field.q_paused_int_stat = 1;
        }
        state->process_state.generate_q_pause_int = 1;
    }

    if (state->process_state.cmd_flags & SEV_RB_CMD_FLAG_INT_COMPLETE)
    {
        if (state->sev_head.u.field.cmd_done_int_stat == 0)
        {
            state->sev_head.u.field.cmd_done_int_stat = 1;
        }

        state->process_state.generate_cmd_done_int = 1;
    }

    /* At this point, the queue pointer has been incremented */
    WriteReg32(SEV_CMD_RB_SEV_HEAD, state->sev_head.u.val);

    return status;
}
