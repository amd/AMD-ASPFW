// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_RING_BUFFER_H
#define SEV_RING_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#include "sev_status.h"

/* cmd_flags */
#define SEV_RB_CMD_FLAG_INT_COMPLETE  (1 << 0)  /* Interrupt when command completes */
#define SEV_RB_CMD_FLAG_CONT_ON_ERROR (1 << 1)  /* Continue or pause queue on error */

#define SEV_MAILBOX_INTERRUPT                   0x01u /* Mailbox interrupt ID*/
typedef enum
{
    HIGH_PRIORITY = 0,
    LOW_PRIORITY  = 1
} sev_rb_queue_type;

typedef struct sev_rb_cmd_ptr_entry
{
    uint16_t cmd_id;
    uint16_t cmd_flags;
    uint32_t software_data;     /* Reserved for x86 */
    uint64_t cmd_buffer_ptr;
} __attribute__((packed))sev_rb_cmd_ptr_entry_t;

typedef struct sev_rb_status_entry  /* StatVal entry */
{
    uint16_t status;
    uint16_t reserved;
    uint32_t reserved2;
    uint64_t error_stack;
} __attribute__((packed))sev_rb_cmd_status_entry_t;

typedef struct sev_rb_control_register_bits /* RBCtl */
{
    uint32_t lo_queue_empty_int     : 1; /* Enable Lo priority queue near empty interrupt */
    uint32_t hi_queue_empty_int     : 1; /* Enable Hi priority queue near empty interrupt */
    uint32_t reserved               : 6;
    uint32_t resume_lo_queue        : 1; /* Resume Lo priority queue (Part of queue error recovery) */
    uint32_t resume_hi_queue        : 1; /* Resume Hi priority queue (Part of queue error recovery) */
    uint32_t reserved2              :19;
    uint32_t clear_int_bits         : 1; /* Clear Interrupt Status bits in RBHead register */
    uint32_t rb_mode_active         : 1; /* Indicates Ring Buffer mode active */
    uint32_t x86_control            : 1; /* Indicates x86 controls the register */
} __attribute__((packed))sev_rb_control_register_bits_t;

typedef struct sev_rb_control_register
{
    union
    {
        sev_rb_control_register_bits_t field;
        uint32_t                       val;
    } __attribute__((packed)) u;
} __attribute__((packed)) sev_rb_control_register_t;

typedef struct sev_rb_tail_bits
{
    uint8_t lo_q_index; /* Lo priority Queue CmdPtr Tail index */
    uint8_t reserved1;
    uint8_t hi_q_index; /* Hi priority Queue CmdPtr Tail index */
    uint8_t reserved2;
} __attribute__((packed)) sev_rb_bits_t;

typedef struct sev_rb_tail
{
    union
    {
        sev_rb_bits_t field;
        uint32_t      val;
    } __attribute__((packed)) u;
} __attribute__((packed)) sev_rb_tail_t;

typedef struct sev_rb_head_bits
{
    uint32_t lo_q_index                 : 8;    /* Lo priority Queue CmdPtr Head index */
    uint32_t reserved1                  : 3;
    uint32_t lo_queue_running           : 1;    /* Lo priority Queue is running */
    uint32_t reserved2                  : 4;
    uint32_t hi_q_index                 : 8;    /* Hi priority Queue CmdPtr Head index */
    uint32_t reserved                   : 3;
    uint32_t hi_queue_running           : 1;    /* Hi priority Queue is running */
    uint32_t all_queue_empty_int_stat   : 1;    /* All queues are empty */
    uint32_t cmd_done_int_stat          : 1;    /* A command with InterruptOnCompletion set completed */
    uint32_t q_paused_int_stat          : 1;    /* A command without ContinueOnError set did not return SUCCESS */
    uint32_t q_free_int_stat            : 1;    /* A queue is near empty */
} __attribute__((packed)) sev_rb_head_bits_t;

typedef struct sev_rb_head
{
    union
    {
        sev_rb_head_bits_t field;
        uint32_t           val;
    } __attribute__((packed)) u;
} __attribute__((packed)) sev_rb_head_t;

/**
 * Processing State
 * - Interrupt trackers exist because some interrupts trigger on each command
 *   and some are only once
 */
typedef struct sev_rb_process_state /* Internal structure */
{
    sev_rb_queue_type queue_in_process;
    uint32_t queue_index;
    uint16_t cmd_flags;
    uint8_t generate_queue_empty_int;   /* Int tracker for rb_head.all_queue_empty_int_stat */
    uint8_t generate_cmd_done_int;      /* Int tracker for rb_head.cmd_done_int_stat */
    uint8_t generate_q_pause_int;       /* Int tracker for rb_head.q_paused_int_stat */
    uint8_t generate_q_free_int;        /* Int tracker for rb_head.q_free_int_stat */
} sev_rb_process_state_t;

typedef struct sev_rb_state
{
    sev_rb_control_register_t x86_control;  /* CmdResp       -> rb_ctl */
    sev_rb_tail_t             x86_tail;     /* CmdBufAddr_Hi -> rb_tail */
    sev_rb_head_t             sev_head;     /* CmdBufAddr_Lo -> rb_head */
    sev_rb_process_state_t    process_state;
} sev_rb_state_t;

typedef struct sev_rb_config
{
    bool rb_enable;
    bool int_on_empty;
    uint64_t cmd_ptr_low_priority_addr;
    uint64_t cmd_ptr_high_priority_addr;
    uint64_t status_ptr_low_priority_addr;
    uint64_t status_ptr_high_priority_addr;
    uint64_t status_ptr_low_priority_reclaim;
    uint64_t status_ptr_high_priority_reclaim;
    uint16_t low_queue_threshold;
    uint16_t high_queue_threshold;
    sev_rb_state_t state;
    uint8_t low_priority_queue_size;
    uint8_t high_priority_queue_size;
} sev_rb_config_t;

#define SEV_RB_CMD_BUFFER_MAX_SIZE (PAGE_SIZE_4K / sizeof(sev_rb_cmd_ptr_entry_t))

sev_status_t sev_rb_pre_cmd_process(sev_rb_state_t *state, uint32_t *cmd,
                                    uint32_t *cmd_low, uint32_t *cmd_high,
                                    bool *valid_cmd);
sev_status_t sev_rb_generate_interrupt(sev_rb_state_t *state);
sev_status_t sev_rb_post_cmd_process(sev_rb_state_t *state, sev_status_t status_save);
void sev_rb_copy_mailbox(sev_rb_state_t *state);

#endif /* SEV_RING_BUFFER_H */
