// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_GUEST_H
#define SEV_GUEST_H

#include <stddef.h>
#include <stdint.h>

#include "digest.h"
#include "sev_channel.h"
#include "sev_errors.h"
#include "sev_es.h"
#include "sev_mcmd.h"
#include "sev_plat.h"
#include "sw_hash.h"

/* SEV Policy bits */
#define SEV_GUEST_POLICY_NODBG_BIT          (0)
#define SEV_GUEST_POLICY_NOKS_BIT           (1)
#define SEV_GUEST_POLICY_ES_BIT             (2)
#define SEV_GUEST_POLICY_NOSEND_BIT         (3)
#define SEV_GUEST_POLICY_DOMAIN_BIT         (4)
#define SEV_GUEST_POLICY_SEV_BIT            (5)
#define SEV_GUEST_POLICY_RESERVED_SHIFT     (6)
#define SEV_GUEST_POLICY_API_MAJOR_SHIFT    (16)
#define SEV_GUEST_POLICY_API_MINOR_SHIFT    (24)

#define SEV_GUEST_POLICY_NODBG_FLAG         (1ul << (SEV_GUEST_POLICY_NODBG_BIT))
#define SEV_GUEST_POLICY_NOKS_FLAG          (1ul << (SEV_GUEST_POLICY_NOKS_BIT))
#define SEV_GUEST_POLICY_ES_FLAG            (1ul << (SEV_GUEST_POLICY_ES_BIT))
#define SEV_GUEST_POLICY_NOSEND_FLAG        (1ul << (SEV_GUEST_POLICY_NOSEND_BIT))
#define SEV_GUEST_POLICY_DOMAIN_FLAG        (1ul << (SEV_GUEST_POLICY_DOMAIN_BIT))
#define SEV_GUEST_POLICY_SEV_FLAG           (1ul << (SEV_GUEST_POLICY_SEV_BIT))
#define SEV_GUEST_POLICY_RESERVED_MASK      (0x10000ul - (1ul << (SEV_GUEST_POLICY_RESERVED_SHIFT)))
#define SEV_GUEST_POLICY_API_MAJOR_MASK     (0xFFul << (SEV_GUEST_POLICY_API_MAJOR_SHIFT))
#define SEV_GUEST_POLICY_API_MINOR_MASK     (0xFFul << (SEV_GUEST_POLICY_API_MINOR_SHIFT))

#define sev_policy_minor(policy)    ((policy & SEV_GUEST_POLICY_API_MINOR_MASK) >> SEV_GUEST_POLICY_API_MINOR_SHIFT)
#define sev_policy_major(policy)    ((policy & SEV_GUEST_POLICY_API_MAJOR_MASK) >> SEV_GUEST_POLICY_API_MAJOR_SHIFT)

/* SNP Policy bits */
#define SNP_GUEST_POLICY_API_MINOR_SHIFT     (0)    /* Minimum ABI minor version required for this guest to run */
#define SNP_GUEST_POLICY_API_MAJOR_SHIFT     (8)    /* Minimum ABI major version required for this guest to run */
#define SNP_GUEST_POLICY_SMT_SHIFT           (16)   /* 1: SMT is allowed. 0: SMT is disallowed */
#define SNP_GUEST_POLICY_VMPL_SHIFT          (17)   /* 1: VMPLs must be enabled. 0: VMPLs are not required */
#define SNP_GUEST_POLICY_MIGRATE_MA_SHIFT    (18)   /* 1: Migration via a MA is allowed. 0: Migration via a MA is disallowed */
#define SNP_GUEST_POLICY_DEBUG_SHIFT         (19)   /* 1: Debugging is allowed. 0: Debugging is disallowed */
#define SNP_GUEST_POLICY_SINGLE_SOCKET_SHIFT (20)   /* 1: Can activate on 1 socket. 0: Can activate on multiple sockets */
#define SNP_GUEST_POLICY_RESERVED_SHIFT      (21)

#define SNP_GUEST_POLICY_API_MINOR_MASK     (0xFFul << (SNP_GUEST_POLICY_API_MINOR_SHIFT))
#define SNP_GUEST_POLICY_API_MAJOR_MASK     (0xFFul << (SNP_GUEST_POLICY_API_MAJOR_SHIFT))
#define SNP_GUEST_POLICY_SMT_FLAG           (1ul << (SNP_GUEST_POLICY_SMT_SHIFT))
#define SNP_GUEST_POLICY_VMPL_FLAG          (1ul << (SNP_GUEST_POLICY_VMPL_SHIFT))
#define SNP_GUEST_POLICY_MIGRATE_MA_FLAG    (1ul << (SNP_GUEST_POLICY_MIGRATE_MA_SHIFT))
#define SNP_GUEST_POLICY_DEBUG_FLAG         (1ul << (SNP_GUEST_POLICY_DEBUG_SHIFT))
#define SNP_GUEST_POLICY_SINGLE_SOCKET_FLAG (1ul << (SNP_GUEST_POLICY_SINGLE_SOCKET_SHIFT))
#define SNP_GUEST_POLICY_RESERVED_MASK      (0xFFFFFFFFFFFul << (SNP_GUEST_POLICY_RESERVED_SHIFT))

#define snp_policy_minor(policy)    ((policy & SNP_GUEST_POLICY_API_MINOR_MASK) >> SNP_GUEST_POLICY_API_MINOR_SHIFT)
#define snp_policy_major(policy)    ((policy & SNP_GUEST_POLICY_API_MAJOR_MASK) >> SNP_GUEST_POLICY_API_MAJOR_SHIFT)

/* We made this up (not in spec) */
#define SEV_GUEST_FLAGS_ACTIVE_BIT        (0)
#define SEV_GUEST_FLAGS_ES_BIT            (1)
#define SEV_GUEST_FLAGS_PENDING_BIT       (2)
#define SEV_GUEST_FLAGS_ES_POOL_ALLOC_BIT (3)

#define SEV_GUEST_FLAGS_ACTIVE_FLAG         (1ul << (SEV_GUEST_FLAGS_ACTIVE_BIT))
#define SEV_GUEST_FLAGS_ES_FLAG             (1ul << (SEV_GUEST_FLAGS_ES_BIT))
#define SEV_GUEST_FLAGS_PENDING_FLAG        (1ul << (SEV_GUEST_FLAGS_PENDING_BIT))
#define SEV_GUEST_FLAGS_ES_POOL_ALLOC_FLAG  (1ul << (SEV_GUEST_FLAGS_ES_POOL_ALLOC_BIT))

#define PACKET_HEADER_COMPRESSED_SHIFT  (0)
#define PACKET_HEADER_COMPRESSED_FLAG   (1ul << (PACKET_HEADER_COMPRESSED_SHIFT))

/* Minimum alignment of each guest in array */
#define GUEST_MIN_ALIGN         (16)

#define is_compressed(flags)    (((flags) & (PACKET_HEADER_COMPRESSED_FLAG)) > 0)

typedef enum sev_guest_type
{
    SEV_GUEST_TYPE_SEV = 0,
    SEV_GUEST_TYPE_SNP = 1,

    SEV_GUEST_TYPE_LIMIT,
} sev_guest_type_t;

/**
 * State    Description                     Allowed Guest Commands
 * UNINIT   Guest is uninitialized          LAUNCH_START, RECEIVE_START
 *
 * LUPDATE  Guest is currently being        LAUNCH_UPDATE_DATA, LAUNCH_UPDATE_VMSA,
 *          launched & plaintext data &     LAUNCH_MEASURE, ACTIVATE, DEACTIVATE,
 *          VMCB save areas are being       DECOMMISSION, GUEST_STATUS
 *          being imported
 *
 * LSECRET  Guest is currently being        LAUNCH_SECRET, LAUNCH_FINISH,
 *          launched & ciphertext           ACTIVATE, DEACTIVATE,
 *          are being imported              DECOMMISSION, GUEST_STATUS
 *
 * RUNNING  Guest is fully launched or      ACTIVATE, DEACTIVATE, DECOMMISSION,
 *          migrated in, and not being      SEND_START, GUEST_STATUS
 *          migrated out to another machine
 *
 * SUPDATE  Guest is currently              SEND_UPDATE_DATA, SEND_UPDATE_VMSA,
 *          being migrated out to           SEND_FINISH, ACTIVATE, DEACTIVATE,
 *          another machine                 DECOMMISSION, GUEST_STATUS
 *
 * RUPDATE  Guest is currently              RECEIVE_UPDATE_DATA, RECEIVE_UPDATE_VMSA,
 *          being migrated from             RECEIVE_FINISH, ACTIVATE, DEACTIVATE,
 *          another machine                 DECOMMISSION, GUEST_STATUS
 */
typedef enum sev_guest_state
{
    SEV_GUEST_STATE_INVALID = 0,
    SEV_GUEST_STATE_LUPDATE = 1,
    SEV_GUEST_STATE_LSECRET = 2,
    SEV_GUEST_STATE_RUNNING = 3,
    SEV_GUEST_STATE_SUPDATE = 4,
    SEV_GUEST_STATE_RUPDATE = 5,
    SEV_GUEST_STATE_SENT    = 6,

    SEV_GUEST_STATE_LIMIT,
} sev_guest_state_t;

/**
 * State            Description     Allowed Guest Commands
 * GSTATE_INIT      Initial state   SNP_LAUNCH_START, SNP_GUEST_REQUEST (VM_IMPORT)
 *                  of the guest    SNP_PAGE_RECLAIM, SNP_DECOMMISSION
 *
 * GSTATE_LAUNCH    Guest is being  SNP_GCTX_CREATE, SNP_LAUNCH_UPDATE, SNP_LAUNCH_FINISH
 *                  launched        SNP_ACTIVATE, SNP_DECOMMISSION, SNP_PAGE_RECLAIM
 *                                  SNP_PAGE_MOVE, SNP_PAGE_SWAP_OUT, SNP_PAGE_SWAP_IN,
 *                                  SNP_PAGE_UNSMASH
 *
 * GSTATE_RUNNING   Guest is        SNP_ACTIVATE, SNP_PAGE_RECLAIM, SNP_DECOMMISSION,
 *                  currently       SNP_PAGE_MOVE, SNP_PAGE_SWAP_OUT, SNP_PAGE_SWAP_IN,
 *                  running         SNP_PAGE_UNSMASH, SNP_GUEST_REQUEST
 */
typedef enum snp_guest_state
{
    SNP_GUEST_STATE_INIT    = 0,
    SNP_GUEST_STATE_LAUNCH  = 1,
    SNP_GUEST_STATE_RUNNING = 2,

    SNP_GUEST_STATE_LIMIT,
} snp_guest_state_t;

/**
 * Please manually arrange members for maximum packing, i.e. minimum padding.
 * The guests array has 1024 of these, so each added pad byte adds 1024 bytes.
 * If members have alignment requirements, add the attribute so it will
 * maintain alignment requirements.
 */
#pragma anon_unions

typedef struct sev_guest
{
    /*
     * Launch measurement digest context 'ld' PSP DRAM minimum alignment
     * for CCP usage is 16 bytes.
     */
    uint8_t                 umc_key_seed[CIPHER_AES_KEY_SIZE_BYTES]; /* VEK seed */
    uint8_t                 oek[32];        /* Offline Encryption Key */
    digest_sha_t            launch_digest;  /* For attestation. Set in LaunchMeasure */
    union {
    digest_sha_ctx_t        ld __attribute__((aligned (GUEST_MIN_ALIGN)));
    SW_SHA_CONTEXT          sw_sha_ctx;
    };
    sev_trusted_channel_t   channel __attribute__((aligned (GUEST_MIN_ALIGN)));
    uint64_t                oek_iv_count;   /* Counter/IV for encryption with OEK (SwapIO) */
    uint32_t                handle;
    uint32_t                policy;     /* sev */
    sev_guest_state_t       sev_state;
    uint32_t                asid;
    uint32_t                ccxs;       /* CCXs to be enabled with this guest's ASID. */
    uint32_t                guest_flags;
    sev_es_guest_t          es;

    /* SNP stuff */
    snp_guest_state_t       snp_state;
    sev_guest_type_t        type;
    uint64_t                policy_snp;
} sev_guest_t;

/**
 * Marks the guest as invalid by setting the handle to zero (possibly
 * by zeroing out the entire structure).
 */
void sev_guest_clear(sev_guest_t *guest);

/**
 * Transition the guest to the provided sev state.
 */
sev_status_t sev_guest_state_transition(sev_guest_t *guest, sev_mcmd_id_t cmd);

/**
 * Transition the guest to the provided snp state.
 */
sev_status_t snp_guest_state_transition(sev_guest_t *guest, sev_mcmd_id_t cmd);

/**
 * Activates the guest on a given ASID.
 */
sev_status_t sev_guest_activate(sev_guest_t *guest, uint32_t asid, uint32_t ccxs);

/**
 * Deactivates the guest.
 */
sev_status_t sev_guest_deactivate(sev_guest_t *guest, uint32_t inuse_ccxs);

/**
 * Completes Activation of the guest pending activation.
 */
sev_status_t sev_guest_finish_pending_activate(sev_guest_t *guest);

/**
 * Import unencrypted data into the guest.
 */
sev_status_t sev_guest_import_pt_data(sev_guest_t *guest, const uint8_t *src_data,
                                      size_t src_length, uint8_t *dst_data,
                                      size_t dst_length);

/**
 * Import encrypted data into the guest. Uses the TEK and TIK.
 */
sev_status_t sev_guest_import_ct_data(sev_guest_t *guest, const uint8_t *src_data,
                                      size_t src_length, uint8_t *dst_data,
                                      size_t dst_length);

/**
 * Export guest data to plaintext data. This is insecure!
 */
sev_status_t sev_guest_export_pt_data(sev_guest_t *guest, const uint8_t *src_data,
                                      size_t src_length, uint8_t *dst_data,
                                      size_t dst_length);

/**
 * Export guest data to ciphertext data. Uses the TEK and TIK.
 */
sev_status_t sev_guest_export_ct_data(sev_guest_t *guest, const uint8_t *src_data,
                                      size_t src_length, uint8_t *dst_data,
                                      size_t dst_length);

/**
 * Import unencrypted VMCB save state (VCPU) into the guest.
 */
sev_status_t sev_guest_import_pt_vcpu(sev_guest_t *guest, const uint8_t *src_vcpu,
                                      size_t src_length, uint8_t *dst_vcpu,
                                      size_t dst_length);

/**
 * Import encrypted VCPU into the guest. Uses the TEK and TIK.
 */
sev_status_t sev_guest_import_ct_vcpu(sev_guest_t *guest, const uint8_t *src_vcpu,
                                      size_t src_length, uint8_t *dst_vcpu,
                                      size_t dst_length);

/**
 * Export guest VCPU to plaintext VCPU. This is insecure!
 */
sev_status_t sev_guest_export_pt_vcpu(sev_guest_t *guest, const uint8_t *src_vcpu,
                                      size_t src_length, uint8_t *dst_vcpu,
                                      size_t dst_length);

/**
 * Export guest VCPU to ciphertext VCPU. Uses the TEK and TIK.
 */
sev_status_t sev_guest_export_ct_vcpu(sev_guest_t *guest, const uint8_t *src_vcpu,
                                      size_t src_length, uint8_t *dst_vcpu,
                                      size_t dst_length);

/**
 * Validate the guest policy.
 */
sev_status_t sev_guest_verify_policy(uint32_t policy, const hmac_sha256_t *mac,
                                     const sev_trusted_channel_t *channel);

/**
 * Calculate the launch measurement.
 */
sev_status_t sev_guest_measure(sev_guest_t *guest, sev_measurement_t *measurement);

/**
 * Returns a free guest handle.
 */
sev_status_t find_free_guest_handle(sev_guest_t *guests, size_t max_guests,
                                    uint32_t *handle);

/**
 * If sev is non-null, returns a pointer to the guest specified by the handle.
 * Otherwise, returns null.
 */
sev_guest_t *sev_get_guest(sev_t *sev, uint32_t handle);

/**
 * Test if a guest is free for allocation.
 */
static inline bool guest_is_free(sev_guest_t *guest)
{
    return guest && (guest->sev_state == SEV_GUEST_STATE_INVALID);
}

/**
 * Test if a guest has an ASID assigned due to Activation & Running.
 */
static inline bool guest_is_active(sev_guest_t *guest)
{
    return guest && (guest->guest_flags & SEV_GUEST_FLAGS_ACTIVE_FLAG);
}

/**
 * Test if a guest has an ASID allocated due to pending Activation.
 * The idea of pending is that, when you call Activate/ActivateEX, you do not
 *  want to be able to call VMRUN before calling LaunchFinish. Therefore,
 *  the Activate will assign an asid and put it in the UMC slot, but not
 *  clear the invalid_asid bit. That only gets done in LaunchFinish.
 * Also, in SEV, you would be able to call LaunchStart, Activate, then
 *  Deactivate without having to do a WBINVD/DF_FLUSH because the invalid_asid
 *  bit was never cleared and the asid would never go to dirty.
 */
static inline bool guest_is_pending(sev_guest_t *guest)
{
    return guest && (guest->guest_flags & SEV_GUEST_FLAGS_PENDING_FLAG);
}

/**
 * Test if a guest has no ASID assigned due to not Activated & not Pending.
 */
static inline bool guest_is_inactive(sev_guest_t *guest)
{
    return guest && !(guest->guest_flags & (SEV_GUEST_FLAGS_ACTIVE_FLAG |
                                            SEV_GUEST_FLAGS_PENDING_FLAG));
}

/**
 * Test if a guest has an ASID assigned due to pending or Running Activation.
 */
static inline bool guest_has_asid(sev_guest_t *guest)
{
    return guest && (guest->guest_flags & (SEV_GUEST_FLAGS_ACTIVE_FLAG |
                                           SEV_GUEST_FLAGS_PENDING_FLAG));
}

/**
 * Test if a guest handle is in the valid range.
 */
bool handle_is_valid(uint32_t handle);

#endif /* SEV_GUEST_H */
