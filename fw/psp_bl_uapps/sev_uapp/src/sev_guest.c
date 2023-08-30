// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "secure_ops.h"
#include "sev_cert.h"
#include "sev_globals.h"
#include "sev_guest.h"
#include "sev_hal.h"
#include "sev_hal_interface.h"
#include "sev_mcmd.h"
#include "umc.h"

#define SEV_GUEST_HANDLE_MIN    1
#define SEV_GUEST_HANDLE_MAX    ((SEV_GUEST_HANDLE_MIN) + (SEV_GUEST_COUNT_MAX) - 1)
#define SEV_MNONCE_LABEL        "sev-mnonce"

struct state_tbl_entry_sev
{
    sev_guest_state_t current;
    sev_guest_state_t next;
    sev_mcmd_id_t cmd;
};

struct state_tbl_entry_snp
{
    snp_guest_state_t current;
    snp_guest_state_t next;
    sev_mcmd_id_t cmd;
};

static const struct state_tbl_entry_sev state_tbl_sev[] = {
    /*
     * Guest Commands
     */

    /* DECOMMISSION transitions */
    { SEV_GUEST_STATE_LUPDATE, SEV_GUEST_STATE_INVALID, SEV_MCMD_ID_DECOMMISSION },
    { SEV_GUEST_STATE_LSECRET, SEV_GUEST_STATE_INVALID, SEV_MCMD_ID_DECOMMISSION },
    { SEV_GUEST_STATE_RUNNING, SEV_GUEST_STATE_INVALID, SEV_MCMD_ID_DECOMMISSION },
    { SEV_GUEST_STATE_SUPDATE, SEV_GUEST_STATE_INVALID, SEV_MCMD_ID_DECOMMISSION },
    { SEV_GUEST_STATE_RUPDATE, SEV_GUEST_STATE_INVALID, SEV_MCMD_ID_DECOMMISSION },
    { SEV_GUEST_STATE_SENT,    SEV_GUEST_STATE_INVALID, SEV_MCMD_ID_DECOMMISSION },

    /* LAUNCH_START transitions */
    { SEV_GUEST_STATE_INVALID, SEV_GUEST_STATE_LUPDATE, SEV_MCMD_ID_LAUNCH_START },

    /* LAUNCH_MEASURE transitions */
    { SEV_GUEST_STATE_LUPDATE, SEV_GUEST_STATE_LSECRET, SEV_MCMD_ID_LAUNCH_MEASURE },

    /* LAUNCH_FINISH transitions */
    { SEV_GUEST_STATE_LSECRET, SEV_GUEST_STATE_RUNNING, SEV_MCMD_ID_LAUNCH_FINISH },

    /* SEND_START transitions */
    { SEV_GUEST_STATE_RUNNING, SEV_GUEST_STATE_SUPDATE, SEV_MCMD_ID_SEND_START },

    /* SEND_FINISH transitions */
    { SEV_GUEST_STATE_SUPDATE, SEV_GUEST_STATE_SENT, SEV_MCMD_ID_SEND_FINISH },

    /* SEND_CANCEL transitions */
    { SEV_GUEST_STATE_SUPDATE, SEV_GUEST_STATE_RUNNING, SEV_MCMD_ID_SEND_CANCEL },

    /* RECEIVE_START transitions */
    { SEV_GUEST_STATE_INVALID, SEV_GUEST_STATE_RUPDATE, SEV_MCMD_ID_RECEIVE_START },

    /* RECEIVE_FINISH transitions */
    { SEV_GUEST_STATE_RUPDATE, SEV_GUEST_STATE_RUNNING, SEV_MCMD_ID_RECEIVE_FINISH },

    /* The last entry must be invalid */
    { SEV_GUEST_STATE_LIMIT, SEV_GUEST_STATE_LIMIT, SEV_MCMD_ID_LIMIT },
};

static const struct state_tbl_entry_snp state_tbl_snp[] = {
    /*
     * Guest Commands
     */

    /* DECOMMISSION transitions */
    { SNP_GUEST_STATE_INIT, SNP_GUEST_STATE_INIT, SNP_MCMD_ID_DECOMMISSION },
    { SNP_GUEST_STATE_LAUNCH, SNP_GUEST_STATE_INIT, SNP_MCMD_ID_DECOMMISSION },
    { SNP_GUEST_STATE_RUNNING, SNP_GUEST_STATE_INIT, SNP_MCMD_ID_DECOMMISSION },

    /* LAUNCH_START transitions */
    { SNP_GUEST_STATE_INIT, SNP_GUEST_STATE_LAUNCH, SNP_MCMD_ID_LAUNCH_START },

    /* LAUNCH_FINISH transitions */
    { SNP_GUEST_STATE_LAUNCH, SNP_GUEST_STATE_RUNNING, SNP_MCMD_ID_LAUNCH_FINISH },

    /* VM_IMPORT transitions */
    { SNP_GUEST_STATE_INIT, SNP_GUEST_STATE_RUNNING, SNP_MCMD_ID_GUEST_REQUEST },

    /* VM_ABSORB transitions */
    { SNP_GUEST_STATE_LAUNCH, SNP_GUEST_STATE_RUNNING, SNP_MCMD_ID_GUEST_REQUEST },

    /* The last entry must be invalid */
    { SNP_GUEST_STATE_LIMIT, SNP_GUEST_STATE_LIMIT, SEV_MCMD_ID_LIMIT },
};

/**
 * Transition the guest to the provided sev state.
 *
 * Returns SEV_STATUS_SUCCESS if the requested state transition is valid, or
 * SEV_STATUS_INVALID_GUEST_STATE otherwise.
 */
sev_status_t sev_guest_state_transition(sev_guest_t *guest, sev_mcmd_id_t cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t i = 0;

    if (!guest || cmd >= SEV_MCMD_ID_LIMIT)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check if this state transition is allowed for this command */
    while (state_tbl_sev[i].cmd != SEV_MCMD_ID_LIMIT)
    {
        if (state_tbl_sev[i].current == guest->sev_state &&
            state_tbl_sev[i].cmd == cmd)
        {
            /* Transition is allowed */
            guest->sev_state = state_tbl_sev[i].next;
            goto end;
        }
        i++;
    }

    /* Illegal state transition! */
    status = SEV_STATUS_INVALID_GUEST_STATE;

end:
    return status;
}

/**
 * Transition the guest to the provided snp state.
 *
 * Returns SEV_STATUS_SUCCESS if the requested state transition is valid, or
 * SEV_STATUS_INVALID_GUEST_STATE otherwise.
 */
sev_status_t snp_guest_state_transition(sev_guest_t *guest, sev_mcmd_id_t cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t i = 0;

    if (!guest || cmd >= SEV_MCMD_ID_LIMIT)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check if this state transition is allowed for this command */
    while (state_tbl_snp[i].cmd != SEV_MCMD_ID_LIMIT)
    {
        if (state_tbl_snp[i].current == guest->snp_state &&
            state_tbl_snp[i].cmd == cmd)
        {
            /* Transition is allowed */
            guest->snp_state = state_tbl_snp[i].next;
            goto end;
        }
        i++;
    }

    /* Illegal state transition! */
    status = SEV_STATUS_INVALID_GUEST_STATE;

end:
    return status;
}

static bool handle_is_in_range(uint32_t handle)
{
    return (handle >= SEV_GUEST_HANDLE_MIN) && (handle <= SEV_GUEST_HANDLE_MAX);
}

bool handle_is_valid(uint32_t handle)
{
    return  handle_is_in_range(handle) && !guest_is_free(sev_get_guest(&gSev, handle));
}

static inline bool index_is_in_range(size_t index)
{
    return index < SEV_GUEST_COUNT_MAX;
}

/**
 * If handle is in the proper range, convert it to the index of the
 * corresponding guest in the array of guests.
 */
static inline sev_status_t handle_to_index(uint32_t handle, size_t *index)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!handle_is_in_range(handle) || !index)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *index = handle - SEV_GUEST_HANDLE_MIN;

end:
    return status;
}

/**
 * Takes an index returned by handle_to_index() and returns the guest handle
 * for the specified guest. If index is invalid, returns the 0 handle.
 */
static inline sev_status_t index_to_handle(size_t index, uint32_t *handle)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!index_is_in_range(index) || !handle)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *handle = index + SEV_GUEST_HANDLE_MIN;

end:
    return status;
}

sev_guest_t *sev_get_guest(sev_t *sev, uint32_t handle)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t i = 0;
    sev_guest_t *guest = NULL;

    if (!sev || !handle_is_in_range(handle))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = handle_to_index(handle, &i);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    guest = &sev->sev.guests[i];

end:
    return guest;
}

sev_status_t find_free_guest_handle(sev_guest_t *guests, size_t max_guests,
                                    uint32_t *handle)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    size_t i = 0;

    if (!guests)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    for (i = 0; i < max_guests; i++)
    {
        if (guest_is_free(&guests[i]))
        {
            status = index_to_handle(i, handle);
            goto end;
        }
    }

    /* No free handles! */
    status = SEV_STATUS_RESOURCE_LIMIT;

end:
    return status;
}

void sev_guest_clear(sev_guest_t *guest)
{
    if (guest)
        secure_memzero(guest, sizeof(*guest));
}

sev_status_t sev_guest_verify_policy(uint32_t policy, const hmac_sha256_t *mac,
                                     const sev_trusted_channel_t *channel)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t major = 0;
    uint32_t minor = 0;

    if (!mac || !channel)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the policy MAC */
    status = hmac_sha256_verify_msg((uint8_t *)&policy, sizeof(policy),
                                    channel->tik, sizeof(channel->tik), mac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Check that the API version is supported */
    major = sev_policy_major(policy);
    minor = sev_policy_minor(policy);

    if (!api_version_supported(major, minor))
    {
        status = SEV_STATUS_POLICY_FAILURE;
        goto end;
    }

    /* Check that the reserved bits are zero */
    if (policy & SEV_GUEST_POLICY_RESERVED_MASK)
        status = SEV_STATUS_POLICY_FAILURE;

end:
    return status;
}

sev_status_t sev_guest_activate(sev_guest_t *guest, uint32_t asid, uint32_t ccxs)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool asid_valid = false;

    if (!guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check that the ASID is in the proper range */
    status = sev_es_validate_asid(guest, asid);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /*
     * Check if the x86 needs to issue the DF_FLUSH command before activating this ASID.
     * Since we dont actually mark the ASID valid until/unless in running state,
     * we look at 'dirty' state info for the ASID's CCXs to be enabled.
     */
    asid_valid = (gpDram->perm.asid_dirty[asid-1] & ccxs) ? false : true;
    if (!asid_valid)
    {
        status = SEV_STATUS_DF_FLUSH_REQUIRED;
        goto end;
    }

    /* Install the guest key into each UMC on every die, once only. */
    if (!guest_has_asid(guest))
    {
        /* Key install not done yet */
        status = set_umc_key(asid, guest->umc_key_seed, CIPHER_AES_KEY_SIZE_BYTES);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Key install not done yet */
        status = set_cnli_key(asid, guest->umc_key_seed, CIPHER_AES_KEY_SIZE_BYTES);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        guest->asid = asid;    /* Set here to prevent multiple guest key installs. */
    }

    guest->ccxs |= ccxs;    /* Never remove any CCXs. */

    /* If guest already Running, enable the CCXs if any. If not, remain Pending. */
    if (((guest->type == SEV_GUEST_TYPE_SEV) && (guest->sev_state == SEV_GUEST_STATE_RUNNING ||
                                                 guest->sev_state == SEV_GUEST_STATE_SUPDATE) && guest->ccxs) ||
        ((guest->type == SEV_GUEST_TYPE_SNP) && (guest->snp_state == SNP_GUEST_STATE_RUNNING) && guest->ccxs))
    {
        /* Mark ASID valid for specified CCXs. Handles all dies. */
        status = mark_asid_valid(guest->asid, guest->ccxs);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        guest->guest_flags |= SEV_GUEST_FLAGS_ACTIVE_FLAG;
        guest->guest_flags &= ~SEV_GUEST_FLAGS_PENDING_FLAG;
    }
    else
        guest->guest_flags |= SEV_GUEST_FLAGS_PENDING_FLAG;

end:
    return status;
}

sev_status_t sev_guest_finish_pending_activate(sev_guest_t *guest)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (guest->guest_flags & SEV_GUEST_FLAGS_PENDING_FLAG)
    {
        /* Activate was pending. Mark ASID valid for specified CCXs */
        status = mark_asid_valid(guest->asid, guest->ccxs);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        guest->guest_flags &= ~SEV_GUEST_FLAGS_PENDING_FLAG;
        guest->guest_flags |= SEV_GUEST_FLAGS_ACTIVE_FLAG;
    }

end:
    return status;
}

sev_status_t sev_guest_deactivate(sev_guest_t *guest, uint32_t inuse_ccxs)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!guest)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* We do not clear umc key here anymore. */

    if (inuse_ccxs)
    {
        /* Mark this ASID invalid on all die */
        /* only for the CCXs in-use for this guest. */
        status = mark_asid_invalid(guest->asid, inuse_ccxs);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Clear WBINVD_DONE bits on all dies */
        /* only on the cores of each CCX that was in use for the guest. */
        status = clear_wbinvd_done(inuse_ccxs);
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    guest->asid = 0;
    guest->ccxs = 0;
    guest->guest_flags &= ~(SEV_GUEST_FLAGS_ACTIVE_FLAG |
                            SEV_GUEST_FLAGS_PENDING_FLAG);

end:
    return status;
}

sev_status_t sev_guest_measure(sev_guest_t *guest, sev_measurement_t *measurement)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_measurement_t m;
    digest_sha_t *launch_digest = NULL;
    hmac_sha256_ctx_t hmac_ctx;
    uint8_t meas_ctx = SEV_CHANNEL_CTX_MEASURE;
    uint8_t api_major = SEV_API_MAJOR;
    uint8_t api_minor = SEV_API_MINOR;
    uint8_t build_id = SEV_BUILD_ID;

    if (!guest || !measurement)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    launch_digest = sha_ctx_to_digest(&guest->ld);
    memset(&m, 0, sizeof(m));
    memset(&hmac_ctx, 0, sizeof(hmac_ctx));

    /* Derive a random nonce */
    status = sev_hal_trng(m.mnonce, sizeof(m.mnonce));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Calculate the HMAC of the measurement data */
    status = hmac_sha256_init(&hmac_ctx, guest->channel.tik, sizeof(guest->channel.tik));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, &meas_ctx, sizeof(meas_ctx));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, &api_major, sizeof(api_major));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, &api_minor, sizeof(api_minor));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, &build_id, sizeof(build_id));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, &guest->policy, sizeof(guest->policy));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, launch_digest->digest, DIGEST_SHA256_SIZE_BYTES /*sizeof(launch_digest->digest)*/);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&hmac_ctx, m.mnonce, sizeof(m.mnonce));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_final(&hmac_ctx, &m.measurement);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the result to the output */
    memcpy(measurement, &m, sizeof(*measurement));

end:
    return status;
}
