// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "apicid.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "nist_kdf.h"
#include "secure_ops.h"
#include "sev_globals.h"
#include "sev_guest.h"
#include "sev_hal.h"
#include "sev_plat.h"
#include "sev_scmd.h"

#define CEK_LABEL    "sev-chip-endorsement-key"
#define VCEK_LABEL   "sev-versioned-chip-endorsement-key"
#define VLEK_LABEL   "sev-versioned-loaded-attestation-key"

struct state_tbl_entry_sev {
    sev_state_t   current;
    sev_state_t   next;
    sev_mcmd_id_t cmd;
};

struct state_tbl_entry_snp {
    snp_state_t   current;
    snp_state_t   next;
    sev_mcmd_id_t cmd;
};

static const struct state_tbl_entry_sev state_tbl_sev[] = {
    /*
     * Platform Commands
     */

    /* SEV_INIT transitions */
    { SEV_STATE_UNINIT, SEV_STATE_INIT, SEV_MCMD_ID_INIT },

    /* SEV_SHUTDOWN transitions */
    { SEV_STATE_UNINIT, SEV_STATE_UNINIT, SEV_MCMD_ID_SHUTDOWN },
    { SEV_STATE_INIT, SEV_STATE_UNINIT, SEV_MCMD_ID_SHUTDOWN },
    { SEV_STATE_WORKING, SEV_STATE_UNINIT, SEV_MCMD_ID_SHUTDOWN },

    /* SEV_PLATFORM_RESET transitions */
    { SEV_STATE_UNINIT, SEV_STATE_UNINIT, SEV_MCMD_ID_PLATFORM_RESET },

    /* SEV_DECOMMISSION transitions */
    { SEV_STATE_WORKING, SEV_STATE_INIT, SEV_MCMD_ID_DECOMMISSION },

    /* SEV_LAUNCH_START transitions */
    { SEV_STATE_INIT, SEV_STATE_WORKING, SEV_MCMD_ID_LAUNCH_START },
    { SEV_STATE_WORKING, SEV_STATE_WORKING, SEV_MCMD_ID_LAUNCH_START },

    /* SEV_RECEIVE_START transitions */
    { SEV_STATE_INIT, SEV_STATE_WORKING, SEV_MCMD_ID_RECEIVE_START },
    { SEV_STATE_WORKING, SEV_STATE_WORKING, SEV_MCMD_ID_RECEIVE_START },

    /* The last entry must be invalid */
    { SEV_STATE_LIMIT, SEV_STATE_LIMIT, SEV_MCMD_ID_LIMIT },
};

static const struct state_tbl_entry_snp state_tbl_snp[] = {
    /*
     * Platform Commands
     */

    /* SNP_INIT transitions */
    { SNP_STATE_UNINIT, SNP_STATE_INIT, SNP_MCMD_ID_INIT },

    /* SNP_SHUTDOWN transitions */
    { SNP_STATE_INIT, SNP_STATE_UNINIT, SNP_MCMD_ID_SHUTDOWN },

    /* The last entry must be invalid */
    { SNP_STATE_LIMIT, SNP_STATE_LIMIT, SEV_MCMD_ID_LIMIT },
};

/**
 * PDH management functions
 */
sev_status_t sev_pdh_generate(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_keypair_t temp_keypair;
    sev_cert_t temp_cert;
    sev_cert_pubkey_t pubkey;

    if (!identity || identity->persistent.pek.usage == SEV_CERT_USAGE_INVALID)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp_keypair, 0, sizeof(temp_keypair));
    memset(&temp_cert, 0, sizeof(temp_cert));
    memset(&pubkey, 0, sizeof(pubkey));

    temp_keypair.algo = SEV_CERT_ALGO_ECDH_SHA256;
    temp_keypair.usage = SEV_CERT_USAGE_PDH;

    /* Generate the PDH from random bytes */
    status = ecdh_keypair_generate(&temp_keypair.keypair.ecdsa);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the public key */
    status = sev_cert_keypair_get_pubkey(&temp_keypair, &pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Create the PDH cert and sign with the PEK private key */
    status = sev_cert_create(&temp_cert, &pubkey, &identity->persistent.pek);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* All steps succeeded, so store the PDH and its cert */
    memcpy(&identity->persistent.pdh, &temp_keypair, sizeof(temp_keypair));
    memcpy(&identity->persistent.pdh_cert, &temp_cert, sizeof(temp_cert));

end:
    return status;
}

sev_status_t sev_pdh_delete(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!identity)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_cert_init(&identity->persistent.pdh_cert);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    secure_memzero(&identity->persistent.pdh, sizeof(identity->persistent.pdh));

end:
    return status;
}

/**
 * PEK management functions
 */
sev_status_t sev_pek_generate(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_keypair_t temp_keypair;
    sev_cert_t temp_cert;
    sev_cert_pubkey_t pubkey;
    sev_cert_keypair_t *signing_key = NULL;

    if (!identity || identity->cek.usage == SEV_CERT_USAGE_INVALID ||
        identity->persistent.oca.self_owned.usage == SEV_CERT_USAGE_INVALID ||
        identity->persistent.oca.ext_owned.usage == SEV_CERT_USAGE_INVALID)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp_keypair, 0, sizeof(temp_keypair));
    memset(&temp_cert, 0, sizeof(temp_cert));
    memset(&pubkey, 0, sizeof(pubkey));

    temp_keypair.algo = SEV_CERT_ALGO_ECDSA_SHA256;
    temp_keypair.usage = SEV_CERT_USAGE_PEK;

    /* Generate the PEK from random bytes */
    status = ecdsa_keypair_generate(&temp_keypair.keypair.ecdsa);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_keypair_get_pubkey(&temp_keypair, &pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Create the PEK certificate and sign with the OCA private key */
    signing_key = &identity->persistent.oca.self_owned;
    status = sev_cert_create(&temp_cert, &pubkey, signing_key);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Sign the PEK certificate with the CEK private key as well */
    signing_key = &identity->cek;
    status = sev_cert_sign(&temp_cert, signing_key);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* All steps succeeded, so store the PEK and its certificate */
    memcpy(&identity->persistent.pek, &temp_keypair, sizeof(temp_keypair));
    memcpy(&identity->persistent.pek_cert, &temp_cert, sizeof(temp_cert));

end:
    return status;
}

sev_status_t sev_pek_delete(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!identity)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_cert_init(&identity->persistent.pek_cert);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    secure_memzero(&identity->persistent.pek, sizeof(identity->persistent.pek));

end:
    return status;
}

/**
 * CEK management functions
 */
sev_status_t sev_cek_derive(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t cuk;
    digest_sha_t cek_seed;
    size_t cuk_size = sizeof(cuk.s);
    size_t cek_seed_size = DIGEST_SHA256_SIZE_BYTES;
    uint8_t rdata[SEV_ECC_CURVE_SIZE_BYTES + ECC_KEYGEN_EXTRA_BYTES] = {0};
    sev_cert_keypair_t temp_keypair;

    if (!identity)
    {
        status = ERR_INVALID_PARAMS;
        goto exit;
    }

    memset(&cuk, 0, sizeof(cuk));
    memset(&cek_seed, 0, sizeof(cek_seed));
    memset(&temp_keypair, 0, sizeof(temp_keypair));

    temp_keypair.algo = SEV_CERT_ALGO_ECDSA_SHA256;
    temp_keypair.usage = SEV_CERT_USAGE_CEK;

#if 1
    /* Get the chip-unique ECC key */
    status = sev_hal_get_chip_unique_key(cuk.s, &cuk_size);
    if (status != SEV_STATUS_SUCCESS)
        goto exit;

    /* Calculate the SHA256 hash of the CUK */
    status = digest_sha(cuk.s, cuk_size, &cek_seed, &cek_seed_size, SHA_TYPE_256);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_clear_cuk;
#else
    /* This is not the correct value because the LSB size changed on Genoa,
        so the hash of the whole LSB returns the wrong value here */
    memcpy(&cek_seed.digest, gPersistent.socket_info[gCurrentDieID].ecc_seed_hash, cek_seed_size);
#endif

    /* Derive a 384-bit key from the chip-unique seed */
    status = kdf_derive(rdata, sizeof(rdata), cek_seed.digest, cek_seed_size,
                        CEK_LABEL, sizeof(CEK_LABEL)-1, NULL, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto exit_clear_cuk;

    /* Derive the CEK */
    status = ecc_keypair_from_extra_bits(&temp_keypair.keypair.ecdsa,
                                         ECC_CURVE_NAME_SECP384R1, rdata,
                                         sizeof(rdata));
    if (status != SEV_STATUS_SUCCESS)
        goto exit_clear_cuk;

    /* Copy the result */
    memcpy(&identity->cek, &temp_keypair, sizeof(temp_keypair));

exit_clear_cuk:
    /* Don't leave the ECC key on the stack */
    secure_memzero(&temp_keypair, sizeof(temp_keypair));
    secure_memzero(rdata, sizeof(rdata));
    secure_memzero(&cek_seed, sizeof(cek_seed));
    secure_memzero(&cuk, sizeof(cuk));

exit:
    return status;
}

sev_status_t sev_cek_delete(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!identity)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    secure_memzero(&identity->cek, sizeof(identity->cek));

end:
    return status;
}

/**
 * OCA management functions
 */
sev_status_t sev_oca_generate(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_cert_keypair_t temp_keypair;
    sev_cert_t temp_cert;
    sev_cert_pubkey_t pubkey;

    if (!identity)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp_keypair, 0, sizeof(temp_keypair));
    memset(&temp_cert, 0, sizeof(temp_cert));
    memset(&pubkey, 0, sizeof(pubkey));

    temp_keypair.algo = SEV_CERT_ALGO_ECDSA_SHA256;
    temp_keypair.usage = SEV_CERT_USAGE_OCA;

    /* Generate the OCA key pair from random bytes */
    status = ecdsa_keypair_generate(&temp_keypair.keypair.ecdsa);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = sev_cert_keypair_get_pubkey(&temp_keypair, &pubkey);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (!ecc_pubkey_is_valid(&pubkey.key.ecdsa))
        goto end;

    /* Create a self-signed OCA certificate */
    status = sev_cert_create(&temp_cert, &pubkey, &temp_keypair);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* All steps succeeded, so store the OCA key and its certificate */
    memcpy(&identity->persistent.oca.self_owned, &temp_keypair, sizeof(temp_keypair));
    memcpy(&identity->persistent.oca_cert, &temp_cert, sizeof(temp_cert));
    identity->persistent.is_ext_owned = 0;

end:
    return status;
}

sev_status_t sev_oca_delete(sev_identity_t *identity)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!identity)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_cert_init(&identity->persistent.oca_cert);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    secure_memzero(&identity->persistent.oca, sizeof(identity->persistent.oca));
    identity->persistent.is_ext_owned = 0;

end:
    return status;
}

/**
 * Params:
 *  [In]id_len:         Input length requested from x86
 *  [Out]out_buf:       Local memory to write buffer before it's copied back to x86
 *  [Out]bytes_wrote:   Bytes wrote by this function.
 *                      Note: If user requested 2P (128B) of data but only
 *                            1P (64B) exists, returns 64B
 */
sev_status_t sev_get_id(uint32_t id_len, uint8_t *out_buf, uint32_t *bytes_wrote)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t socket = 0;
    ecc_point_t G = ecc_get_curve(ECC_CURVE_NAME_SECP256K1)->G;

    if (!out_buf || !bytes_wrote)
    {
        return ERR_INVALID_PARAMS;
    }

    *bytes_wrote = 0;

    for (socket = 0; socket < SEV_MAX_NUM_SOCKETS; ++socket)
    {
        get_id_t id = { {0}, {0} };
        ecc_scalar_t cuk;
        size_t cuk_size = 32;
        ecc_keypair_t ecc_keypair;
        memset(&cuk, 0, sizeof(cuk));

        /* Get the CUK for the master, or the slave */
        if (socket == SEV_GLOBAL_MASTER_DIE_ID)    /* Master */
        {
            /* Get the chip-unique ECC key */
            status = sev_hal_get_chip_unique_key(cuk.s, &cuk_size);
            if (status != SEV_STATUS_SUCCESS)
                break;
        }
        else                                /* Slave */
        {
            sev_scmd_t cmd;
            if (id_len != SEV_MAX_NUM_SOCKETS*sizeof(get_id_t) || gTotalDieNum != MP0_DIE_CNT_2P)
                continue;

            memset(gpDram->p1_info.p1cuk, 0, sizeof(gpDram->p1_info.p1cuk));
            sev_hal_clean_dcache((uint32_t)gpDram->p1_info.p1cuk, sizeof(gpDram->p1_info.p1cuk));

            /* Get the CUK from P1 if desired, and there is one */
            memset(&cmd, 0, sizeof(cmd));
            cmd.id = SEV_SCMD_ID_GET_CUK;
            status = sev_hal_master_to_slave(1, &cmd, sizeof(cmd));
            if (status != SEV_STATUS_SUCCESS)
                break;
            sev_hal_invalidate_dcache((uint32_t)gpDram->p1_info.p1cuk, sizeof(gpDram->p1_info.p1cuk));
            memcpy(cuk.s, gpDram->p1_info.p1cuk, cuk_size);
            secure_memzero(gpDram->p1_info.p1cuk, sizeof(gpDram->p1_info.p1cuk));
        }

        memset(&ecc_keypair, 0, sizeof(ecc_keypair));

        /*
         * Calculate the public key from the private component (the CUK):
         * Q = d*G
         */
        reverse_bytes(cuk.s, cuk_size);
        status = ecc_point_scale(&ecc_keypair.Q, &G, &cuk, ECC_CURVE_NAME_SECP256K1);

        /* Don't leave the ECC key on the stack */
        secure_memzero(&cuk, sizeof(cuk));

        if (status != SEV_STATUS_SUCCESS)
            break;

        memcpy(id.x, &ecc_keypair.Q.x, sizeof(id.x));
        memcpy(id.y, &ecc_keypair.Q.y, sizeof(id.y));
        reverse_bytes((uint8_t *)&id.x, sizeof(id.x));
        reverse_bytes((uint8_t *)&id.y, sizeof(id.y));

        /* Copy id to the buffer */
        memcpy(out_buf + (socket*sizeof(get_id_t)), &id, sizeof(get_id_t));
        *bytes_wrote += sizeof(get_id_t);
    }

    return status;
}

/* This prepends 8 zero bytes to the given digest and generates a hash for that.
 * VCEK Algorithm specification describes it as (64'h0||d).
 */
static sev_status_t compute_next_stick_base(uint8_t *hashstick_addr, uint8_t *previous_digest)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t hashstick_intermediate_input[HASH_STICK_INTERMEDIATE_NULL_BYTES_LEN + PSP_HASHSTICK_LENGTH] = {0};
    digest_sha_t digest = {0};
    size_t digest_len = sizeof(digest);

    memcpy(&hashstick_intermediate_input[HASH_STICK_INTERMEDIATE_NULL_BYTES_LEN],
           previous_digest, PSP_HASHSTICK_LENGTH);

    status = digest_sha((uint8_t *)&hashstick_intermediate_input[0],
                        PSP_HASHSTICK_LENGTH + HASH_STICK_INTERMEDIATE_NULL_BYTES_LEN,
                        &digest, &digest_len, SHA_TYPE_384);
    if (status != SEV_STATUS_SUCCESS)
        goto EXIT;
    memcpy(hashstick_addr, &digest.digest[0], PSP_HASHSTICK_LENGTH);

EXIT:
    memset(&hashstick_intermediate_input, 0, sizeof(hashstick_intermediate_input));
    return status;
}

/* Recompute the hash stick by performing hash operation
 * repeatedly 255 - aVers times. Zero extend
 * and compute the hash stick base for the next component
 * if applicable (applies to components higher than microcode).
 * Hash one more time to finalize the stick for the current component.
 * See Stick_Create() in Versioned CEK Algorithm Specification.
 */
static sev_status_t recompute_hash_stick(uint8_t *hashstick_addr, uint8_t version, int index)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t digest;
    size_t digest_len = (size_t)PSP_HASHSTICK_LENGTH;

    memcpy(&digest.digest[0], hashstick_addr, sizeof(digest));

    for (uint32_t i = 255; i > version; i--)
    {
        status = digest_sha(&digest.digest[0], PSP_HASHSTICK_LENGTH,
                            &digest, &digest_len, SHA_TYPE_384);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;
    }

    if (index < TCB_HASHSTICK_INDEX_CPU_MICROCODE)
    {
        status = compute_next_stick_base(hashstick_addr + PSP_HASHSTICK_LENGTH, &digest.digest[0]);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;
    }

    status = digest_sha(&digest.digest[0], PSP_HASHSTICK_LENGTH, &digest, &digest_len, SHA_TYPE_384);
    if (status != SEV_STATUS_SUCCESS)
        goto EXIT;

    memcpy(hashstick_addr, &digest.digest[0], PSP_HASHSTICK_LENGTH);

EXIT:
    memset(&digest, 0x0, sizeof(digest));
    return status;
}

/* Hash repeatedly aVersFrom - aVersTo - 1 times.
 * That is the base for the component. Hash one more time
 * to finalize the hash for the current component. See Stick_Extend() in
 * Versioned CEK Algorithm Specificaton.
 */
static sev_status_t hashstick_extend(uint8_t *hash_stick, snp_tcb_version_t *tcb_version,
                                     snp_tcb_version_t *old_tcb_version, uint32_t index)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t digest;
    size_t digest_len = sizeof(digest);
    uint32_t old_ver = ((uint8_t *)old_tcb_version)[index];
    uint32_t new_ver = ((uint8_t *)tcb_version)[index];

    memcpy(&digest.digest[0], (uint8_t *)hash_stick, sizeof(digest));

    for (uint32_t i = 0; i < (new_ver - old_ver - 1); i++)
    {
        status = digest_sha(&digest.digest[0], PSP_HASHSTICK_LENGTH,
                            &digest, &digest_len, SHA_TYPE_384);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;
    }

    status = compute_next_stick_base(hash_stick + PSP_HASHSTICK_LENGTH, &digest.digest[0]);
    if (status != SEV_STATUS_SUCCESS)
        goto EXIT;

    status = digest_sha(&digest.digest[0], PSP_HASHSTICK_LENGTH,
                        &digest, &digest_len, SHA_TYPE_384);
    if (status != SEV_STATUS_SUCCESS)
        goto EXIT;

    memcpy(hash_stick, &digest.digest[0], PSP_HASHSTICK_LENGTH);
EXIT:
    return status;
}

/* If older TCB is used, this function is used to re-derive the
 * hash sticks from the first applicable component.
 */
sev_status_t vceck_rederive(HASH_STICK *hash_stick, uint32_t start_index, snp_tcb_version_t *old_tcb_version, snp_tcb_version_t *tcb_version)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    /* Retrieve the seed value (current digest) from the PSP Bootrom.
     * The PSP Bootrom sets the original seed and the PSP BL calculates the
     * other sticks up until microcode version, which is lets SEV calculate.
     * When an older TCB is used, recompute from the component that has changed.
     */
    sev_hal_get_seed_at_idx((uint8_t *)(&(hash_stick[start_index].HashStick)),
                            sizeof(hash_stick[start_index].HashStick), start_index);

    /* start_index is the first (highest order), lower versioned component
     * that is different from the system default version.
     * If it is a component other than microcode component, then extend
     * the hash stick for the highest ordered component that has changed
     * and then recompute the hash sticks for the lower ordered components
     * based on that.
     */
    if (start_index < TCB_HASHSTICK_INDEX_CPU_MICROCODE) {
        status = hashstick_extend((uint8_t *)&(hash_stick[start_index]),
                                  tcb_version, old_tcb_version, start_index);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;
        for (int i = start_index + 1; i <= TCB_HASHSTICK_INDEX_CPU_MICROCODE; i++)
        {
            status = recompute_hash_stick((uint8_t *)&(hash_stick[i]),
                                          ((uint8_t *)old_tcb_version)[i], i);
            if (status != SEV_STATUS_SUCCESS)
                break;
        }
    } else {
    /* If it is microcode component, recompute
     * the hashstick for that, by taking the corresponding seed
     * and hashing it 255 - aVers times. aVers represents the version we want
     * to use. Since this is the last component, no extending required.
     */
        status = recompute_hash_stick((uint8_t *)&(hash_stick[TCB_HASHSTICK_INDEX_CPU_MICROCODE]),
                                    old_tcb_version->f.microcode,
                                    TCB_HASHSTICK_INDEX_CPU_MICROCODE);
    }

EXIT:
    return status;
}

sev_status_t vcek_hash_derive(uint8_t *vcek, uint32_t length,
                              snp_tcb_version_t *old_tcb_version)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    digest_sha_t digest;
    uint32_t microcode_patch_level = 0;
    uint32_t microcode_version = 0;
    HASH_STICK hash_sticks[8] = {0};

    if (!vcek || (length < MICROCODE_SEED_LENGTH))
    {
        status = ERR_INVALID_PARAMS;
        goto EXIT;
    }
    /*
     * This function should be called when an older TCBVersion is requested, for
     * example: SNP_MSG_KEY_REQ. That means we take the current hash stick table
     * calculated by the PSP Bootrom and PSP Bootloader, find out where the first
     * diffence is, and re-calculate the table from there. Basically, do what we did
     * in the PSP Bootloader (but for the current version), but again (for an older
     * version)
     */
    if (old_tcb_version)
    {
        snp_tcb_version_t current_tcb;
        tcb_hashstick_index_t starting_hash_stick_index = TCB_HASHSTICK_INDEX_CPU_MICROCODE;

        /* Calculate the current tcb version using the latest uCode SVN */
        get_committed_tcb(&current_tcb);

        /* Re-calculate the hash sticks from the first difference */
        if (old_tcb_version->f.boot_loader < current_tcb.f.boot_loader)
            starting_hash_stick_index = TCB_HASHSTICK_INDEX_PSP_BL;
        else if (old_tcb_version->f.tee < current_tcb.f.tee)
            starting_hash_stick_index = TCB_HASHSTICK_INDEX_PSP_TEE;
        else if (old_tcb_version->f.snp < current_tcb.f.snp)
            starting_hash_stick_index = TCB_HASHSTICK_INDEX_SEV_UAPP;
        else
            starting_hash_stick_index = TCB_HASHSTICK_INDEX_CPU_MICROCODE;

        /* Re-calculate the hash sticks */
        status = vceck_rederive(&hash_sticks[0], starting_hash_stick_index, old_tcb_version, &current_tcb);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;

        memcpy(&digest.digest[0], &hash_sticks[TCB_HASHSTICK_INDEX_CPU_MICROCODE], sizeof(digest));
    } else {
        /* Get the latest microcode patch level, that x86 can change on the fly */
        microcode_patch_level = retrieve_microcode_patch_level();

        /* Retrieve current TCB version from Bootloader (already done in INIT) */
        /* Update Microcode version in the TCB (already done in INIT) */
        microcode_version = microcode_patch_level & 0xff;
        status = sev_hal_get_seed_at_idx(&digest.digest[0], sizeof(digest), TCB_HASHSTICK_MICROCODE_INDEX);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;

        /* Calculate the hash stick for the microcode version */
        status = recompute_hash_stick((uint8_t *)&digest.digest[0],
                                      microcode_version,
                                      TCB_HASHSTICK_INDEX_CPU_MICROCODE);
        if (status != SEV_STATUS_SUCCESS)
            goto EXIT;
    }

    memcpy(vcek, &digest.digest[0], MICROCODE_SEED_LENGTH);

EXIT:
    return status;
}

sev_status_t key_from_hash(ecc_keypair_t *key, const uint8_t *hash, keytype type)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    const size_t cek_seed_size = DIGEST_SHA384_SIZE_BYTES;
    uint8_t rdata[SEV_ECC_CURVE_SIZE_BYTES + ECC_KEYGEN_EXTRA_BYTES] = {0};
    const uint8_t *label = NULL;
    size_t label_len = 0;

    if (key == NULL || hash == NULL)
        return ERR_INVALID_PARAMS;

    switch (type) {
    case KEYTYPE_VCEK:
        label = VCEK_LABEL;
        label_len = sizeof(VCEK_LABEL) -1;
        break;
    case KEYTYPE_VLEK:
        label = VLEK_LABEL;
        label_len = sizeof(VLEK_LABEL) -1;
        break;
    default:
        return ERR_INVALID_PARAMS;
    }

    /* Derive a 384-bit key from the chip-unique seed */
    status = kdf_derive(rdata, sizeof(rdata), hash, cek_seed_size,
                        label, label_len, NULL, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the key */
    status = ecc_keypair_from_extra_bits(key, ECC_CURVE_NAME_SECP384R1,
                                         rdata, sizeof(rdata));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    secure_memzero(rdata, sizeof(rdata));
    return status;
}

/**
 * VCEK management functions
 */
sev_status_t vcek_derive(snp_identity_t *identity)
{
    return key_from_hash(&identity->vcek.keypair.ecdsa, identity->vcek_hash, KEYTYPE_VCEK);
}

/**
 * Since the uCode version can change underneath us, we need to pull the latest
 * uCode version every time we want to use current_tcb. This means we cannot
 * store current_tcb in gPersistent because someone might assume the uCode
 * version is up to date and use it.
 */
sev_status_t get_running_tcb(snp_tcb_version_t *tcb, SEV_FW_IMAGE_HEADER *hdr)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t microcode_patch_level = 0;

    if (hdr == NULL)
        hdr = (SEV_FW_IMAGE_HEADER *)&Image$$SEV_UAPP_CODE$$Base;

    /* BL & SEV FW TCB values. Set during first INIT and DLFW/DLFW_EX&COMMIT */
    tcb->val = gpDram->perm.committed_tcb.val;

    /* Now update the SEV FW component... could be different due to DLFW_EX w/o COMMIT */
    tcb->f.snp = hdr->SecPatchLevel & 0xff;

    /* Finally, update Microcode version in the TCB */
    microcode_patch_level = retrieve_microcode_patch_level();
    tcb->f.microcode = microcode_patch_level & 0xff;

    return status;
}

/**
 * Get the TCB at the time of the last COMMIT
 */
void get_committed_tcb(snp_tcb_version_t *tcb)
{
    /* BL & SEV FW TCB values. Set during first INIT and DLFW/DLFW_EX&COMMIT */
    tcb->val = gpDram->perm.committed_tcb.val;
}

/**
 * Get either the TCB set by an SNP_CONFIG command or the current TCB
 */
void get_reported_tcb(snp_tcb_version_t *tcb)
{
    if (gPersistent.config_tcb.val != 0)
        *tcb = gPersistent.config_tcb;
    else
        get_committed_tcb(tcb);
}

/**
 * Transition the platform to the provided sev state.
 *
 * Only returns if the requested state transition is valid.
 */
sev_status_t sev_state_transition(sev_t *sev, sev_mcmd_id_t cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t i = 0;

    if (!sev || cmd >= SEV_MCMD_ID_LIMIT)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check if this state transition is allowed for this command */
    while (state_tbl_sev[i].cmd != SEV_MCMD_ID_LIMIT)
    {
        if (state_tbl_sev[i].current == sev->sev.state && state_tbl_sev[i].cmd == cmd)
        {
            sev->sev.state = state_tbl_sev[i].next;     /* Transition is allowed */
            goto end;
        }
        i++;
    }

    /* Illegal state transition! */
    status = SEV_STATUS_INVALID_PLATFORM_STATE;

end:
    return status;
}

/**
 * Transition the platform to the provided snp state.
 *
 * Only returns if the requested state transition is valid.
 */
sev_status_t snp_state_transition(sev_t *sev, sev_mcmd_id_t cmd)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t i = 0;

    if (!sev || cmd >= SEV_MCMD_ID_LIMIT)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Check if this state transition is allowed for this command */
    while (state_tbl_snp[i].cmd != SEV_MCMD_ID_LIMIT)
    {
        if (state_tbl_snp[i].current == gpDram->perm.snp_state && state_tbl_snp[i].cmd == cmd)
        {
            gpDram->perm.snp_state = state_tbl_snp[i].next;     /* Transition is allowed */
            goto end;
        }
        i++;
    }

    /* Illegal state transition! */
    status = SEV_STATUS_INVALID_PLATFORM_STATE;

end:
    return status;
}

/**
 * Initialize the guest array
 */
sev_status_t sev_get_guests(sev_guest_t **guests, size_t *size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!guests || !size)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *size = sizeof(((struct sev_rsvd_dram *)0)->guests_dram); /* actual size in memory */
    *guests = gpDram->guests_dram;

end:
    return status;
}

/**
 * Initialize the "permanent" area of DRAM. This should happen ONCE, and
 * survives DLFW & DLFW_EX & SEV/SNP_INIT operations.
 * Cannot use any gSev or gPersistent state!
 */
static sev_status_t init_perm(void)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (gCurrentDieID != SEV_GLOBAL_MASTER_DIE_ID)
    {
        /* Invalidate P1 cache to force an update from memory to get latest data */
        sev_hal_invalidate_dcache((uint32_t)&gpDram->perm, sizeof(gpDram->perm));

        return (gpDram->perm.magic == SEV_PERM_MAGIC) ?
            SEV_STATUS_SUCCESS : SEV_STATUS_HARDWARE_UNSAFE;
    }

    /* Zero everything */
    memset(&gpDram->perm, 0, sizeof(gpDram->perm));
    /* Clear the area after perm in gpDram that will be used by future FW */
    memset(gpDram->buffer, 0, sizeof(gpDram->buffer));

    /*
     * Init state of all ASIDs/CCXs to 'dirty', not 'clean', not 'in-use',
     * and not 'allocated'. asid_dirty[] is initialized in sev_init
     * after ccx_present_bit_mask is initialized.
     */
    for (uint32_t i = 0; i < SEV_ASID_ARRAY_SIZE; i++)
    {
        memset(gpDram->perm.asid_dirty, 0, sizeof(gpDram->perm.asid_dirty));
        memset(gpDram->perm.asid_clean, 0, sizeof(gpDram->perm.asid_clean));
        memset(gpDram->perm.asid_allocated, 0, sizeof(gpDram->perm.asid_allocated));
        memset(gpDram->perm.asid_in_use, 0, sizeof(gpDram->perm.asid_in_use));
    }

    gpDram->perm.snp_guest_count = 0;

    /* Clear the global config register */
    memset(&gpDram->perm.rb_config, 0, sizeof(sev_rb_config_t));

    gpDram->perm.snp_iommu_enabled = false;
    memset(gpDram->perm.iommu_entry_list_start, 0, sizeof(gpDram->perm.iommu_entry_list_start));
    memset(gpDram->perm.iommu_entry_list_end, 0, sizeof(gpDram->perm.iommu_entry_list_end));
    gpDram->perm.iommu_entry_ctr = 0;

    gpDram->perm.dlfw_ex_commit = false;

    gpDram->perm.version = SEV_PERM_VERSION;
    gpDram->perm.length = sizeof(gpDram->perm);
    gpDram->perm.reserved = 0;

    gpDram->perm.rmp_base = 0;
    gpDram->perm.rmp_end = 0;
    gpDram->perm.snp_state = SNP_STATE_UNINIT;
    /* gpDram->perm.snp_identity zeroed with memset above */

    /* On first run, get committed tcb of BL from BL */
    status = sev_hal_get_tcb_version(&gpDram->perm.committed_tcb);
    if (status != SEV_STATUS_SUCCESS)
        goto end;
    gpDram->perm.committed_tcb.f.snp = SEV_FW_SVN;

    /* On first run, set committed FW version to current FW version */
    gpDram->perm.committed_build_id = SEV_BUILD_ID;
    gpDram->perm.committed_api_minor = SEV_API_MINOR;
    gpDram->perm.committed_api_major = SEV_API_MAJOR;

    /* Flag the perm area as initialized */
    gpDram->perm.magic = SEV_PERM_MAGIC;

    /* Flush the P0 dcache out to PSP DRAM so P1 can see gpDram->perm */
    sev_hal_clean_dcache((uint32_t)&gpDram->perm, sizeof(gpDram->perm));

end:
    return status;
}

/**
 * Initialize the SEV platform context.
 * Path 1: Call SEV init, call SEV uninit
 * Path 2: Call SNP init, call SNP uninit
 * Path 3: Call SNP init, call SEV init, call SEV uninit, call SNP uninit
 *
 * Note: This gets called by master and slaves
 */
sev_status_t sev_init(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_guest_t *guests = NULL;
    size_t guests_size = 0;
    uint32_t microcode_patch_level = 0;
    bool df_locked = false;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto exit_dont_unlock;
    }

    /* Initialize the permanent state, if necessary */
    if (gpDram->perm.magic != SEV_PERM_MAGIC)
        if ((status = init_perm()) != SEV_STATUS_SUCCESS)
            goto exit_dont_unlock;

    if ((!sev->common_context_initialized) && (!sev->sev.context_initialized) &&
        (!sev->snp.context_initialized))    /* Only really need to check common */
    {
        memset(sev, 0, sizeof(*sev));
    }

    /* Both modes, but don't run if already run */
    if (!sev->common_context_initialized)
    {
        /*
        * This is needed here in addition to the API call because sev_init() is called
        * for both master and slave die in the early part of SEV firmware sequence.
        * It is called before any command has been executed on the first run or before
        * the next command after a full shutdown (both SEV and SNP are UNINIT).
        */
        status = df_access_lock();
        if (status != SEV_STATUS_SUCCESS)
            goto exit_dont_unlock;
        df_locked = true;

        /* Get SOC Version */
        status = sev_hal_get_soc_version(&gPersistent.soc_version);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Get the initpkg data. Returns pointer to DRAM table; data and pointer never change */
        status = sev_hal_get_initpkg_dram(&gPersistent.initpkg_addr);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        /* Get current CPU's information. Master will also import slave data */
        /* Needs to be called before create_apicid_table() */
        status = sev_hal_get_mcm_info(&gPersistent);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        sev_hal_invalidate_dcache((uint32_t)gPersistent.initpkg_addr, sizeof(sev_scfctp_init_pkg_regs_t));

        /* BL FW Version is only fetched after mcm info */
        if (gPersistent.bl_fw_version >= MIN_BL_VERSION_SVC_SKIP_RSMU)
        {
            /* Get Skip RSMUS */
            status = sev_hal_get_skip_rsmus();
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
        else
        {
            /* if it's other versions copy it directly from mailbox */
            memcpy(&gPersistent.skip_rsmus,  &BL_BOOT_ROM_TABLE_PTR->Config.SkipRSMU, sizeof(gPersistent.skip_rsmus));
        }

        /* Needs to be before the first validate_memory_map call (x86_copy or access_cpu_tmr) */
        if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
        {
            /* CSF-961: Get the memory map to make sure RMP/SEV-ES, TMR's,
                GCTX pages, etc don't overlap MMIO region */
            memset(&gpDram->mem_map, 0, sizeof(SYS_MEM_MAP));
            status = get_memory_map(&gpDram->mem_map);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }

        gPersistent.smke_enabled = smke_is_enabled_all_cores();

        /* Create APICID lookup table */
        status = create_apicid_table(sev);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
        {
            /* Get the current, lowest microcode patch level. Can change @ any time */
            microcode_patch_level = retrieve_microcode_patch_level();

            /* Update committed TCB with this uCode version */
            gpDram->perm.committed_tcb.f.microcode = microcode_patch_level & 0xff;

            sev_hal_get_smm_range(&gPersistent.smm_base, &gPersistent.smm_length);

            /* Initialize the ASID dirty array with the CCX mask. */
            for (uint32_t i = 0; i < SEV_ASID_ARRAY_SIZE; i++)
            {
                gpDram->perm.asid_dirty[i] = gPersistent.ccx_present_bit_mask;
            }
        }
        sev->common_context_initialized = true;
    }

    /* Do the SEV-related initialization */
    if (!sev->sev.context_initialized)
    {
        if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
        {
            status = sev_get_guests(&guests, &guests_size);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            sev->sev.guests = guests;    /* Init pointer to guests[] in DRAM */

            /* Clear guests[] in DRAM, but only if master die. */
            if (gCurrentDieID == SEV_GLOBAL_MASTER_DIE_ID)
                memset(guests, 0, guests_size);

            status = sev_cert_init(&sev->sev.identity.persistent.oca_cert);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            status = sev_cert_init(&sev->sev.identity.persistent.pdh_cert);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            status = sev_cert_init(&sev->sev.identity.persistent.pek_cert);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            sev->sev.es.reserved_tmr_base = PADDR_INVALID;
            sev->sev.es.reserved_tmr_end = PADDR_INVALID;
        }
        sev->sev.context_initialized = true;
    }

    if (!sev->snp.context_initialized)
    {
        sev->snp.context_initialized = true;
    }

end: /* Release DF C State but preserve the status code */
    if (df_locked)
        df_access_unlock();
exit_dont_unlock:
    return status;
}

/**
 * Clear the SEV platform context.
 */
sev_status_t sev_clear(sev_t *sev)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_guest_t *guests = NULL;
    size_t guests_size = 0;
    uint32_t asid = 0;
    uint32_t ccxs = 0;
    uint32_t tmp_ccxs = 0;
    uint32_t guest_count = 0;

    if (!sev)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (sev->sev.state == SEV_STATE_UNINIT && sev->sev.context_initialized) /* SEV */
    {
        status = sev_get_guests(&guests, &guests_size);
        if (status != SEV_STATUS_SUCCESS)
            goto end;

        sev->sev.guests = guests;    /* Init pointer to guests[] in DRAM */

        /*
         * If shutting down SEV while SNP is running, mark only SEV asids
         * invalid and decommission all SEV guests so we can keep running SNP
         * guests (if enabled)
         */
        if (gpDram->perm.snp_state != SNP_STATE_UNINIT)
        {
            for (uint32_t i = 0; i < SEV_GUEST_COUNT_MAX; i++)
            {
                if (guest_is_free(&sev->sev.guests[i]))
                    continue;

                asid = sev->sev.guests[i].asid;
                ccxs = sev->sev.guests[i].ccxs;

                /* Skip if Guest is valid but not activated */
                if (asid != 0)
                {
                    /* Need to update the asid arrays in sev struct and set invalid asid bits */
                    if (gpDram->perm.asid_in_use[asid-1])
                    {
                        status = sev_guest_deactivate(&sev->sev.guests[i], gpDram->perm.asid_in_use[sev->sev.guests[i].asid-1]);
                        if (status != SEV_STATUS_SUCCESS)
                            goto end;
                    }

                    tmp_ccxs = gpDram->perm.asid_allocated[asid-1] & ccxs;
                    if (tmp_ccxs)
                    {
                        /* These CCXs never made it to Running.
                        Allocated but never used CCXs: Clean */
                        gpDram->perm.asid_allocated[asid-1] &= ~tmp_ccxs;
                        gpDram->perm.asid_clean[asid-1] |= tmp_ccxs;
                    }
                    tmp_ccxs = gpDram->perm.asid_in_use[asid-1] & ccxs;
                    if (tmp_ccxs)
                    {
                        /* Has been Running: InUse CCXs Dirty. */
                        gpDram->perm.asid_in_use[asid-1] &= ~tmp_ccxs;
                        gpDram->perm.asid_dirty[asid-1] |= tmp_ccxs;
                    }
                }

                /* Could decommission the guest here, but it gets done in memzero(guests) below anyway */
                guest_count++;
            }

            /*
             * Note: You can ONLY do this because we are NOT decommissioning the
             * guests above. That would decrement the sev.guest_count param and
             * the check would have to move/change
             */
            if (guest_count != sev->sev.guest_count)
            {
                status = ERR_OUT_OF_RESOURCES;   /* Internal error. Should never happen */
                goto end;
            }
        }
        else
        {
            /* SEV and SNP are both UNINIT, invalidate all ASIDs
             * Prevent guests from running before we release the TMR */
            status = mark_all_asids_invalid();
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }

        /* Release the SEV-ES TMR */
        if (sev_es_platform_enabled(sev))
        {
            status = sev_es_release_trusted_region(&sev->sev.es);
            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }

        /* Clear guests[] in DRAM */
        secure_memzero(guests, guests_size);

        /* Clear only the SEV part of the sev_t structure */
        secure_memzero(&sev->sev, sizeof(sev->sev));

        sev->sev.context_initialized = false;
    }

    if (gpDram->perm.snp_state == SNP_STATE_UNINIT && sev->snp.context_initialized)     /* SNP */
    {
        /* Clear only the SNP part of the sev_t structure */
        secure_memzero(&sev->snp, sizeof(sev->snp));

        sev->snp.context_initialized = false;
    }

    if (sev->sev.state == SEV_STATE_UNINIT && gpDram->perm.snp_state == SNP_STATE_UNINIT) /* Common */
    {
        secure_memzero(sev, sizeof(sev_t));  /* Erase the whole thing */

        if (gpDram->perm.rb_config.rb_enable)
        {
            /* Reclaim Ring Buffer for SNP enabled system */
            if (gpDram->perm.rb_config.status_ptr_high_priority_reclaim)
            {
                status = snp_reclaim_buffer(gpDram->perm.rb_config.status_ptr_high_priority_reclaim);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
            }

            if (gpDram->perm.rb_config.status_ptr_low_priority_reclaim)
            {
                status = snp_reclaim_buffer(gpDram->perm.rb_config.status_ptr_low_priority_reclaim);
                if (status != SEV_STATUS_SUCCESS)
                    goto end;
            }
        }
        /* Ring Buffer - Disable when both are UNINIT */
        gpDram->perm.rb_config.rb_enable = false;

        sev->common_context_initialized = false;
    }

end:
    return status;
}

/**
 * Return the max SEV ASID
 */
uint32_t GetMaxSEVASID(void)
{
    return MAX_SEV_ASIDS;
}

static uint32_t tcb_version_to_num(const snp_tcb_version_t *tcb)
{
    uint32_t num = 0;

    if (tcb)
    {
        num = (tcb->f.boot_loader & 0xff);
        num <<= 8;
        num |= (tcb->f.tee & 0xff);
        num <<= 8;
        num |= (tcb->f.snp & 0xff);
        num <<= 8;
        num |= (tcb->f.microcode & 0xff);
    }

    return num;
}

int32_t tcb_compare_versions(const snp_tcb_version_t *tcb_a, const snp_tcb_version_t *tcb_b)
{
    int32_t ret;

    if (memcmp(tcb_a, tcb_b, sizeof(snp_tcb_version_t)) == 0)
       ret = 0;
    else if (tcb_version_to_num(tcb_a) < tcb_version_to_num(tcb_b))
       ret = -1;
    else
       ret = 1;

    return ret;
}
