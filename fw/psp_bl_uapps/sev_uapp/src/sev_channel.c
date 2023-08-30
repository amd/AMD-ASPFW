// Copyright(C) 2017-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ecdh.h"
#include "nist_kdf.h"
#include "secure_ops.h"
#include "sev_cert.h"
#include "sev_channel.h"
#include "sev_hal.h"

#define SEV_MASTER_SECRET_LABEL "sev-master-secret"
#define SEV_KEK_LABEL           "sev-kek"
#define SEV_KIK_LABEL           "sev-kik"

/**
 * Flow of channel opening/closing
 * launch_start -> sev_channel_open_server -> establish_channel (generates KEK/KIK)(is_open->true)
 * send_start   -> sev_channel_open_client -> create_channel    (generates TEK/TIK)(is_open->true)
 * launch_finish / send_finish / send_cancel / receive_finish -> sev_channel_close (is_open->false)
 */

static sev_status_t derive_master_secret(const sev_cert_keypair_t *keypair,
                                         const sev_cert_pubkey_t *pubkey,
                                         const uint8_t *nonce, size_t nonce_size,
                                         uint8_t *secret, size_t secret_size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    ecc_scalar_t intermediate;
    uint8_t master_secret[MASTER_SECRET_SIZE_BYTES] = {0};

    if (!keypair || !pubkey || !nonce || nonce_size == 0 || !secret ||
        secret_size != MASTER_SECRET_SIZE_BYTES)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Calculate the intermediate secret */
    memset(intermediate.s, 0, sizeof(intermediate.s));
    status = ecdh_key_agreement(&keypair->keypair.ecdsa, &pubkey->key.ecdsa,
                                intermediate.s, ECC_CURVE_SECP384R1_SIZE_BYTES);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the master secret from the intermediate secret */
    status = kdf_derive(master_secret, sizeof(master_secret),
                        intermediate.s, ECC_CURVE_SECP384R1_SIZE_BYTES,
                        SEV_MASTER_SECRET_LABEL, sizeof(SEV_MASTER_SECRET_LABEL)-1,
                        nonce, nonce_size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the master secret to the output */
    memcpy(secret, master_secret, secret_size);

end:
    /* Clear secrets from memory */
    secure_memzero(master_secret, sizeof(master_secret));
    secure_memzero(intermediate.s, sizeof(intermediate.s));
    return status;
}

static sev_status_t create_channel(const sev_cert_keypair_t *keypair,
                                   const sev_cert_pubkey_t *pubkey,
                                   sev_trusted_channel_t *channel)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_trusted_channel_t temp;

    if (!keypair || !pubkey || !channel)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp, 0, sizeof(temp));

    /* Generate the TEK from random bytes */
    status = sev_hal_trng(temp.tek.key, sizeof(temp.tek.key));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Generate the TIK from random bytes */
    status = sev_hal_trng(temp.tik, sizeof(temp.tik));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Generate a nonce */
    status = sev_hal_trng(temp.nonce, sizeof(temp.nonce));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the master secret */
    status = derive_master_secret(keypair, pubkey, temp.nonce,
                                  sizeof(temp.nonce), temp.master_secret,
                                  sizeof(temp.master_secret));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the channel data to the output */
    memcpy(channel, &temp, sizeof(*channel));

end:
    secure_memzero(&temp, sizeof(temp));
    return status;
}

static sev_status_t create_session(sev_session_t *session, uint32_t policy,
                                   const sev_trusted_channel_t *channel)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_session_t temp;
    cipher_aes_key_t kek;
    uint8_t kik[SEV_KIK_SIZE_BYTES] = {0};
    cipher_aes_ctr_ctx_t ctx;
    size_t size = 0;

    if (!session || !channel)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&temp, 0, sizeof(temp));
    memset(&kek, 0, sizeof(kek));

    /* Generate a fresh IV */
    status = sev_hal_trng(temp.wrap_iv.iv, sizeof(temp.wrap_iv.iv));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the key encryption key (KEK) */
    status = kdf_derive(kek.key, sizeof(kek),
                        channel->master_secret, sizeof(channel->master_secret),
                        SEV_KEK_LABEL, sizeof(SEV_KEK_LABEL)-1, NULL, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the key integrity key (KIK) */
    status = kdf_derive(kik, sizeof(kik),
                        channel->master_secret, sizeof(channel->master_secret),
                        SEV_KIK_LABEL, sizeof(SEV_KIK_LABEL)-1, NULL, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Wrap the transport keys */
    status = cipher_aes_ctr_init(&ctx, &temp.wrap_iv, &kek, AES_MODE_ENCRYPT);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    size = sizeof(temp.wrap_tk);
    status = cipher_aes_ctr_update(&ctx, channel->tek.key,
                                   sizeof(channel->tek.key), temp.wrap_tk,
                                   &size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_aes_ctr_final(&ctx, channel->tik, sizeof(channel->tik),
                                  temp.wrap_tk + size, &size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Integrity protect the wrapped transport keys */
    status = hmac_sha256(temp.wrap_tk, sizeof(temp.wrap_tk), kik, sizeof(kik),
                         &temp.wrap_mac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Integrity protect the guest policy */
    status = hmac_sha256(&policy, sizeof(policy), channel->tik,
                         sizeof(channel->tik), &temp.policy_mac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the channel nonce */
    memcpy(temp.nonce, channel->nonce, sizeof(temp.nonce));

    /* Copy the session data to the output */
    memcpy(session, &temp, sizeof(*session));

end:
    secure_memzero(&kek, sizeof(kek));
    secure_memzero(kik, sizeof(kik));
    return status;
}

static sev_status_t establish_channel(const uint8_t *secret, size_t size,
                                      const sev_session_t *session,
                                      sev_trusted_channel_t *channel)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    cipher_aes_key_t kek;
    uint8_t kik[SEV_KIK_SIZE_BYTES] = {0};
    cipher_aes_ctr_ctx_t ctx;
    uint8_t unwrapped_keys[SEV_TRANSPORT_KEYS_SIZE_BYTES] = {0};
    size_t unwrapped_keys_len = sizeof(unwrapped_keys);

    if (!secret || size != MASTER_SECRET_SIZE_BYTES || !session || !channel)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    memset(&kek, 0, sizeof(kek));

    /* Derive the key encryption key (KEK) */
    status = kdf_derive(kek.key, sizeof(kek), secret, size,
                        SEV_KEK_LABEL, sizeof(SEV_KEK_LABEL)-1, NULL, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the key integrity key (KIK) */
    status = kdf_derive(kik, sizeof(kik), secret, size,
                        SEV_KIK_LABEL, sizeof(SEV_KIK_LABEL)-1, NULL, 0);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Validate the HMAC for the wrapped keys */
    status = hmac_sha256_verify_msg(session->wrap_tk, sizeof(session->wrap_tk),
                                    kik, sizeof(kik), &session->wrap_mac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Unwrap the transport keys */
    status = cipher_aes_ctr_init(&ctx, &session->wrap_iv, &kek, AES_MODE_DECRYPT);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = cipher_aes_ctr_final(&ctx, session->wrap_tk, sizeof(session->wrap_tk),
                                  unwrapped_keys, &unwrapped_keys_len);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Store the trusted channel data */
    memcpy(channel->master_secret, secret, sizeof(channel->master_secret));
    memcpy(channel->nonce, session->nonce, sizeof(channel->nonce));
    memcpy(channel->tek.key, unwrapped_keys, sizeof(channel->tek.key));
    memcpy(channel->tik, unwrapped_keys + SEV_TEK_SIZE_BYTES, sizeof(channel->tik));

end:
    /* Clear sensitive data from memory */
    secure_memzero(&kek, sizeof(kek));
    secure_memzero(kik, sizeof(kik));
    secure_memzero(unwrapped_keys, sizeof(unwrapped_keys));

    return status;
}

/**
 * Params:
 *  keypair[in]: PDH from sev->identity (firmware)
 *  dh_cert[in]: cert from x86
 *  session[in]: session from x86
 *  channel[out]: output of function
 */
sev_status_t sev_channel_open_server(const sev_cert_keypair_t *keypair,
                                     const sev_cert_t *dh_cert,
                                     const sev_session_t *session,
                                     sev_trusted_channel_t *channel)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint8_t master_secret[MASTER_SECRET_SIZE_BYTES] = {0};
    sev_trusted_channel_t temp;

    if (!keypair || !session || !dh_cert || !channel)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (keypair->usage != SEV_CERT_USAGE_PDH ||
        (keypair->algo != SEV_CERT_ALGO_ECDH_SHA256 && keypair->algo != SEV_CERT_ALGO_ECDH_SHA384))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* Validate the body information */
    status = sev_cert_sanity_check(dh_cert, SEV_CERT_USAGE_PDH, SEV_CERT_ALGO_ECDH_SHA256);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Derive the master secret */
    status = derive_master_secret(keypair, &dh_cert->body.pubkey,
                                  session->nonce, sizeof(session->nonce),
                                  master_secret, sizeof(master_secret));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Establish the trusted channel from the session data */
    memset(&temp, 0, sizeof(temp));
    status = establish_channel(master_secret, sizeof(master_secret), session,
                               &temp);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the channel data to the output */
    memcpy(channel, &temp, sizeof(*channel));

end:
    /* Clear sensitive data from memory */
    secure_memzero(master_secret, sizeof(master_secret));
    return status;
}

sev_status_t sev_channel_open_client(uint32_t policy,
                                     const sev_cert_keypair_t *keypair,
                                     const sev_cert_t *dh_cert,
                                     sev_session_t *session,
                                     sev_trusted_channel_t *channel)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    sev_trusted_channel_t temp_channel;
    sev_session_t temp_session;

    if (!keypair || !session || !dh_cert || !channel)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (keypair->usage != SEV_CERT_USAGE_PDH ||
        (keypair->algo != SEV_CERT_ALGO_ECDH_SHA256 && keypair->algo != SEV_CERT_ALGO_ECDH_SHA384))
    {
        status = SEV_STATUS_INVALID_CERTIFICATE;
        goto end;
    }

    /* Validate the body information */
    status = sev_cert_sanity_check(dh_cert, SEV_CERT_USAGE_PDH, SEV_CERT_ALGO_ECDH_SHA256);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Create the trusted channel */
    status = create_channel(keypair, &dh_cert->body.pubkey, &temp_channel);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Create a new session for the channel */
    status = create_session(&temp_session, policy, &temp_channel);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Copy the channel and session data to the output */
    memcpy(session, &temp_session, sizeof(*session));
    memcpy(channel, &temp_channel, sizeof(*channel));

end:
    /* Clear sensitive data from memory */
    secure_memzero(&temp_channel, sizeof(temp_channel));
    return status;
}

void sev_channel_close(sev_trusted_channel_t *channel)
{
    if (channel)
        secure_memzero(channel, sizeof(*channel));
}

static sev_status_t sev_channel_hmac(sev_channel_ctx_t channel_ctx,
                                     const void *buffer, size_t size,
                                     size_t uncompressed_size,
                                     const sev_trusted_channel_t *channel,
                                     const sev_packet_header_t *header,
                                     hmac_sha256_t *hmac)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    hmac_sha256_ctx_t ctx;

    if (!buffer || size == 0 || uncompressed_size == 0 || !channel || !header || !hmac)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Calculate the HMAC for the buffer */
    status = hmac_sha256_init(&ctx, channel->tik, sizeof(channel->tik));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, &channel_ctx, sizeof(char));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, &header->flags, sizeof(header->flags));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, &header->iv, sizeof(header->iv));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, &uncompressed_size, sizeof(uncompressed_size));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, &size, sizeof(size));
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_update(&ctx, buffer, size);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    if (channel_ctx == SEV_CHANNEL_CTX_SECRET)
    {
        status = hmac_sha256_update(&ctx, &channel->measurement.measurement,
                                    sizeof(channel->measurement.measurement));
        if (status != SEV_STATUS_SUCCESS)
            goto end;
    }

    status = hmac_sha256_final(&ctx, hmac);

end:
    return status;
}

static sev_status_t sev_channel_verify_hmac(sev_channel_ctx_t channel_ctx,
                                            const void *buffer, size_t size,
                                            size_t uncompressed_size,
                                            const sev_trusted_channel_t *channel,
                                            const sev_packet_header_t *header)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    hmac_sha256_t hmac;

    if (!buffer || size == 0 || uncompressed_size == 0 || !channel || !header)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Calculate the HMAC for the buffer */
    status = sev_channel_hmac(channel_ctx, buffer, size, uncompressed_size,
                              channel, header, &hmac);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    status = hmac_sha256_verify(&hmac, &header->mac);

end:
    return status;
}

static sev_status_t sev_channel_extract(sev_channel_ctx_t ctx,
                                        void *buffer, size_t size,
                                        size_t uncompressed_size,
                                        const sev_trusted_channel_t *channel,
                                        const sev_packet_header_t *header)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    cipher_aes_ctr_ctx_t aes_ctx;
    size_t plaintext_size = 0;

    if (!buffer || size == 0 || uncompressed_size == 0 || !channel || !header)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    /* Validate the HMAC for this transfer */
    status = sev_channel_verify_hmac(ctx, buffer, size, uncompressed_size,
                                     channel, header);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Decrypt the data in-place */
    status = cipher_aes_ctr_init(&aes_ctx, &header->iv, &channel->tek,
                                 AES_MODE_DECRYPT);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    plaintext_size = size;
    status = cipher_aes_ctr_final(&aes_ctx, buffer, size,
                                  buffer, &plaintext_size);

end:
    return status;
}

sev_status_t sev_channel_extract_secret(void *buffer, size_t size,
                                        size_t uncompressed_size,
                                        const sev_trusted_channel_t *channel,
                                        const sev_packet_header_t *header)
{
    return sev_channel_extract(SEV_CHANNEL_CTX_SECRET, buffer, size,
                               uncompressed_size, channel, header);
}
