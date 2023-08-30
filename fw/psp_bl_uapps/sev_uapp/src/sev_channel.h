// Copyright(C) 2017-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_CHANNEL_H
#define SEV_CHANNEL_H

#include "cipher.h"
#include "hmac.h"
#include "sev_status.h"

#define MASTER_SECRET_SIZE_BYTES        (16)
#define NONCE_SIZE_BYTES                (16)

#define SEV_TEK_SIZE_BYTES              (CIPHER_AES128_KEY_SIZE_BYTES)
#define SEV_TIK_SIZE_BYTES              (SEV_TEK_SIZE_BYTES)
#define SEV_TRANSPORT_KEYS_SIZE_BYTES   ((SEV_TEK_SIZE_BYTES)+(SEV_TIK_SIZE_BYTES))
#define SEV_KEK_SIZE_BYTES              (CIPHER_AES128_KEY_SIZE_BYTES)
#define SEV_KIK_SIZE_BYTES              (SEV_KEK_SIZE_BYTES)

typedef struct sev_measurement
{
    hmac_sha256_t   measurement;
    uint8_t         mnonce[NONCE_SIZE_BYTES];
} sev_measurement_t;

typedef struct sev_trusted_channel
{
    uint8_t                 master_secret[MASTER_SECRET_SIZE_BYTES];
    cipher_aes_key_t        tek;
    uint8_t                 tik[SEV_TIK_SIZE_BYTES];
    uint8_t                 nonce[NONCE_SIZE_BYTES];
    sev_measurement_t       measurement;    /* launch measure to launch secret */
} sev_trusted_channel_t;

typedef struct sev_session
{
    uint8_t             nonce[NONCE_SIZE_BYTES];
    uint8_t             wrap_tk[SEV_TRANSPORT_KEYS_SIZE_BYTES];
    cipher_aes_iv_t     wrap_iv;
    hmac_sha256_t       wrap_mac;
    hmac_sha256_t       policy_mac;
} sev_session_t;

typedef struct sev_packet_header
{
    uint32_t            flags;
    cipher_aes_iv_t     iv;
    hmac_sha256_t       mac;
} sev_packet_header_t;

typedef enum sev_channel_ctx
{
    SEV_CHANNEL_CTX_SECRET  = 0x01,
    SEV_CHANNEL_CTX_DATA    = 0x02,
    SEV_CHANNEL_CTX_VMSA    = 0x03,
    SEV_CHANNEL_CTX_MEASURE = 0x04,
} sev_channel_ctx_t;

/**
 * Open the server end of the trusted channel (i.e. the receiver).
 *
 * Parameters:
 *     keypair        [in] server's DH keypair,
 *     dh_cert        [in] client's DH cert,
 *     session        [in] launch session object,
 *     channel        [out] stored channel parameters
 */
sev_status_t sev_channel_open_server(const sev_cert_keypair_t *keypair,
                                     const sev_cert_t *dh_cert,
                                     const sev_session_t *session,
                                     sev_trusted_channel_t *channel);

/**
 * Open the client end of the trusted channel (i.e. the sender).
 *
 * Parameters:
 *     policy           [in] guest policy
 *     keypair          [in] client's DH keypair,
 *     dh_cert_paddr    [in] server's DH cert,
 *     session          [out] migrate session object,
 *     channel          [out] generated channel parameters
 */
sev_status_t sev_channel_open_client(uint32_t policy,
                                     const sev_cert_keypair_t *keypair,
                                     const sev_cert_t *dh_cert,
                                     sev_session_t *session,
                                     sev_trusted_channel_t *channel);

/**
 * Close the trusted channel and delete all channel parameters.
 *
 * Parameters:
 *     channel          [in] channel parameters
 */
void sev_channel_close(sev_trusted_channel_t *channel);

/**
 * Extract a secret from the trusted channel. The secret will be extracted to
 * 'buffer' in-place.
 *
 * Parameters:
 *     buffer               [in/out] input data/extracted secret,
 *     size                 [in] buffer size,
 *     uncompressed_size    [in] size of uncompressed secret,
 *     channel              [in] SEV trusted channel parameters,
 *     header               [in] SEV packet header object.
 */
sev_status_t sev_channel_extract_secret(void *buffer, size_t size,
                                        size_t uncompressed_size,
                                        const sev_trusted_channel_t *channel,
                                        const sev_packet_header_t *header);

#endif /* SEV_CHANNEL_H */
