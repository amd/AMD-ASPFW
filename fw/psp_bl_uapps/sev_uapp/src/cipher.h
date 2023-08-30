// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef CIPHER_H
#define CIPHER_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

#define CIPHER_AES128_KEY_SIZE_BYTES    16  /* Existing SEV APIs */
#define CIPHER_AES_KEY_SIZE_BYTES       32  /* Genoa hardware - UMC keys, cnli */
#define CIPHER_AES_BLOCK_SIZE_BYTES     16
#define CIPHER_AES_IV_SIZE_BYTES        (CIPHER_AES_BLOCK_SIZE_BYTES)

typedef struct cipher_aes_iv
{
    uint8_t iv[CIPHER_AES_IV_SIZE_BYTES];
} cipher_aes_iv_t;

typedef struct cipher_aes_key
{
    uint8_t key[CIPHER_AES128_KEY_SIZE_BYTES];
} cipher_aes_key_t;

typedef enum cipher_aes_mode
{
    AES_MODE_DECRYPT = 0,
    AES_MODE_ENCRYPT = 1,
    AES_MODE_INVALID = 0xFF,
} cipher_aes_mode_t;

typedef struct cipher_aes_ctr_ctx
{
    cipher_aes_iv_t      counter;
    cipher_aes_key_t     key;
    cipher_aes_mode_t    mode;
} cipher_aes_ctr_ctx_t;

/**
 * Implements AES-CTR init.
 *
 * 'ctx': output, pointer to context provided by crypto layer.
 *
 */
sev_status_t cipher_aes_ctr_init(cipher_aes_ctr_ctx_t *ctx,
                                 const cipher_aes_iv_t *counter,
                                 const cipher_aes_key_t *key,
                                 const cipher_aes_mode_t  mode);

/**
 * Implements AES-CTR update.
 *
 * 'ctx'    : input/output of intermediate context IV
 * 'src_len': must be multiple of 16 bytes, cannot be 0.
 *
 * support In Place operation (src==dest)!!!
 */
sev_status_t cipher_aes_ctr_update(cipher_aes_ctr_ctx_t *ctx,
                                   const uint8_t *src, uint32_t src_len,
                                   uint8_t *dest, uint32_t *dest_len);

/**
 * Implements AES-CTR final.
 *
 * 'ctx'    : input of final IV, note: this final IV cannot be used as context IV if
 *            src_len is not aligned to 16.
 * 'src_len': could be 0, or any, do not have to be multiple of 16 bytes.
 *
 * support In Place operation (src==dest)!!!
 */
sev_status_t cipher_aes_ctr_final(cipher_aes_ctr_ctx_t *ctx,
                                  const uint8_t *src, uint32_t src_len,
                                  uint8_t *dest, uint32_t *dest_len);

#endif /* CIPHER_H */
