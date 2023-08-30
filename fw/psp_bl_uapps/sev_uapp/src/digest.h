// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef DIGEST_H
#define DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "bl_syscall.h"
#include "sev_errors.h"

#define DIGEST_SHA256_SIZE_BYTES    (32)
#define SHA256_BLOCK_SIZE_BYTES     (64)
#define SHA256_HASH_WORDS           (8)

#define DIGEST_SHA384_SIZE_BYTES    (48)
#define SHA384_BLOCK_SIZE_BYTES     (128)
#define SHA384_HASH_WORDS           (16)

#define DIGEST_SHA512_SIZE_BYTES    (64)
#define SHA512_BLOCK_SIZE_BYTES     (128)
#define SHA512_HASH_WORDS           (16)

/* Set this to be the largest size of the SHA expected */
#define DIGEST_SHA_SIZE_BYTES       (DIGEST_SHA384_SIZE_BYTES)
#define SHA_BLOCK_SIZE_BYTES        (SHA384_BLOCK_SIZE_BYTES)

/* For SHA 384 the DIGEST has to be stored with 64 bytes */
#define DIGEST_STORAGE_BYTES        (64)
#define SHA_HASH_WORDS              (DIGEST_STORAGE_BYTES / 4)

typedef struct digest_sha
{
    uint8_t digest[DIGEST_STORAGE_BYTES];
} digest_sha_t;

typedef uint32_t digest_crc32_t;
typedef uint32_t digest_crc32_ctx_t;

/**
 * Note: If this structure is used in PSP reserved DRAM, msg_block[] minimum
 *       alignment must be 16 bytes if used with CCP. Since the sizeof h[] is a
 *       multiple of 16 bytes, aligning the structure is sufficient. Don't swap
 *       msg_block[] and h[]: there is an order dependency.
 *       If used in SRAM, 4 byte minimum alignment is sufficient, so the 16-byte
 *       alignment is not imposed here.
 */
typedef struct digest_sha_ctx
{
    union
    {
        digest_sha_t d;
        uint32_t     words[SHA_HASH_WORDS];
    } h;
    uint8_t     msg_block[SHA_BLOCK_SIZE_BYTES];
    size_t      bytes_used;
    uint32_t    length;
    SHA_TYPE    sha_type;
} digest_sha_ctx_t;

/**
 * Initializes the digest context.
 *
 * Caller must be responsible for donating context memory!
 *
 * Interweaving call is supported!
 *
 * For each digest_* call, low-level crypto resource is allocated
 * and release upon completion as one-shot business!
 */
sev_status_t digest_sha_init(digest_sha_ctx_t *ctx, SHA_TYPE sha_type);

/**
 * Updates the context with the given data.
 *
 * 'data'  : data buffer to hash.
 * 'length': length of the input data.
 *
 */
sev_status_t digest_sha_update(digest_sha_ctx_t *ctx, const void *data,
                               size_t length);

/**
 * Updates the context with the padding and calculates the final digest.
 *
 * digest    : output buffer for the final digest.
 * digest_len: length of the output buffer.
 */
sev_status_t digest_sha_final(digest_sha_ctx_t *ctx, digest_sha_t *digest,
                              size_t *digest_len);

/**
 * Calculate the complete SHA256 digest of the input message.
 *
 * msg       : message buffer to hash.
 * msg_len   : length of the input message.
 * digest    : output buffer for the final digest.
 * digest_len: length of the output buffer.
 */
sev_status_t digest_sha(const void *msg, size_t msg_len,
                        digest_sha_t *digest, size_t *digest_len,
                        SHA_TYPE sha_type);

/**
 * Retrieve the digest bytes from the context
 * Returns the h param in digest_sha_ctx_t
 */
static inline digest_sha_t *sha_ctx_to_digest(digest_sha_ctx_t *ctx)
{
    return (digest_sha_t *)ctx;
}

#endif /* DIGEST_H */
