// Copyright(C) 2018-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef CCP_DIRECT_CIPHER_H
#define CCP_DIRECT_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#include "sev_errors.h"

sev_status_t aesctr_hmac256_encrypt(const uint8_t *pEncKey, size_t EncKeySize,
                                    const uint8_t *pMacKey, size_t MacKeySize,
                                    const uint8_t *pAAD, size_t AADSize,
                                    const uint8_t *pMsg, size_t MsgSize,
                                    uint8_t *pOut, uint8_t *pIV,
                                    uint8_t *pHmac);

sev_status_t aesctr_hmac256_decrypt(const uint8_t *pEncKey, size_t EncKeySize,
                                    const uint8_t *pMacKey, size_t MacKeySize,
                                    const uint8_t *pAAD, size_t AADSize,
                                    const uint8_t *pMsg, size_t MsgSize,
                                    uint8_t *pOut, const uint8_t *pIv,
                                    const uint8_t *pHmac);

sev_status_t aes256gcm_authenticated_encrypt(const uint8_t *pKey, size_t KeySize,
                                             const uint8_t *pAAD, size_t AADSize,
                                             const uint8_t *pMsg, size_t MsgSize,
                                             uint8_t *pOut,
                                             const uint8_t *pIV, size_t IVSize,
                                             uint8_t *pTag); // [out, 16 bytes]

sev_status_t aes256gcm_authenticated_encrypt_x86addr(const uint8_t *pKey, size_t KeySize,
                                             const uint8_t *pAAD, size_t AADSize,
                                             const uint64_t MsgAddr, size_t MsgSize,
                                             const uint64_t OutAddr,
                                             const uint8_t *pIV, size_t IVSize,
                                             uint8_t *pTag, // [out, 16 bytes]
                                             uint32_t asid);

sev_status_t aes256gcm_authenticated_decrypt(const uint8_t *pKey, size_t KeySize,
                                             const uint8_t *pAAD, size_t AADSize,
                                             const uint8_t *pMsg, size_t MsgSize,
                                             uint8_t *pOut,
                                             const uint8_t *pIV, size_t IVSize,
                                             const uint8_t *pTag); // [in, 16 bytes]

sev_status_t aes256gcm_authenticated_decrypt_x86addr(const uint8_t *pKey, size_t KeySize,
                                             const uint8_t *pAAD, size_t AADSize,
                                             const uint64_t MsgAddr, size_t MsgSize,
                                             const uint64_t OutAddr,
                                             const uint8_t *pIV, size_t IVSize,
                                             const uint8_t *pTag, // [in, 16 bytes]
                                             uint32_t asid);

// -- KAT ----------------------------------------------------------------

sev_status_t digest_utest_sha256_kat(const uint8_t *msg, size_t msg_size,
                                     const uint8_t *digest, int multipart);

sev_status_t hmac_utest_hmac256_kat(const uint8_t *key, size_t key_size,
                                    const uint8_t *msg, size_t msg_size,
                                    const uint8_t *hmac);

sev_status_t cipher_utest_aes256gcm_kat(const uint8_t *pKey, const uint8_t *pIV,
                                        size_t IV_size, const uint8_t *pAAD,
                                        size_t AADSize, const uint8_t *pMsg,
                                        size_t MsgSize,
                                        const uint8_t *pCiphertext,
                                        const uint8_t *pTag);

#endif /* CCP_DIRECT_CIPHER_H */
