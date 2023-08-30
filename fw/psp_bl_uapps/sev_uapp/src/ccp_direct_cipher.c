// Copyright(C) 2018-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <string.h>

#include "ccp_direct_cipher.h"
#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "crypto.h"
#include "secure_ops.h"
#include "sev_hal.h"
#include "x86_copy.h"

#define LSB_SEV_RESERVED    5       // 4 static LSB's reserved for SEV use

// We are using staticly assigned LSB's
#define LSB_SEV_AESKEY  (LSB_SEV_RESERVED + 0)
#define LSB_SEV_AESIV   (LSB_SEV_RESERVED + 1)
#define LSB_SEV_SHA     (LSB_SEV_RESERVED + 2)

#define ADDRESS_LO(X)   (uint32_t)(X)
#define ADDRESS_HI(X)   0

#define DEFAULT_IOC     1
#define DEFAULT_SOC     0
#define GCM_IV_PAD      0x00000000

#define PASSTHROUGH_NO_SWAP         0
#define PASSTHROUGH_SWAP_256_BITS   2   // CCP_HAL_PASSTHROUGH_SWAP_256_BIT

// ------------------------------------------------------------------------------
// opad, ipad and aad arrays allocate the minimum required space based on what
// hashing algorithms are implemented. You may increase the sizes for SHA384/512
// but make sure new size is multiple of 32 (cache line is 32 bytes).
// ------------------------------------------------------------------------------
static __align(32) struct
{
    union
    {
        uint8_t bytes[32];
        struct
        {
            struct
            {
                uint32_t cnt32;
                uint32_t ext32;
                uint8_t  iv[8];
            } j0;
            uint8_t ghash[16];
        } aes_gcm_le;

        struct
        {
            struct
            {
                uint64_t cnt64;
                uint8_t  iv[8];
            } iv;
            uint8_t rfu[16];
        } aes_ctr_le;
    } ctx;
    uint8_t key_256bits[32];
    uint8_t opad[HMAC_SHA512_BLOCK_SIZE_BYTES]; /* Do not change order of these fields */
    uint8_t ipad[HMAC_SHA512_BLOCK_SIZE_BYTES];
    uint8_t aad[HMAC_SHA512_BLOCK_SIZE_BYTES - 16]; /* Minimum of 112 bytes */
    uint8_t len[16];
} gWorkBuffs;

// Make sure no changes due to alignment/padding
COMMON_COMPILE_TIME_ASSERT(sizeof(gWorkBuffs) == 448, this_file);
COMMON_COMPILE_TIME_ASSERT((sizeof(gWorkBuffs.opad) % 32) == 0, this_file);
COMMON_COMPILE_TIME_ASSERT((sizeof(gWorkBuffs.ipad) % 32) == 0, this_file);
COMMON_COMPILE_TIME_ASSERT(((sizeof(gWorkBuffs.aad) + sizeof(gWorkBuffs.len)) % 32) == 0, this_file);

#define AlignedIV   gWorkBuffs.ctx.bytes
#define AlignedKey  gWorkBuffs.key_256bits
#define AlignedHmac gWorkBuffs.opad
#define AlignedHash gWorkBuffs.opad
#define AlignedAAD  gWorkBuffs.aad
#define AlignedLen  gWorkBuffs.len
#define GCM_CTX     gWorkBuffs.ctx.aes_gcm_le
#define CTR_CTX     gWorkBuffs.ctx.aes_ctr_le

/**
 * Perform a memcpy operation through CCP. This requires the source and destination
 * address to be in CCP_MEM_LOCAL (i.e. mapped as PSP 32bit virtual address)
 */
static sev_status_t memcpy_ccp(void *pDest, void *pSource, uint32_t size)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    bl_ccp_cmd_desc cmds;
    bl_ccp_cmd_desc *pCcpCmd = &cmds;

    uint32_t eids = 0;
    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCcpCmd->cmd0.fields.hoc = 0;
    pCcpCmd->cmd0.fields.ioc = 1;  // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som = 0;  // 1;
    pCcpCmd->cmd0.fields.eom = 1;
    pCcpCmd->cmd0.fields.prot = 0;
    pCcpCmd->cmd0.fields.engine = CCP_ENGINE_PT;
    pCcpCmd->cmd0.fields.function = 0;

    pCcpCmd->cmd1.length = size;

    pCcpCmd->cmd2.source_pointer_lo = ADDRESS_LO(pSource);
    pCcpCmd->cmd3.fields.source_pointer_hi = 0;
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id = 0;

    pCcpCmd->cmd4.dest_pointer_lo = ADDRESS_LO(pDest);
    pCcpCmd->cmd5.fields.dest_pointer_hi = 0;
    pCcpCmd->cmd5.fields.dest_mem = CCP_MEM_LOCAL;

    /* No need to wait for CCP to complete the command, so we can continue. */
    status = sev_hal_enqueue_and_run_commands(&cmds, &eids, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Wait for HMAC commands to complete */
    status = sev_hal_query_commands(&eids, 1, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

end:
    return status;
}

static void BuildCmd_Aes128Ctr(bl_ccp_cmd_desc *pCcpCmd,
                               uint8_t *pDataOut,
                               const uint8_t *pDataIn,
                               size_t DataSize)
{
    ccp_function fun;

    /* AES Engine specific settings */
    fun.raw          = 0;
    fun.aes.size     = (AES_BLOCKLEN * 8) - 1; /* Special setting for CTR mode on CCP5.0 */
    fun.aes.encrypt  = 1;                    /* Either 1 (encrypt) or 0 (decrypt) */
    fun.aes.mode     = CCP_AES_MODE_CTR;
    fun.aes.key_size = CCP_AES_KEY_SIZE_128;

    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCcpCmd->cmd0.fields.hoc      = 0;
    pCcpCmd->cmd0.fields.ioc      = 0; // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som      = 1;
    pCcpCmd->cmd0.fields.eom      = 1;
    pCcpCmd->cmd0.fields.prot     = 1;
    pCcpCmd->cmd0.fields.engine   = CCP_ENGINE_AES;
    pCcpCmd->cmd0.fields.function = fun.raw;

    pCcpCmd->cmd1.length          = DataSize;

    // Source parameters
    pCcpCmd->cmd2.source_pointer_lo        = ADDRESS_LO(pDataIn);
    pCcpCmd->cmd3.fields.source_pointer_hi = ADDRESS_HI(pDataIn);
    pCcpCmd->cmd3.fields.source_mem        = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id    = LSB_SEV_AESIV;

    // Destination parameters
    pCcpCmd->cmd4.dest_pointer_lo        = ADDRESS_LO(pDataOut);
    pCcpCmd->cmd5.fields.dest_pointer_hi = ADDRESS_HI(pDataOut);
    pCcpCmd->cmd5.fields.dest_mem        = CCP_MEM_LOCAL;

    // Key parameters
    pCcpCmd->cmd6.key_pointer_lo        = LSB_SEV_AESKEY << LSB_SHIFT_PER_SLOT;
    pCcpCmd->cmd7.fields.key_pointer_hi = 0;
    pCcpCmd->cmd7.fields.key_mem        = CCP_MEM_LSB;
}

static void BuildCmd_CryptoPtToLsb(bl_ccp_cmd_desc *pCcpCmd,
                                   uint32_t LsbSlotDest,
                                   const uint8_t *pSource,
                                   size_t DataLength,
                                   uint32_t BSwp)
{
    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCcpCmd->cmd0.fields.hoc      = 0;
    pCcpCmd->cmd0.fields.ioc      = 0; // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som      = 0; // 1;
    pCcpCmd->cmd0.fields.eom      = 1;
    pCcpCmd->cmd0.fields.prot     = 0;
    pCcpCmd->cmd0.fields.engine   = CCP_ENGINE_PT;
    pCcpCmd->cmd0.fields.function = BSwp;

    pCcpCmd->cmd1.length = DataLength;

    pCcpCmd->cmd2.source_pointer_lo = ADDRESS_LO(pSource);
    pCcpCmd->cmd3.fields.source_pointer_hi = ADDRESS_HI(pSource);
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id = 0;

    pCcpCmd->cmd4.dest_pointer_lo = LsbSlotDest << LSB_SHIFT_PER_SLOT; /* LSB slot# */
    pCcpCmd->cmd5.fields.dest_pointer_hi = 0;
    pCcpCmd->cmd5.fields.dest_mem = CCP_MEM_LSB;
}

static void BuildCmd_CryptoPtFromLsb(bl_ccp_cmd_desc *pCcpCmd,
                                     uint8_t *pDest,
                                     uint32_t LsbSlotSource,
                                     size_t DataLength,
                                     uint32_t BSwp)
{
    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCcpCmd->cmd0.fields.hoc      = 0;
    pCcpCmd->cmd0.fields.ioc      = 0; // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som      = 0; // 1;
    pCcpCmd->cmd0.fields.eom      = 1;
    pCcpCmd->cmd0.fields.prot     = 0;
    pCcpCmd->cmd0.fields.engine   = CCP_ENGINE_PT;
    pCcpCmd->cmd0.fields.function = BSwp;

    pCcpCmd->cmd1.length = DataLength;

    pCcpCmd->cmd2.source_pointer_lo = LsbSlotSource << LSB_SHIFT_PER_SLOT; /* LSB slot# */
    pCcpCmd->cmd3.fields.source_pointer_hi = 0;
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LSB;
    pCcpCmd->cmd3.fields.lsb_context_id = 0;

    pCcpCmd->cmd4.dest_pointer_lo = ADDRESS_LO(pDest);
    pCcpCmd->cmd5.fields.dest_pointer_hi = ADDRESS_HI(pDest);
    pCcpCmd->cmd5.fields.dest_mem = CCP_MEM_LOCAL;
}

static __align(32) const uint32_t SHA_256_INIT_VECTOR[] =
{
    0x5BE0CD19, 0x1F83D9AB, 0x9B05688C, 0x510E527F,
    0xA54FF53A, 0x3C6EF372, 0xBB67AE85, 0x6A09E667
};

static void BuildCmd_Sha256Init(bl_ccp_cmd_desc *pCcpCmd)
{
    BuildCmd_CryptoPtToLsb(pCcpCmd, LSB_SEV_SHA, (uint8_t *)SHA_256_INIT_VECTOR, 32, PASSTHROUGH_NO_SWAP);
}

static void BuildCmd_Sha256Update(bl_ccp_cmd_desc *pCcpCmd,
                                  const uint8_t *pMsg,
                                  size_t MsgBytes)
{
    ccp_function sha_fun;

    /* SHA Engine specific settings */
    sha_fun.raw = 0;
    sha_fun.sha.type = CCP_SHA_TYPE_256;

    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    pCcpCmd->cmd0.fields.hoc      = 0;
    pCcpCmd->cmd0.fields.ioc      = 0; // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som      = 1;
    pCcpCmd->cmd0.fields.eom      = 0;
    pCcpCmd->cmd0.fields.engine   = CCP_ENGINE_SHA;
    pCcpCmd->cmd0.fields.function = sha_fun.raw;

    pCcpCmd->cmd1.length = MsgBytes;

    /* Source parameters */
    pCcpCmd->cmd2.source_pointer_lo = ADDRESS_LO(pMsg);
    pCcpCmd->cmd3.fields.source_pointer_hi = ADDRESS_HI(pMsg);
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id = LSB_SEV_SHA;
}

static void BuildCmd_Sha256Final(bl_ccp_cmd_desc *pCcpCmd,
                                 const uint8_t *pMsg,
                                 size_t MsgBytes,
                                 size_t TotalMsgBytes)
{
    ccp_function sha_fun;

    /* SHA Engine specific settings */
    sha_fun.raw = 0;
    sha_fun.sha.type = CCP_SHA_TYPE_256;

    /* Prepare cmd_ctrl */
    memset(pCcpCmd, 0, sizeof(bl_ccp_cmd_desc));

    pCcpCmd->cmd0.fields.hoc = 0;
    pCcpCmd->cmd0.fields.ioc = 0; // DEFAULT_IOC;
    pCcpCmd->cmd0.fields.som = 1;
    pCcpCmd->cmd0.fields.eom = 1;
    pCcpCmd->cmd0.fields.engine = CCP_ENGINE_SHA;
    pCcpCmd->cmd0.fields.function = sha_fun.raw;

    pCcpCmd->cmd1.length = MsgBytes;

    /* Source parameters */
    pCcpCmd->cmd2.source_pointer_lo = ADDRESS_LO(pMsg);
    pCcpCmd->cmd3.fields.source_pointer_hi = ADDRESS_HI(pMsg);
    pCcpCmd->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCcpCmd->cmd3.fields.lsb_context_id = LSB_SEV_SHA;

    pCcpCmd->cmd4.sha_length_lo = TotalMsgBytes << 3; /* In bits */
    pCcpCmd->cmd5.sha_length_hi = TotalMsgBytes >> 29;
}

static sev_status_t BuildCmd_Sha256Hmac(bl_ccp_cmd_desc *pCmds,
                                        const uint8_t *pKey, size_t KeySize,
                                        const uint8_t *pAAD, size_t AadSize,
                                        const uint8_t *pMsg, size_t MsgSize)
{
    size_t i = 0;
    size_t pad_size = 0;

    if (pKey == NULL || pMsg == NULL || (AadSize > 0 && pAAD == NULL))
    {
        return ERR_INVALID_PARAMS;
    }

    if (KeySize > HMAC_SHA256_BLOCK_SIZE_BYTES ||
        AadSize > HMAC_SHA256_BLOCK_SIZE_BYTES ||
        MsgSize < (HMAC_SHA256_BLOCK_SIZE_BYTES - AadSize))
    {
        return ERR_INVALID_PARAMS;
    }

    /* Calculate i_pad: Key XOR ipad (0x36). Key is zero-padded. */
    /* Calculate o_pad: Key XOR opad (0x5C). Key is zero-padded. */
    memset(gWorkBuffs.opad, 0x5C, HMAC_SHA256_BLOCK_SIZE_BYTES);
    memset(gWorkBuffs.ipad, 0x36, HMAC_SHA256_BLOCK_SIZE_BYTES);
    for (i = 0; i < KeySize; i++)
    {
        gWorkBuffs.ipad[i] ^= pKey[i];
        gWorkBuffs.opad[i] ^= pKey[i];
    }

    /*
     * Append hmac meta-data
     * We are using &gWorkBuffs.ipad[HMAC_SHA256_BLOCK_SIZE_BYTES] instead
     * of using gWorkBuffs.aad. This is to allow gWorkBuffs array sizes to
     * grow for support of SHA384/512.
     */
    memcpy(&gWorkBuffs.ipad[HMAC_SHA256_BLOCK_SIZE_BYTES], pAAD, AadSize);
    /* Make buffer HMAC_SHA256_BLOCK_SIZE_BYTES aligned */
    pad_size = HMAC_SHA256_BLOCK_SIZE_BYTES - AadSize;
    memcpy(&gWorkBuffs.ipad[HMAC_SHA256_BLOCK_SIZE_BYTES + AadSize], pMsg, pad_size);
    pMsg += pad_size;
    MsgSize -= pad_size;

    /* H(ipad || AAD || MSG) */
    BuildCmd_Sha256Init(pCmds);
    BuildCmd_Sha256Update(pCmds + 1,
                          gWorkBuffs.ipad,
                          HMAC_SHA256_BLOCK_SIZE_BYTES * 2); /* ipad || AAD */

    BuildCmd_Sha256Final(pCmds + 2,
                         pMsg,
                         MsgSize,
                         MsgSize + HMAC_SHA256_BLOCK_SIZE_BYTES * 2); /* Total msg size */
    /* CSF-1693: Genoa CCP HW issue, cannot have SOM=1 followed by another SOM=1 without EOM=1
       in between.   It needs to have SOM=1 for the FIRST BuildCmd_Sha256Update or BuildCmd_Sha256Final,
       and SOM must be 0 after. */
    pCmds[2].cmd0.fields.som = 0;

    /* Get digest (append it to OPAD) */
    BuildCmd_CryptoPtFromLsb(pCmds + 3,
                             gWorkBuffs.opad + HMAC_SHA256_BLOCK_SIZE_BYTES,
                             LSB_SEV_SHA,
                             HMAC_SHA256_SIZE_BYTES,
                             PASSTHROUGH_SWAP_256_BITS);

    /* H(opad || H(ipad || AAD || MSG)) */
    BuildCmd_Sha256Init(pCmds + 4);
    BuildCmd_Sha256Final(pCmds + 5,
                         gWorkBuffs.opad, /* opad || H(ipad...) */
                         HMAC_SHA256_BLOCK_SIZE_BYTES + HMAC_SHA256_SIZE_BYTES,
                         HMAC_SHA256_BLOCK_SIZE_BYTES + HMAC_SHA256_SIZE_BYTES); /* Total msg size */

    // Get final HMAC
    BuildCmd_CryptoPtFromLsb(pCmds + 6,
                             AlignedHmac,
                             LSB_SEV_SHA,
                             HMAC_SHA256_SIZE_BYTES,
                             PASSTHROUGH_SWAP_256_BITS);

    return SEV_STATUS_SUCCESS;
}

/**
 * This interface expects following LSB's:
 *      LSB_SEV_AESIV   IV in lower 128-bits and GHASH in upper 128-bits
 *      LSB_SEV_AESKEY  AES-256 key
 */
static void BuildCmd_Aes256GCTR(bl_ccp_cmd_desc *pCmds,
                                const uint8_t *pMsg, size_t MsgSize,
                                uint8_t *pOut,
                                int Encrypt)
{
    ccp_function fun;

    /* AES Engine specific settings */
    fun.raw          = 0;
    fun.aes.size     = (AES_BLOCKLEN * 8) - 1; /* Special setting for GCTR mode when eom=1 */
    fun.aes.encrypt  = Encrypt;              /* Either 1 (encrypt) or 0 (decrypt) */
    fun.aes.mode     = CCP_AES_MODE_GCTR;
    fun.aes.key_size = CCP_AES_KEY_SIZE_256;

    /* Prepare cmd_ctrl */
    memset(pCmds, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCmds->cmd0.fields.hoc      = 0;
    pCmds->cmd0.fields.ioc      = 0; // DEFAULT_IOC;
    // From ccp_test.c:
    /* Init is always passed in as 0 since we are using the context from GHASH */
    pCmds->cmd0.fields.som      = 0;
    pCmds->cmd0.fields.eom      = 1;
    pCmds->cmd0.fields.prot     = 1;
    pCmds->cmd0.fields.engine   = CCP_ENGINE_AES;
    pCmds->cmd0.fields.function = fun.raw;

    pCmds->cmd1.length          = MsgSize;

    /* Source parameters */
    pCmds->cmd2.source_pointer_lo = ADDRESS_LO(pMsg);
    pCmds->cmd3.fields.source_pointer_hi = ADDRESS_HI(pMsg);
    pCmds->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCmds->cmd3.fields.lsb_context_id = LSB_SEV_AESIV;

    /* Destination parameters */
    pCmds->cmd4.dest_pointer_lo = ADDRESS_LO(pOut);
    pCmds->cmd5.fields.dest_pointer_hi = ADDRESS_HI(pOut);
    pCmds->cmd5.fields.dest_mem = CCP_MEM_LOCAL;

    /* Key parameters */
    pCmds->cmd6.key_pointer_lo = LSB_SEV_AESKEY << LSB_SHIFT_PER_SLOT;
    pCmds->cmd7.fields.key_pointer_hi = 0;
    pCmds->cmd7.fields.key_mem = CCP_MEM_LSB;
}

static void BuildCmd_Aes256GHASH(bl_ccp_cmd_desc *pCmds,
                                 const uint8_t *pMsg, size_t MsgSize,
                                 uint8_t *pOut,
                                 int Init,
                                 int Finish)
{
    ccp_function fun;

    /* AES Engine specific settings */
    fun.raw          = 0;
    fun.aes.encrypt  = Finish; // 0=GHASH-AAD, 1=GHASH-Final
    fun.aes.mode     = CCP_AES_MODE_GHASH;
    fun.aes.key_size = CCP_AES_KEY_SIZE_256;

    /* Prepare cmd_ctrl */
    memset(pCmds, 0, sizeof(bl_ccp_cmd_desc));

    /* Command parameters */
    pCmds->cmd0.fields.hoc      = 0;
    pCmds->cmd0.fields.ioc      = 0; // DEFAULT_IOC;
    pCmds->cmd0.fields.som      = Init;
    pCmds->cmd0.fields.eom      = Finish;
    pCmds->cmd0.fields.prot     = 1;
    pCmds->cmd0.fields.engine   = CCP_ENGINE_AES;
    pCmds->cmd0.fields.function = fun.raw;

    pCmds->cmd1.length          = MsgSize;

    /* Source parameters */
    pCmds->cmd2.source_pointer_lo = ADDRESS_LO(pMsg);
    pCmds->cmd3.fields.source_pointer_hi = ADDRESS_HI(pMsg);
    pCmds->cmd3.fields.source_mem = CCP_MEM_LOCAL;
    pCmds->cmd3.fields.lsb_context_id = LSB_SEV_AESIV;

    /* Destination parameters */
    if (pOut)
    {
        pCmds->cmd4.dest_pointer_lo = ADDRESS_LO(pOut);
        pCmds->cmd5.fields.dest_pointer_hi = ADDRESS_HI(pOut);
        pCmds->cmd5.fields.dest_mem = CCP_MEM_LOCAL;
    }

    /* Key parameters */
    pCmds->cmd6.key_pointer_lo = LSB_SEV_AESKEY << LSB_SHIFT_PER_SLOT;
    pCmds->cmd7.fields.key_pointer_hi = 0;
    pCmds->cmd7.fields.key_mem = CCP_MEM_LSB;
}

static void SWAP_16(const uint8_t *src, uint8_t *dst)
{
    uint32_t i = 0;
    for (i = 0; i < 16; i++)
    {
        dst[i] = src[15 - i];
    }
}

sev_status_t aesctr_hmac256_encrypt(const uint8_t *pEncKey, size_t EncKeySize,
                                    const uint8_t *pMacKey, size_t MacKeySize,
                                    const uint8_t *pAAD, size_t AADSize,
                                    const uint8_t *pMsg, size_t MsgSize,
                                    uint8_t *pOut,
                                    uint8_t *pIV,
                                    uint8_t *pHmac)
{
    sev_status_t status;
    bl_ccp_cmd_desc cmds[10];
    uint32_t eids[10];

    if (!pEncKey || !pMacKey || !pAAD || !pMsg || !pOut || !pIV || !pHmac)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }
    if (MsgSize == 0 || (MsgSize & 15) != 0 || AADSize > 64)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_trng(pIV, 16);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    SWAP_16(pIV, AlignedIV);
    SWAP_16(pEncKey, AlignedKey);

    /*
     * CcpVcqCmdEnqueue() takes care of input and output addresses in term of cache
     * operations and address translation but no action is taken for AES keys addresses.
     * To make sure AES keys are properly dealt with, we load it into a LSB slot.
     */
    BuildCmd_CryptoPtToLsb(cmds,
                           LSB_SEV_AESKEY,
                           AlignedKey, // SWAP_16(pEncKey)
                           16,
                           PASSTHROUGH_NO_SWAP);

    // Load IV in the context LSB
    BuildCmd_CryptoPtToLsb(cmds + 1,
                           LSB_SEV_AESIV,
                           AlignedIV, // SWAP_16(pIV)
                           16,
                           PASSTHROUGH_NO_SWAP);

    BuildCmd_Aes128Ctr(cmds + 2,
                       pOut,
                       pMsg,
                       MsgSize);

    cmds[2].cmd0.fields.ioc = 1; /* Interrupt on completion of last command */

    /* Enqueue and run commands but do not wait for completion */
    status = sev_hal_enqueue_and_run_commands(cmds, eids, 3);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* While AES is running, prepare for HMAC operations */
    status = BuildCmd_Sha256Hmac(cmds + 3, /* fills in 7 entries */
                                 pMacKey, MacKeySize,
                                 pAAD, AADSize,
                                 pOut, MsgSize);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    cmds[9].cmd0.fields.hoc = DEFAULT_SOC; /* Stop on completion of last command */
    cmds[9].cmd0.fields.ioc = 1;           /* Interrupt on completion of last command */

    /* No need to wait for CCP to complete the command, so we can continue */
    status = sev_hal_enqueue_and_run_commands(cmds + 3, eids + 3, 7);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Wait for HMAC commands to complete */
    status = sev_hal_query_commands(eids, 10, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memcpy(pHmac, AlignedHmac, 32);

end:
    return status;
}

sev_status_t aesctr_hmac256_decrypt(const uint8_t *pEncKey, size_t EncKeySize,
                                    const uint8_t *pMacKey, size_t MacKeySize,
                                    const uint8_t *pAAD, size_t AADSize,
                                    const uint8_t *pMsg, size_t MsgSize,
                                    uint8_t *pOut,
                                    const uint8_t *pIV,
                                    const uint8_t *pHmac)
{
    sev_status_t status;
    bl_ccp_cmd_desc cmds[10];
    uint32_t eids[10];

    if (!pEncKey || !pMacKey || !pAAD || !pMsg || !pOut || !pIV || !pHmac)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }
    if (MsgSize == 0 || (MsgSize & 15) != 0 || AADSize > 64)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = BuildCmd_Sha256Hmac(cmds, /* Fills in 7 entries */
                                 pMacKey, MacKeySize,
                                 pAAD, AADSize,
                                 pOut, MsgSize);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    cmds[6].cmd0.fields.hoc = DEFAULT_SOC; /* Stop on completion of last command */
    cmds[6].cmd0.fields.ioc = 1;           /* Interrupt on completion of last command */

    status = sev_hal_enqueue_and_run_commands(cmds, eids, 7);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Do some work while HMAC is being calculated */

    SWAP_16(pIV, AlignedIV);
    SWAP_16(pEncKey, AlignedKey);

    /*
     * CcpVcqCmdEnqueue() takes care of input and output addresses in term of cache
     * operations and address translation. To make sure AES keys are properly dealt
     * with, we load it into a LSB slot.
     */
    BuildCmd_CryptoPtToLsb(cmds + 7,
                           LSB_SEV_AESKEY,
                           AlignedKey, // SWAP_16(pEncKey)
                           16,
                           PASSTHROUGH_NO_SWAP);

    // Move the IV to the context LSB
    BuildCmd_CryptoPtToLsb(cmds + 8,
                           LSB_SEV_AESIV,
                           AlignedIV, // SWAP_16(pIV)
                           16,
                           PASSTHROUGH_NO_SWAP);

    BuildCmd_Aes128Ctr(cmds + 9,
                       pOut,
                       pMsg,
                       MsgSize);

    cmds[9].cmd0.fields.hoc = DEFAULT_SOC; /* Stop on completion of last command */
    cmds[9].cmd0.fields.ioc = 1;           /* Interrupt on completion of last command */

    /* Wait for HMAC commands to complete */
    status = sev_hal_query_commands(eids, 7, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Verify hmac */
    if (secure_compare(pHmac, AlignedHmac, 32) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
        goto end;
    }

    /* Ciphertext integrity verified. Decrypt it now */

    status = sev_hal_enqueue_and_run_commands(cmds + 7, eids + 7, 3);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    /* Wait for AES commands to complete */
    status = sev_hal_query_commands(eids + 7, 3, 1);

end:
    return status;
}

// --------------------------------------------------------------------------
// Important notes:
// --------------------------------------------------------------------------
// pIV is pointing to a 64-bit big-endian IV
sev_status_t aes256gcm_authenticated_encrypt(const uint8_t *pKey, size_t KeySize,
                                             const uint8_t *pAAD, size_t AADSize,
                                             const uint8_t *pMsg, size_t MsgSize,
                                             uint8_t *pOut,
                                             const uint8_t *pIV, size_t IVSize,
                                             uint8_t *pTag)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bl_ccp_cmd_desc cmds[6];
    uint32_t eids[6];
    size_t i;
    uint32_t command_count = 0;

    // --------------------------------------------------
    // gWorkBuffs usage:
    // --------------------------------usage-------------
    // [32] GCM_CTX     AlignedIV  --> iv[16], ghash[16]
    // [32] Key32       AlignedKey --> key[32]
    // [64] opad
    // [64] ipad
    // [64] aad,len     AlignedAAD --> AAD[48], LENs[16]
    if (!pKey || !pMsg || !pOut || !pIV || !pTag || (AADSize && !pAAD) || (!AADSize && pAAD))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (KeySize != 32 || MsgSize == 0 || (MsgSize & 15) != 0 ||
        AADSize > sizeof(AlignedAAD) || IVSize < 8 || IVSize > 16)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    GCM_CTX.j0.ext32 = GCM_IV_PAD;
    GCM_CTX.j0.cnt32 = 1;
    for (i = 0; i < IVSize; i++)
    {
        AlignedIV[15 - i] = pIV[i];
    }

    // Load key into a LSB slot.
    memcpy(AlignedKey, pKey, 32);
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESKEY,
                           AlignedKey,
                           32,
                           PASSTHROUGH_SWAP_256_BITS);
    command_count++;

    // Load IV(for GCTR)
    // Setup context LSB as defined in CCP TRM: GHASH_CTX in upper 128-bits and IV in lower 128
    memset(GCM_CTX.ghash, 0, 16); // @AlignedIV+16
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           32,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    if (AADSize != 0)
    {
        // Use upper 16 bytes of gWorkBuffs.aad for LENs and lower 48 as 0-padded AAD
        memset(AlignedAAD, 0, sizeof(AlignedAAD) + sizeof(AlignedLen));
        memcpy(AlignedAAD, pAAD, AADSize);
        BuildCmd_Aes256GHASH(cmds + command_count,
                             AlignedAAD, (AADSize + 15) & ~15, // AAD || 0-pad
                             NULL,                             // AAD mode
                             1,                                // Init
                             0);                               // Finish
        command_count++;
    }

    // Encrypt and update GHASH
    BuildCmd_Aes256GCTR(cmds + command_count,
                        pMsg, MsgSize, // Plaintext
                        pOut,          // Ciphertext
                        1);            // Encrypt

    // cmds[command_count].cmd0.fields.hoc = DEFAULT_SOC;     // stop on completion of last command
    cmds[command_count].cmd0.fields.ioc = 1; // interrupt on completion of last command
    command_count++;

    status = sev_hal_enqueue_and_run_commands(cmds, eids, command_count);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Prepare GHASH-Final sub-commands while GCTR is running

    // [len64(AAD) || len64(MSG)]
    AlignedLen[6]  = (uint8_t)(AADSize >>  5);
    AlignedLen[7]  = (uint8_t)(AADSize <<  3);
    AlignedLen[12] = (uint8_t)(MsgSize >> 21);
    AlignedLen[13] = (uint8_t)(MsgSize >> 13);
    AlignedLen[14] = (uint8_t)(MsgSize >>  5);
    AlignedLen[15] = (uint8_t)(MsgSize <<  3);

    // Reload IV (for GHASH-Final)
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           16,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    BuildCmd_Aes256GHASH(cmds + command_count,
                         AlignedLen, 16, // len(AAD) || len(Msg)
                         GCM_CTX.ghash,
                         0,  // Init
                         1); // Finish (GHASH-Final)

    cmds[command_count].cmd0.fields.hoc = DEFAULT_SOC; /* stop on completion of last command */
    cmds[command_count].cmd0.fields.ioc = 1;           /* interrupt on completion of last command */
    command_count++;

    status = sev_hal_enqueue_and_run_commands(cmds + command_count-2, eids + command_count-2, 2);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Wait for GHASH to complete

    status = sev_hal_query_commands(eids, command_count, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    memcpy(pTag, GCM_CTX.ghash, 16);

end:
    return status;
}

/* Used for SwapOut */
sev_status_t aes256gcm_authenticated_encrypt_x86addr(const uint8_t *pKey, size_t KeySize,
                                                     const uint8_t *pAAD, size_t AADSize,
                                                     const uint64_t MsgAddr, size_t MsgSize,
                                                     const uint64_t OutAddr,
                                                     const uint8_t *pIV, size_t IVSize,
                                                     uint8_t *pTag,
                                                     uint32_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bl_ccp_cmd_desc cmds[6];
    uint32_t eids[6];
    size_t i;
    uint32_t command_count = 0;
    uint8_t *pMsg = NULL;
    uint8_t *pOut = NULL;
    void *msg_x86_buffer = NULL;
    void *out_x86_buffer = NULL;
    void *scratch_dram = NULL;

    // --------------------------------------------------
    // gWorkBuffs usage:
    // --------------------------------usage-------------
    // [32] GCM_CTX     AlignedIV  --> iv[16], ghash[16]
    // [32] Key32       AlignedKey --> key[32]
    // [64] opad
    // [64] ipad
    // [64] aad,len     AlignedAAD --> AAD[48], LENs[16]
    if (!pKey || !pIV || !pTag || (AADSize && !pAAD) || (!AADSize && pAAD))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (KeySize != 32 || MsgSize == 0 || (MsgSize & 15) != 0 ||
        AADSize > sizeof(AlignedAAD) || IVSize < 8 || IVSize > 16)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_map_memory_ccp_asid(MsgAddr, &msg_x86_buffer, MsgSize, asid);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;
    status = sev_hal_map_memory_ccp(OutAddr, &out_x86_buffer, MsgSize);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /*
     * Copy to PSP DRAM and use that as src address to prevent
     * double-fetches/race conditions from ccp functions
     */
    status = sev_hal_get_dram_2mb((void **)&scratch_dram);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    memcpy_ccp(scratch_dram, msg_x86_buffer, MsgSize);

    /* Set the source address using the 2mb scratch location */
    pMsg = (uint8_t *)scratch_dram; //msg_x86_buffer;
    pOut = (uint8_t *)out_x86_buffer;

    GCM_CTX.j0.ext32 = GCM_IV_PAD;
    GCM_CTX.j0.cnt32 = 1;
    for (i = 0; i < IVSize; i++)
    {
        AlignedIV[15 - i] = pIV[i];
    }

    // Load key into a LSB slot.
    memcpy(AlignedKey, pKey, 32);
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESKEY,
                           AlignedKey,
                           32,
                           PASSTHROUGH_SWAP_256_BITS);
    command_count++;

    // Load IV(for GCTR)
    // Setup context LSB as defined in CCP TRM: GHASH_CTX in upper 128-bits and IV in lower 128
    memset(GCM_CTX.ghash, 0, 16); // @AlignedIV+16
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           32,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    if (AADSize != 0)
    {
        // Use upper 16 bytes of gWorkBuffs.aad for LENs and lower 48 as 0-padded AAD
        memset(AlignedAAD, 0, sizeof(AlignedAAD) + sizeof(AlignedLen));
        memcpy(AlignedAAD, pAAD, AADSize);
        BuildCmd_Aes256GHASH(cmds + command_count,
                             AlignedAAD, (AADSize + 15) & ~15, // AAD || 0-pad
                             NULL,                             // AAD mode
                             1,                                // Init
                             0);                               // Finish
        command_count++;
    }

    // Encrypt and update GHASH
    BuildCmd_Aes256GCTR(cmds + command_count,
                        pMsg, MsgSize, // Plaintext
                        pOut,          // Ciphertext
                        1);            // Encrypt

    // cmds[command_count].cmd0.fields.hoc = DEFAULT_SOC;     // stop on completion of last command
    cmds[command_count].cmd0.fields.ioc = 1; // interrupt on completion of last command
    command_count++;

    status = sev_hal_enqueue_and_run_commands(cmds, eids, command_count);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    // Prepare GHASH-Final sub-commands while GCTR is running

    // [len64(AAD) || len64(MSG)]
    AlignedLen[6]  = (uint8_t)(AADSize >>  5);
    AlignedLen[7]  = (uint8_t)(AADSize <<  3);
    AlignedLen[12] = (uint8_t)(MsgSize >> 21);
    AlignedLen[13] = (uint8_t)(MsgSize >> 13);
    AlignedLen[14] = (uint8_t)(MsgSize >>  5);
    AlignedLen[15] = (uint8_t)(MsgSize <<  3);

    // Reload IV (for GHASH-Final)
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           16,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    BuildCmd_Aes256GHASH(cmds + command_count,
                         AlignedLen, 16, // len(AAD) || len(Msg)
                         GCM_CTX.ghash,
                         0,  // Init
                         1); // Finish (GHASH-Final)

    cmds[command_count].cmd0.fields.hoc = DEFAULT_SOC; // stop on completion of last command
    cmds[command_count].cmd0.fields.ioc = 1;           // interrupt on completion of last command
    command_count++;

    status = sev_hal_enqueue_and_run_commands(cmds + command_count-2, eids + command_count-2, 2);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    // Wait for GHASH to complete

    status = sev_hal_query_commands(eids, command_count, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    memcpy(pTag, GCM_CTX.ghash, 16);

unmap:
    sev_hal_unmap_memory(out_x86_buffer);
    sev_hal_unmap_memory(msg_x86_buffer);
end:
    return status;
}

// --------------------------------------------------------------------------
// Important notes:
// --------------------------------------------------------------------------
// pIV is pointing to a 64-bit big-endian IV
sev_status_t aes256gcm_authenticated_decrypt(const uint8_t *pKey, size_t KeySize,
                                             const uint8_t *pAAD, size_t AADSize,
                                             const uint8_t *pMsg, size_t MsgSize,
                                             uint8_t *pOut,
                                             const uint8_t *pIV, size_t IVSize,
                                             const uint8_t *pTag)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bl_ccp_cmd_desc cmds[6];
    uint32_t eids[6];
    size_t i = 0;
    uint32_t command_count = 0;

    // --------------------------------------------------
    // gWorkBuffs usage:
    // --------------------------------usage-------------
    // [32] GCM_CTX     AlignedIV  --> iv[16], ghash[16]
    // [32] Key32       AlignedKey --> key[32]
    // [64] opad
    // [64] ipad
    // [64] aad,len     AlignedAAD --> AAD[48], LENs[16]

    if (!pKey || !pMsg || !pOut || !pIV || !pTag || (AADSize && !pAAD) || (!AADSize && pAAD))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (KeySize != 32 || MsgSize == 0 || (MsgSize & 15) != 0 ||
        AADSize > sizeof(AlignedAAD) || IVSize < 8 || IVSize > 16)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    GCM_CTX.j0.ext32 = GCM_IV_PAD;
    GCM_CTX.j0.cnt32 = 1;
    for (i = 0; i < IVSize; i++)
    {
        AlignedIV[15 - i] = pIV[i];
    }

    memset(GCM_CTX.ghash, 0, 16);

    // Load key into a LSB slot.
    memcpy(AlignedKey, pKey, 32);
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESKEY,
                           AlignedKey,
                           32,
                           PASSTHROUGH_SWAP_256_BITS);
    command_count++;

    // Load IV (for GHASH/GCTR)
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           32,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    if (AADSize != 0)
    {
        // Use lower 16 bytes of gWorkBuffs.aad for LENs and upper 48 as 0-padded AAD
        memset(AlignedAAD, 0, sizeof(AlignedAAD) + sizeof(AlignedLen));
        memcpy(AlignedAAD, pAAD, AADSize);
        BuildCmd_Aes256GHASH(cmds + command_count,
                             AlignedAAD, (AADSize + 15) & ~15, // AAD || 0-pad
                             NULL,
                             1,  // Init
                             0); // !Finish
        command_count++;
    }

    BuildCmd_Aes256GCTR(cmds + command_count,
                        pMsg, MsgSize, // Plaintext
                        pOut,          // Ciphertext
                        0);            // !Encrypt
    command_count++;

    // [len64(AAD) || len64(MSG)]
    AlignedLen[6]  = (uint8_t)(AADSize >> 5);
    AlignedLen[7]  = (uint8_t)(AADSize << 3);

    AlignedLen[12] = (uint8_t)(MsgSize >> 21);
    AlignedLen[13] = (uint8_t)(MsgSize >> 13);
    AlignedLen[14] = (uint8_t)(MsgSize >> 5);
    AlignedLen[15] = (uint8_t)(MsgSize << 3);

    // Reload IV(for GHASH-Final)
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           16,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    BuildCmd_Aes256GHASH(cmds + command_count,
                         AlignedLen, 16, // len(AAD) || len(Msg)
                         GCM_CTX.ghash,
                         0,  // Init
                         1); // Finish

    cmds[command_count].cmd0.fields.hoc = DEFAULT_SOC; // stop on completion of last command
    cmds[command_count].cmd0.fields.ioc = 1;           // interrupt on completion of last command
    command_count++;

    status = sev_hal_enqueue_and_run_commands(cmds, eids, command_count);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Wait for commands to complete
    status = sev_hal_query_commands(eids, command_count, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Validate calculated tag against expected value
    if (secure_compare(pTag, GCM_CTX.ghash, 16) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
    }

end:
    return status;
}

/* Used for SwapIn */
/* Always preceed with set_misc_read_sized_wrbkinvd() */
sev_status_t aes256gcm_authenticated_decrypt_x86addr(const uint8_t *pKey, size_t KeySize,
                                                     const uint8_t *pAAD, size_t AADSize,
                                                     const uint64_t MsgAddr, size_t MsgSize,
                                                     const uint64_t OutAddr,
                                                     const uint8_t *pIV, size_t IVSize,
                                                     const uint8_t *pTag,
                                                     uint32_t asid)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bl_ccp_cmd_desc cmds[6];
    uint32_t eids[6];
    size_t i = 0;
    uint32_t command_count = 0;
    uint8_t *pMsg = NULL;
    uint8_t *pOut = NULL;
    void *msg_x86_buffer = NULL;
    void *out_x86_buffer = NULL;
    void *scratch_dram = NULL;
    uint64_t dst_addr = OutAddr;

    // --------------------------------------------------
    // gWorkBuffs usage:
    // --------------------------------usage-------------
    // [32] GCM_CTX     AlignedIV  --> iv[16], ghash[16]
    // [32] Key32       AlignedKey --> key[32]
    // [64] opad
    // [64] ipad
    // [64] aad,len     AlignedAAD --> AAD[48], LENs[16]

    if (!pKey || !pIV || !pTag || (AADSize && !pAAD) || (!AADSize && pAAD))
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    if (KeySize != 32 || MsgSize == 0 || (MsgSize & 15) != 0 ||
        AADSize > sizeof(AlignedAAD) || IVSize < 8 || IVSize > 16)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = sev_hal_map_memory_ccp(MsgAddr, &msg_x86_buffer, MsgSize);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;
    status = sev_hal_map_memory_ccp_asid(OutAddr, &out_x86_buffer, MsgSize, asid);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /*
     * Map to PSP DRAM and use that as src and dest address to prevent
     * double-fetches/race conditions from ccp functions.
     */
    status = sev_hal_get_dram_2mb((void **)&scratch_dram);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* (CSF-698) Dummy read from OutAddr (with c-bit) and throw away the result */
    SET_CBIT(dst_addr);
    status = copy_from_x86(dst_addr, (uint32_t *)scratch_dram, MsgSize);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* (CSF-698) Dummy read from OutAddr (without c-bit) and throw away the result */
    CLEAR_CBIT(dst_addr);
    status = copy_from_x86(dst_addr, (uint32_t *)scratch_dram, MsgSize);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    /* Copy to PSP DRAM */
    memcpy_ccp(scratch_dram, msg_x86_buffer, MsgSize);

    /*
     * Set source and dest to use the 2mb region for decryption
     * if successfully validated, the results will be copied to the
     * output buffer.
     */
    pMsg = (uint8_t *)scratch_dram; //msg_x86_buffer;
    pOut = (uint8_t *)scratch_dram; //out_x86_buffer;

    GCM_CTX.j0.ext32 = GCM_IV_PAD;
    GCM_CTX.j0.cnt32 = 1;
    for (i = 0; i < IVSize; i++)
    {
        AlignedIV[15 - i] = pIV[i];
    }

    memset(GCM_CTX.ghash, 0, 16);

    // Load key into a LSB slot.
    memcpy(AlignedKey, pKey, 32);
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESKEY,
                           AlignedKey,
                           32,
                           PASSTHROUGH_SWAP_256_BITS);
    command_count++;

    // Load IV (for GHASH/GCTR)
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           32,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    if (AADSize != 0)
    {
        // Use lower 16 bytes of gWorkBuffs.aad for LENs and upper 48 as 0-padded AAD
        memset(AlignedAAD, 0, sizeof(AlignedAAD) + sizeof(AlignedLen));
        memcpy(AlignedAAD, pAAD, AADSize);
        BuildCmd_Aes256GHASH(cmds + command_count,
                             AlignedAAD, (AADSize + 15) & ~15, // AAD || 0-pad
                             NULL,
                             1,  // Init
                             0); // !Finish
        command_count++;
    }

    BuildCmd_Aes256GCTR(cmds + command_count,
                        pMsg, MsgSize, // Plaintext
                        pOut,          // Ciphertext
                        0);            // !Encrypt
    command_count++;

    // [len64(AAD) || len64(MSG)]
    AlignedLen[6]  = (uint8_t)(AADSize >> 5);
    AlignedLen[7]  = (uint8_t)(AADSize << 3);

    AlignedLen[12] = (uint8_t)(MsgSize >> 21);
    AlignedLen[13] = (uint8_t)(MsgSize >> 13);
    AlignedLen[14] = (uint8_t)(MsgSize >> 5);
    AlignedLen[15] = (uint8_t)(MsgSize << 3);

    // Reload IV(for GHASH-Final)
    BuildCmd_CryptoPtToLsb(cmds + command_count,
                           LSB_SEV_AESIV,
                           AlignedIV,
                           16,
                           PASSTHROUGH_NO_SWAP);
    command_count++;

    BuildCmd_Aes256GHASH(cmds + command_count,
                         AlignedLen, 16,    // len(AAD) || len(Msg)
                         GCM_CTX.ghash,
                         0,                 // Init
                         1);                // Finish

    cmds[command_count].cmd0.fields.hoc = DEFAULT_SOC; // stop on completion of last command
    cmds[command_count].cmd0.fields.ioc = 1;           // interrupt on completion of last command
    command_count++;

    status = sev_hal_enqueue_and_run_commands(cmds, eids, command_count);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    // Wait for commands to complete
    status = sev_hal_query_commands(eids, command_count, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto unmap;

    // Validate calculated tag against expected value
    if (secure_compare(pTag, GCM_CTX.ghash, 16) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
    }
    else
    {
        /* (CSF-698) Do a dummy copy to evict the dirty cache lines (and throw away the result) */
        memcpy_ccp((uint32_t *)out_x86_buffer, (uint32_t *)scratch_dram, MsgSize);

        /* Validation is successful, copy the decrypted data from 2mb scratch to output buffer */
        memcpy_ccp((uint32_t *)out_x86_buffer, (uint32_t *)scratch_dram, MsgSize);
    }

unmap:
    sev_hal_unmap_memory(out_x86_buffer);
    sev_hal_unmap_memory(msg_x86_buffer);
end:
    return status;
}

/////////////////////////////////////////////////////////////////////////////////
//
// KAT (Known Answer Test) support
//
/////////////////////////////////////////////////////////////////////////////////
sev_status_t digest_utest_sha256_kat(const uint8_t *msg, size_t msg_size,
                                     const uint8_t *digest, int multipart)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bl_ccp_cmd_desc cmds[4];
    uint32_t n = 0, eids[4];

    BuildCmd_Sha256Init(cmds + (n++));

    if (multipart != 0 && msg_size > 64)
    {
        BuildCmd_Sha256Update(cmds + (n++),
                              msg, 64);

        BuildCmd_Sha256Final(cmds + (n++),
                             msg + 64,
                             msg_size - 64,
                             msg_size); // total msg size
    }
    else
    {
        BuildCmd_Sha256Final(cmds + (n++),
                             msg,
                             msg_size,
                             msg_size); // total msg size
    }

    // Get digest
    BuildCmd_CryptoPtFromLsb(cmds + (n++),
                             AlignedHash,
                             LSB_SEV_SHA,
                             HMAC_SHA256_SIZE_BYTES,
                             PASSTHROUGH_SWAP_256_BITS);

    status = sev_hal_enqueue_and_run_commands(cmds, eids, n);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Wait for commands to complete
    status = sev_hal_query_commands(eids, n, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // verify calculated hash
    if (secure_compare(digest, AlignedHash, 32) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
    }

end:
    return status;
}

sev_status_t hmac_utest_hmac256_kat(const uint8_t *key, size_t key_size,
                                    const uint8_t *msg, size_t msg_size,
                                    const uint8_t *hmac)
{
    sev_status_t status;
    bl_ccp_cmd_desc cmds[7];
    uint32_t eids[7];

    if (key_size > 64 || msg_size < 65)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    status = BuildCmd_Sha256Hmac(cmds, // fills in 7 entries
                                 key, key_size,
                                 msg, 29, // as AAD
                                 msg + 29, msg_size - 29);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // At this time we have: AlignedHmac => {OPAD || IPAD || MSG[0-63]}
    // Calculate SHA256(IPAD||MSG)

    status = sev_hal_enqueue_and_run_commands(cmds, eids, 7);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Wait for HMAC commands to complete
    status = sev_hal_query_commands(eids, 7, 1);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Now we should have: AlignedHmac => {HAMC||5C's||Hash(IPAD||MSG)}

    // verify hmac
    if (secure_compare(hmac, AlignedHmac, 32) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
    }

end:
    return status;
}

sev_status_t cipher_utest_aes256gcm_kat(const uint8_t *pKey,
                                        const uint8_t *pIV, size_t IVSize,
                                        const uint8_t *pAAD, size_t AADSize,
                                        const uint8_t *pMsg, size_t MsgSize,
                                        const uint8_t *pCiphertext,
                                        const uint8_t *pTag)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    // --------------------------------------------------
    // gWorkBuffs usage:
    // --------------------------------usage-------------
    // [32] GCM_CTX     AlignedIV  --> iv[16], ghash[16]
    // [32] key_256bit  AlignedKey --> key[32]
    // [64] opad                       Ciphertext[64]
    // [64] ipad                       Calculated Tag[16]
    // [64] aad,len     AlignedAAD --> AAD[48], LENs[16]

    status = aes256gcm_authenticated_encrypt(
        pKey, 32,
        pAAD, AADSize,
        pMsg, MsgSize,
        gWorkBuffs.opad,
        pIV, IVSize, gWorkBuffs.ipad);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Verify ciphertext
    if (memcmp(pCiphertext, gWorkBuffs.opad, MsgSize) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
        goto end;
    }

    // Verify calculated tag
    if (secure_compare(pTag, gWorkBuffs.ipad, 16) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
        goto end;
    }

    // Decrypt using our regular interface
    status = aes256gcm_authenticated_decrypt(
        pKey, 32,
        pAAD, AADSize,
        pCiphertext, MsgSize,
        gWorkBuffs.opad,
        pIV, IVSize, pTag);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    // Do we get our plaintext back?
    if (memcmp(pMsg, gWorkBuffs.opad, MsgSize) != 0)
    {
        status = SEV_STATUS_BAD_MEASUREMENT;
    }

end:
    return status;
}
