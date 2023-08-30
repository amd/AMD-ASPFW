// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nist_kdf.h"
#include "secure_ops.h"
#include "sev_globals.h"
#include "sev_hal.h"

#define UMC_CH_OFFSET                  (0x0000)
#define UMC_CTRL_OFFSET                (0x1000)

#define UMC_ENC_KEY_INDEX_OFFSET       (0x0A00 + UMC_CH_OFFSET)   /* (UMC::EncrArrIndex) */
#define UMC_ENC_KEY_INDEX_WORD_OFFSET  (UMC_ENC_KEY_INDEX_OFFSET / 4)

#define UMC_ENC_KEY_DATA_OFFSET        (0x0A04 + UMC_CH_OFFSET)   /* (UMC::EncrArrData) */
#define UMC_ENC_KEY_DATA_WORD_OFFSET   (UMC_ENC_KEY_DATA_OFFSET / 4)

#define UMC_KEY_ARRAY_AUTOINC_MASK (1ul << 31)

#define UMC_CLK_DIV_CTRL_OFFSET        (0x01AC + UMC_CTRL_OFFSET) /* (UMC::ClkDivCtrl) */
#define UMC_CLK_DIV_CTRL_WORD_OFFSET   (UMC_CLK_DIV_CTRL_OFFSET / 4)

#define UMC_DATA_CTRL_OFFSET        (0x0144)    /* (UMC::DataCtrl)  */
#define UMC_CAP_OFFSET              (0x0DF0)    /* (UMC::UmcCap)    */
#define UMC_CONFIG_OFFSET           (0x0100)    /* (UMC::UmcConfig) */

/* UMC[0...7]CHx00000144 [Data Control] (UMC::DataCtrl) */
#define UMC_DATA_CTRL_ENCR_EN_BIT   (8)
#define UMC_DATA_CTRL_ENCR_EN_MASK  (1ul << (UMC_DATA_CTRL_ENCR_EN_BIT))

/* UMC[0...7]CHx00000DF0 [UMC Capabilities] (UMC::UmcCap) */
#define UMC_CAP_ENCR_DISABLE_BIT    (18)
#define UMC_CAP_ENCR_DISABLE_MASK   (1ul << (UMC_CAP_ENCR_DISABLE_BIT))

/* UMC[0...7]CHx00000100 [UMC Configuration] (UMC::UmcConfig) */
#define UMC_CONFIG_DRAM_READY_BIT   (31)
#define UMC_CONFIG_DRAM_READY_MASK  (1ul << (UMC_CONFIG_DRAM_READY_BIT))

#define UMC_KEY_LABEL    "sev-vm-encryption-key-0"

static sev_status_t read_umc_reg_on_die(uint32_t offset, uint32_t umc_nr,
                                        uint32_t die, uint32_t *value)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t smn_addr = 0;
    volatile uint32_t *axi_addr = NULL;

    if (!value || umc_nr >= UMCCH_TOTAL_NUM)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    smn_addr = UMCCH_SMN_ADDR(mmUMCCH_BaseAddrCS0, umc_nr) + offset;
    status = sev_hal_map_smn_on_die(smn_addr, (void **)&axi_addr, die);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    *value = *axi_addr;

    sev_hal_unmap_smn((void *)axi_addr);

end:
    return status;
}

static bool dram_is_ready(uint32_t umc, uint32_t die)
{
    bool is_ready = false;
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t umc_config = 0;

    status = read_umc_reg_on_die(UMC_CONFIG_OFFSET, umc, die, &umc_config);
    if (status != SEV_STATUS_SUCCESS)
        goto end;

    is_ready = (umc_config & UMC_CONFIG_DRAM_READY_MASK) > 0;

end:
    return is_ready;
}

static bool is_umc_channel_enabled(uint32_t channel, uint32_t die)
{
    uint32_t mask = (1 << channel);
    mask <<= (die * UMCCH_TOTAL_NUM);
    return ((gPersistent.umc_present_bit_mask & mask) == mask);
}

sev_status_t set_umc_key(uint32_t asid, const uint8_t *seed, size_t size)
{
    uint8_t key_val[CIPHER_AES_KEY_SIZE_BYTES];
    size_t context = 0;
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (!seed || asid > GetMaxSEVASID())
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    for (size_t die = 0; die < gTotalDieNum; die++)
    {
        for (size_t umc = 0; umc < UMCCH_TOTAL_NUM; umc++)
        {
            volatile uint32_t *umc_axi = NULL;
            uint32_t umc_addr;
            uint32_t clk_div_ctrl_save = 0;

            if (!is_umc_channel_enabled(umc, die))
                continue;

            /* Make sure UMC channel is populated before writing the registers */
            if (!dram_is_ready(umc, die))
                continue;

            context = (die * UMCCH_TOTAL_NUM) + umc;
            status = kdf_derive(key_val, size, seed, size, UMC_KEY_LABEL,
                                sizeof(UMC_KEY_LABEL), (uint8_t *)&context,
                                sizeof(context));
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            umc_addr = UMCCH_SMN_ADDR(mmUMCCH_BaseAddrCS0, umc);
            status = sev_hal_map_smn_on_die(umc_addr, (void **)&umc_axi, die);
            if (status != SEV_STATUS_SUCCESS)
                goto end;

            /* CSF-568 - For DF-P states, we need to make sure the coarse clock
               gaters for UCLK is enabled before we write the UMC encryption
               registers. Save the original value and restore it after the access */
            clk_div_ctrl_save = umc_axi[UMC_CLK_DIV_CTRL_WORD_OFFSET];
            umc_axi[UMC_CLK_DIV_CTRL_WORD_OFFSET] = clk_div_ctrl_save | (1 << 17) | (1 << 29);

            /*
             * Enable auto_inc, set index which is asid * 8.
             *
             * Steps to write the key:
             *
             * Write UMC::EncrArrIndex[AutoInc,Index] = {1,KeyIndex*4}
             * Write UMC::EncrArrData[Data] w/ Key[31:0]
             * Write UMC::EncrArrData[Data] w/ Key[63:32]
             * Write UMC::EncrArrData[Data] w/ Key[95:64]
             * Write UMC::EncrArrData[Data] w/ Key[127:96]
             * Write UMC::EncrArrData[Data] w/ Key[159:128]
             * Write UMC::EncrArrData[Data] w/ Key[191:160]
             * Write UMC::EncrArrData[Data] w/ Key[223:192]
             * Write UMC::EncrArrData[Data] w/ Key[255:224]
             */
            umc_axi[UMC_ENC_KEY_INDEX_WORD_OFFSET] = ((asid * 8) | UMC_KEY_ARRAY_AUTOINC_MASK);
            for (size_t i = 0; i < size; i += sizeof(uint32_t))
            {
                umc_axi[UMC_ENC_KEY_DATA_WORD_OFFSET] = *(uint32_t *)&key_val[i];
            }

            /* CSF-568 - restore the original UMC_CLK_DIV_CTRL register value */
            umc_axi[UMC_CLK_DIV_CTRL_WORD_OFFSET] = clk_div_ctrl_save;
            sev_hal_unmap_smn((void *)umc_axi);

            if (status != SEV_STATUS_SUCCESS)
                goto end;
        }
    }

end:
    secure_memzero(key_val, sizeof(key_val));
    return status;
}

static bool encryption_enabled_on_die(uint32_t die)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool is_enabled = false;
    bool has_memory = false;
    uint32_t data_ctrl = 0;
    uint32_t cap = 0xFFFFFFFF;
    size_t umc = 0;

    for (umc = 0; umc < UMCCH_TOTAL_NUM; umc++)
    {
        if (!is_umc_channel_enabled(umc, die))
            continue;

        has_memory = dram_is_ready(umc, die);
        if (!has_memory)
            continue;

        status = read_umc_reg_on_die(UMC_DATA_CTRL_OFFSET, umc, die, &data_ctrl);
        if (status != SEV_STATUS_SUCCESS)
        {
            is_enabled = false;
            goto end;
        }

        status = read_umc_reg_on_die(UMC_CAP_OFFSET, umc, die, &cap);
        if (status != SEV_STATUS_SUCCESS)
        {
            is_enabled = false;
            goto end;
        }

        is_enabled = (data_ctrl & UMC_DATA_CTRL_ENCR_EN_MASK) &&
                     !(cap & UMC_CAP_ENCR_DISABLE_MASK);
        if (!is_enabled)
            break;
    }

end:
    return is_enabled;
}

static bool die_has_memory(uint32_t die)
{
    bool has_memory = false;
    size_t umc = 0;

    for (umc = 0; umc < UMCCH_TOTAL_NUM; umc++)
    {
        if (!is_umc_channel_enabled(umc, die))
            continue;

        has_memory = dram_is_ready(umc, die);
        if (has_memory)
            break;
    }

    return has_memory;
}

bool umc_encryption_enabled(void)
{
    size_t die = 0;
    bool is_enabled = false;

    for (die = 0; die < gTotalDieNum; die++)
    {
        /* If there is no memory installed on this die, skip it */
        if (!die_has_memory(die))
            continue;

        is_enabled = encryption_enabled_on_die(die);
        if (!is_enabled)
            break;
    }

    return is_enabled;
}
