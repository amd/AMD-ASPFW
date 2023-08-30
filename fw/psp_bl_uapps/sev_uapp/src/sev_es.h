// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_ES_H
#define SEV_ES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "pool_u32.h"
#include "sev_status.h"

/**
 * http://twiki.amd.com/twiki/bin/view/ZPArch/VMSAVMEncryptedSaveArea
 * Offsets in the 4K vmsa page
 */
#define VMSA_RIP                (0x178) /* For VMSA tweak */
#define VMSA_RSP                (0x1D8) /* For VMSA tweak */
#define VMSA_RAX                (0x1F8) /* For VMSA tweak */
#define VMSA_GUEST_TSC_SCALE    (0x2F0)
#define VMSA_GUEST_TSC_OFFSET   (0x2F8)
#define VMSA_REG_PROT_NONCE     (0x300)
#define VMSA_RCX                (0x308) /* For VMSA tweak */
#define VMSA_RDX                (0x310) /* For VMSA tweak */
#define VMSA_RBX                (0x318) /* For VMSA tweak */
#define VMSA_RBP                (0x328) /* For VMSA tweak */
#define VMSA_RSI                (0x330) /* For VMSA tweak */
#define VMSA_RDI                (0x338) /* For VMSA tweak */
#define VMSA_R8                 (0x340) /* For VMSA tweak */
#define VMSA_R9                 (0x348) /* For VMSA tweak */
#define VMSA_R10                (0x350) /* For VMSA tweak */
#define VMSA_R11                (0x358) /* For VMSA tweak */
#define VMSA_R12                (0x360) /* For VMSA tweak */
#define VMSA_R13                (0x368) /* For VMSA tweak */
#define VMSA_R14                (0x370) /* For VMSA tweak */
#define VMSA_R15                (0x378) /* For VMSA tweak */
#define VMSA_SEV_FEATURES       (0x3B0)
#define VMSA_FPREG_X87          (0x420) /* For VMSA tweak */
#define VMSA_FPREG_XMM          (0x470) /* For VMSA tweak */
#define VMSA_FPREG_YMM          (0x570) /* For VMSA tweak */
#define VMSA_FPREG_KI           (0x980) /* For VMSA tweak */
#define VMSA_FPREG_ZMMHI        (0x9C0) /* For VMSA tweak */
#define VMSA_FPREG_HIZMM        (0xBC0) /* For VMSA tweak */

#define VMSA_OPAQUE_SIZE        (0x380)
#define VMSA_CRC_SIZE           (0xFC0) /* Must match uCode, CRC doesn't apply to whole page because 'history' */
#define VMSA_SIZE               (PAGE_SIZE_4K)

#define VMSA_TWEAK_BITMAP_SIZE (VMSA_SIZE/(sizeof(uint64_t)*BITS_PER_BYTE)) /* 64 */

/* http://twiki.amd.com/twiki/bin/view/ZPArch/SEV_FEATURES */
#define VMSA_SEV_FEATURES_SECURE_TSC                    (1ULL << 9)  /* Secure TSC feature is enabled for this guest */
#define VMSA_SEV_FEATURES_VMSA_REG_PROT                 (1ULL << 14) /* VMSA Register Protection is enabled for this guest */
#define VMSA_SEV_FEATURES_SECURE_TSC_ENABLED(vmsa)      ((*(uint64_t *)((uint8_t *)vmsa + VMSA_SEV_FEATURES)) & VMSA_SEV_FEATURES_SECURE_TSC)
#define VMSA_SEV_FEATURES_VMSA_REG_PROT_ENABLED(vmsa)   ((*(uint64_t *)((uint8_t *)vmsa + VMSA_SEV_FEATURES)) & VMSA_SEV_FEATURES_VMSA_REG_PROT)

/*
 * Use forward declarations here to avoid circular dependencies on
 * sev_plat.h/sev_guest.h
 */
typedef struct sev_guest sev_guest_t;
typedef struct sev sev_t;

typedef struct sev_es_platform
{
    pool_vcpu_t crc32_pool;
    uint64_t tmr_addr_start;
    uint64_t tmr_addr_size;
    uint64_t start_pool_addr;
    uint64_t start_crc_addr;
    uint32_t pool_block_size;
    uint32_t crc_block_size;
    bool enable_crc64;
    uint64_t reserved_tmr_base;  /* TMR is reserved but not initialized */
    uint64_t reserved_tmr_end;
} sev_es_platform_t;

typedef struct sev_es_guest
{
    size_t   num_vcpus;
    uint32_t head_index;
    uint32_t tail_index;
} sev_es_guest_t;

static inline bool sev_es_is_initialized(sev_es_platform_t *es)
{
    return es != NULL ? es->crc32_pool.is_initialized : false;
}

/**
 * Setup a VMSA for use in a guest.
 *
 * A VMSA is the VMCB register save state area.
 *
 * This function takes the following steps:
 *
 *   1. Allocates a 32bit block from the CRC32 pool.
 *
 *   2. Writes the _system physical address_ of the allocated 32bit
 *      word into the VCPU.
 *
 *   3. Calculates the CRC32 checksum of the VCPU and saves it to the
 *      allocated 32bit block.
 *
 * Parameters:
 *      es       : [in/out] SEV-ES platform object,
 *      guest    : [in/out] SEV guest object,
 *      psp_addr : [in/out] PSP-local buffer containing the VMSA,
 *      length   : [in]     Length of the VMSA buffer.
 */
sev_status_t sev_es_setup_vmsa(sev_es_platform_t *es, sev_guest_t *guest,
                               uint8_t *psp_addr, size_t length);

/**
 * Validate VMSA in guest.
 *
 * A VMSA is the VMCB register save state area.
 *
 * This function takes the following steps:
 *
 *   1. Allocates a 32bit block from the CRC32 pool.
 *
 *   2. Writes the _system physical address_ of the allocated 32bit
 *      word into the VCPU.
 *
 *   3. Calculates the CRC32 checksum of the VCPU and saves it to the
 *      allocated 32bit block.
 *
 * Parameters:
 *      es       : [in/out] SEV-ES platform object,
 *      guest    : [in/out] SEV guest object,
 *      psp_addr : [in/out] PSP-local buffer containing the VMSA,
 *      length   : [in]     Length of the VMSA buffer.
 */
sev_status_t sev_es_validate_vmsa(sev_es_platform_t *es, sev_guest_t *guest,
                                  uint8_t *psp_addr, uint32_t length);

/**
 * Returns false if SEV-ES is disabled for the platform and true if enabled.
 */
bool sev_es_platform_enabled(const sev_t *sev);

/**
 * Returns false if SEV-ES is disabled for the guest and true if enabled.
 */
bool sev_es_guest_enabled(const sev_guest_t *guest);

/**
 * Returns false if SEV-ES pool allocation is disabled for the guest and true if enabled.
 */
bool sev_es_allocation_guest_enabled(const sev_guest_t *guest);

/**
 * Checks if an ASID is valid for use with SEV-ES
 *
 * Returns INVALID_ASID if the ASID is not in the proper range.
 */
sev_status_t sev_es_validate_asid(sev_guest_t *guest, size_t asid);

/**
 * Reserve a Trusted Memory Region (TMR)
 */
sev_status_t sev_es_reserve_trusted_region(sev_es_platform_t *es, uint64_t base, size_t size);

/**
 * Initialize a reserved Trusted Memory Region (TMR). The TMR must have
 * already been reserved with sev_es_reserve_trusted_region().
 *
 * If the TMR has not been reserved, returns ERR_OUT_OF_RESOURCES.
 */
sev_status_t sev_es_init_trusted_region(sev_es_platform_t *es);

/**
 * Free a Trusted Memory Region (TMR)
 */
sev_status_t sev_es_release_trusted_region(sev_es_platform_t *es);

/**
 * Generate the bitmap to which the VMSA tweak will be applied. The kth bit of
 * the bitmap indicates that the kth quadword of the VMSA is tweaked
 */
void sev_es_create_vmsa_bitmap(uint8_t *bitmap);

/**
 * Apply the XOR tweak to the VMSA
 */
void sev_es_apply_vmsa_bitmap(uint8_t *vmsa, uint8_t *bitmap);

/**
 * Create the XOR tweak and apply it to the VMSA
 */
sev_status_t sev_es_vmsa_xor_tweak(uint8_t *vmsa, uint8_t *bitmap);

#endif /* SEV_ES_H */
