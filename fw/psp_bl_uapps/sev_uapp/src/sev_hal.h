// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_HAL_H
#define SEV_HAL_H

#include <stddef.h>
#include <stdint.h>

#include "bl_syscall.h"
#include "digest.h"
#include "ecc.h"
#include "sev_plat.h"
#include "sev_scmd.h"

#define ALL_SLAVE_DIES  (0xFF)
#define CUK_SIZE        (32)   /* 32 bytes for CUK size */

#define sev_hal_ecc_primitive_type_t sev_ecc_primitive_type_t

typedef struct sev_hal_key_derive
{
    uint8_t*        key_out;
    size_t          key_out_length;
    const uint8_t*  key_in;
    size_t          key_in_length;
    const uint8_t*  label;
    size_t          label_length;
    const uint8_t*  context;
    size_t          context_length;
} sev_hal_key_derive_t;

typedef enum sev_hal_aes_alg
{
    CCP_HAL_AES_ALG_ECB   = 0,
    CCP_HAL_AES_ALG_CBC   = 1,
    CCP_HAL_AES_ALG_OFB   = 2,
    CCP_HAL_AES_ALG_CFB   = 3,
    CCP_HAL_AES_ALG_CTR   = 4,
    CCP_HAL_AES_ALG_CMAC  = 5,
    CCP_HAL_AES_ALG_GHASH = 6,
    CCP_HAL_AES_ALG_GCTR  = 7,
    CCP_HAL_AES_ALG_IAPM_NIST  = 8,
    CCP_HAL_AES_ALG_IAPM_IPSEC = 9,
    CCP_HAL_AES_ALG_UMC   = 10,
    CCP_HAL_AES_ALG_FORCE_32BIT_ENUM = 0x7FFFFFFF /*!< [UNUSED] Added to force this enum to 32-bits */
} sev_hal_aes_alg_t;

typedef enum sev_hal_aes_mode
{
    CCP_HAL_AES_MODE_DECRYPT = 0,
    CCP_HAL_AES_MODE_ENCRYPT = 1,
    CCP_HAL_AES_MODE_32BIT_ENUM = 0x7FFFFFFF /*!< [UNUSED] Added to force this enum to 32-bits */
} sev_hal_aes_mode_t;


#ifdef CCP_HAL_H
#define sev_hal_mem_type_t CCP_HAL_MEM_TYPE
#else
typedef enum sev_hal_mem_type
{
    CCP_HAL_SOC_DRAM    = 0,
    CCP_HAL_LSB         = 1,
    CCP_HAL_LOCAL       = 2,
    CCP_HAL_SYSTEM_GART = 3,
    CCP_HAL_FORCE_32BIT_ENUM = 0x7FFFFFFF /*!< [UNUSED] Added to force this enum to 32-bits */
} sev_hal_mem_type_t;
#endif

typedef struct sev_hal_aes      // AES_GENERIC_E in bl_syscall.h
{
    uint8_t*            iv;         // in, out
    size_t              iv_length;
    const uint8_t*      key;
    size_t              key_length;
    sev_hal_mem_type_t  key_memtype;
    const uint8_t*      src;
    size_t              src_length;
    sev_hal_mem_type_t  src_memtype;
    const uint8_t*      dest;
    size_t              dest_length;
    sev_hal_mem_type_t  dest_memtype;
    sev_hal_aes_alg_t   aes_alg;
    sev_hal_aes_mode_t  aes_mode;
} sev_hal_aes_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_hal_aes_t) == sizeof(AES_GENERIC), this_file);

typedef struct sev_hal_sha      // SHA_GENERIC_DATA_T in bl_syscall.h
{
    SHA_TYPE        SHAType;
    const uint8_t*  data;
    size_t          data_len;
    uint8_t         data_memtype;
    uint8_t         padding1[3];
    uint8_t*        digest;
    size_t          digest_len;
    uint8_t*        intermediate_digest;
    size_t          intermediate_msg_len;
    uint8_t         som;
    uint8_t         padding2[3];
    uint8_t         eom;
    uint8_t         padding3[3];
} sev_hal_sha_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_hal_sha_t) == sizeof(SHA_DATA), this_file);

typedef struct sev_hal_ecc_scalar_add
{
    ecc_scalar_t*   r;
    ecc_scalar_t*   n;      // modulus
    ecc_scalar_t*   a;
    ecc_scalar_t*   b;
} sev_hal_ecc_scalar_add_t;

typedef struct sev_hal_ecc_scalar_mul
{
    ecc_scalar_t*   r;
    ecc_scalar_t*   n;      // modulus
    ecc_scalar_t*   a;
    ecc_scalar_t*   b;
} sev_hal_ecc_scalar_mul_t;

typedef struct sev_hal_ecc_scalar_inv
{
    ecc_scalar_t*   r;
    ecc_scalar_t*   n;      // modulus
    ecc_scalar_t*   a;
} sev_hal_ecc_scalar_inv_t;

typedef struct sev_hal_ecc_point_add
{
    ecc_point_t*    R;      // R = P + Q
    ecc_scalar_t*   n;      // modulus for prime curve
    ecc_point_t*    P;
    ecc_point_t*    Q;
} sev_hal_ecc_point_add_t;

typedef struct sev_hal_ecc_point_scale
{
    ecc_point_t*    R;      // R = k*P
    ecc_scalar_t*   n;      // modulus for prime curve
    ecc_scalar_t*   a;      // domain parameter "a"
    ecc_scalar_t*   k;      // scalar
    ecc_point_t*    P;      // R = k*P
} sev_hal_ecc_point_scale_t;

typedef struct sev_hal_ecc_point_double
{
    ecc_point_t*    R;      // R = 2*P
    ecc_scalar_t*   n;      // modulus for prime curve
    ecc_scalar_t*   a;      // domain parameter "a"
    ecc_point_t*    P;      // R = 2*P
} sev_hal_ecc_point_double_t;

typedef struct sev_hal_ecc_point_dual_mul
{
    ecc_point_t*    R;      // R = k*P + h*Q
    ecc_scalar_t*   n;      // modulus for prime curve
    ecc_scalar_t*   a;      // domain parameter "a"
    ecc_scalar_t*   k;
    ecc_point_t*    P;
    ecc_scalar_t*   h;
    ecc_point_t*    Q;
} sev_hal_ecc_point_dual_mul_t;

typedef struct sev_hal_ecc_primitive
{
    sev_hal_ecc_primitive_type_t        primitive;

    union
    {
        sev_hal_ecc_scalar_add_t        scalar_add;
        sev_hal_ecc_scalar_mul_t        scalar_mul;
        sev_hal_ecc_scalar_inv_t        scalar_inv;
        sev_hal_ecc_point_add_t         point_add;
        sev_hal_ecc_point_scale_t       point_scale;
        sev_hal_ecc_point_double_t      point_double;
        sev_hal_ecc_point_dual_mul_t    point_dual_mul;
    } cmd;
} sev_hal_ecc_primitive_t;

typedef struct sev_hal_rsapss_verify
{
    uint8_t*    hash;           // Message digest to verify the RSA signature
    uint32_t    hash_len;       // hash length in bytes
    uint8_t*    modulus;        // Modulus address
    uint32_t    modulus_len;    // Modulus length in bytes
    uint8_t*    exponent;       // Exponent address
    uint32_t    exp_len;        // Exponent length in bytes
    uint8_t*    sig;            // Signature to be verified, same size as ModulusSize
} sev_hal_rsapss_verify_t;


#define TCB_HASHSTICK_MICROCODE_INDEX    (7)

/* SVC Service Call for Global Feature */
#define SNP_GLOBALS_READ  0
#define SNP_GLOBALS_WRITE 1

/**
 *  Map and unmap system memory.
 */
sev_status_t sev_hal_map_memory(uint64_t addr, void **axi_addr);
sev_status_t sev_hal_map_guest_context(uint64_t addr, void **axi_addr, uint32_t size);
sev_status_t sev_hal_map_memory_ccp(uint64_t addr, void **axi_addr, uint32_t size);
sev_status_t sev_hal_map_memory_ccp_asid(uint64_t addr, void **axi_addr, uint32_t size, uint32_t asid);
sev_status_t sev_hal_unmap_memory(void *axi_addr);
sev_status_t sev_hal_unmap_guest_context(void *axi_addr, uint32_t size);

/**
 *  Map and unmap SMN memory on the given die.
 */
sev_status_t sev_hal_map_smn_on_die(uint32_t smn_addr, void **axi_addr, size_t die);
sev_status_t sev_hal_map_smn(uint32_t smn_addr, void **axi_addr);
sev_status_t sev_hal_unmap_smn(void *axi_addr);

/**
 *  SEV master die send command to slave die, and wait until response.
 *
 *  Parameters:
 *      target_die == 0, the command is sent to each die and wait until all responded.
 *      target_die != 0, the command is sent to specific die and wait until response.
 */
sev_status_t sev_hal_master_to_slave(uint32_t target_die, void *pCmd_buf, uint32_t buf_size);

/**
 * Functions to access SEV persistent data which is saved to non-volatile storage in SPI-ROM.
 *
 * This interface provide a thin and simple layer implementation for SEV to
 * save/retrieve its persistent data,
 * - the confidentiality and integrity of the data is handled by SEV app itself.
 * - the management of the data is also handled by SEV app itself.
 */
sev_status_t sev_hal_persistent_write(void *pBuf, uint32_t input_size);
sev_status_t sev_hal_persistent_read(void *pBuf, uint32_t buf_size);
sev_status_t sev_hal_persistent_erase(uint32_t num_blocks);

/**
 * Leverage the Implemention in SVC code for the KDF in Counter Mode defined in section 5.1 of NIST
 * SP 800-108.
 *
 * DEPRECATED: Use nist_kdf.h instead.
 */
sev_status_t sev_hal_key_derive(sev_hal_key_derive_t *pParams);

/**
 * AES operation
 */
sev_status_t sev_hal_aes_generic(sev_hal_aes_t *pParams);

/**
 * SHA-256 operation
 */
sev_status_t sev_hal_sha(sev_hal_sha_t *pParams, SHA_TYPE sha_type);

/**
 * ECC primitive operation
 */
sev_status_t sev_hal_ecc_primitive(sev_hal_ecc_primitive_t *pParams);

/**
 * RSA PSS validation
 */
sev_status_t sev_hal_rsapss_verify(sev_hal_rsapss_verify_t *pParams);

/**
 *  Cache operations.
 *
 *  Parameters:
 *      vaddr : Virtual address
 *      size  : size
 *
 *  These functions never fail.
 */
void sev_hal_clean_dcache(uint32_t vaddr, size_t size);
void sev_hal_invalidate_dcache(uint32_t vaddr, size_t size);
void sev_hal_clean_invalidate_dcache(uint32_t vaddr, size_t size);

void sev_hal_invalidate_icache(uint32_t vaddr, size_t size);
void sev_hal_invalidate_all_icache(void);

/**
 * Generate random number
 *
 *  pOut : Destination pointer to copy random data
 *  size : size of Random number desired in Bytes
 */
sev_status_t sev_hal_trng(uint8_t *pOut, uint32_t size);

/**
 *  Get information about a Trusted Memory Region (TMR)
 *
 *  Parameters:
 *      tmr_nr    : TMR region number (0-24) (in)
 *      *base     : TMR base address (out)
 *      *limit    : TMR limit address (out)
 *      *mask     : Mask of valid address bits (out)
 *      *is_valid : Whether or not the TMR is marked valid (out)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_INVALID_PARAMS if *base, *limit*, *mask, and *is_valid are all NULL,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_get_tmr(size_t tmr_nr, uint64_t *base, uint64_t *limit,
                             bool *is_valid);

/**
 *  Setup a Trusted Memory Region (TMR)
 *
 *  Parameters:
 *      tmr_nr         : TMR region number (0-24) (in)
 *      base           : TMR base address (in)
 *      size           : TMR size (in)
 *      trust_lvl_mask : Trusted entities allowed to access this region (in)
 *      flags          : Other access restrictions (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_set_tmr(size_t tmr_nr, uint64_t base, uint64_t size,
                             uint32_t trust_lvl_mask, uint32_t flags);

/**
 *  Enable/Disable bit(s) in an existing TMR entry.
 *  Parameters:
 *      tmr_nr         : TMR region number (0-24) (in)
 *      flags          : TMR_CTL flags to set or clear (in)
 *      set            : set or clear the flags (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success, else error code
 */
sev_status_t sev_hal_modify_tmr_flags(size_t tmr_nr, uint32_t flags, bool set);

/**
 *  Reset a Trusted Memory Region (TMR)
 *
 *  Parameters:
 *      tmr_nr : TMR region number (0-24) (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_reset_tmr(size_t tmr_nr);

/**
 *  Enable a Trusted Memory Region (TMR) by setting the 'valid' flag in the
 *  TMR control register.
 *
 *  Parameters:
 *      tmr_nr : TMR region number (0-24) (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_INVALID_PARAMS if the TMR number is out of range,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_enable_tmr(size_t tmr_nr);

/**
 *  Iterate through all TMRs in the system
 *
 *  Parameters:
 *      tmr : This variable is set to the current TMR number on each iteration (in)
 */
#define for_each_tmr(tmr)    for ((tmr) = 0; (tmr) <= (TMR_NR_MAX); (tmr)++)

/**
 * See DEDFRTL-5545
 *  Only set this when doing operations that involve reading a page in one
 *    way (e.g. unencrypted) and then writing it out in place the same way
 *    (e.g. encrypted) because it slows down PSP memory accesses
 *
 * See PPR: D18F1x3F8 [PSP Miscellaneous Modes] (DF::PspMiscMode)
 * Set PspMiscMode.PspRdSzWrBkInvd = 0/1
 * Notes: Block reads = cacheline accesses (64 bytes)
 *        Sized reads = less than cacheline accesses
 *
 *  Parameters:
 *      enable : true to set the bit, false to clear the bit
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_set_misc_read_sized_wrbkinvd(bool enable);

/**
 *  Check if TSME is enabled
 *
 *  Parameters:
 *      enable : pointer to uint32_t to return the TSME status
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_get_misc_tsme_enable(uint32_t *enable);

/**
 *  Flush the data fabric on the current die
 *
 *  Parameters:
 *      none
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      ERR_OUT_OF_RESOURCES if register mapping failed.
 */
sev_status_t sev_hal_df_write_flush(void);

/**
 *  Get the chip-unique ECC key from the LSB.
 *
 *  Parameters:
 *      buffer : Memory buffer to copy the key into. (out)
 *      size   : size of the input buffer. On return, this is set to the size
 *               of the ECC key. (in/out)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success,
 *      SEV_STATUS_HARDWARE_PLATFORM if copying from the LSB failed.
 */
sev_status_t sev_hal_get_chip_unique_key(uint8_t *buffer, size_t *size);

/**
 *  Return the address and length of the x86 SMM region.
 *
 *  Parameters:
 *      base   : SMM base address        (out)
 *      length : Length of SMM region    (out)
 *
 *  Return value:
 *      None.
 */
void sev_hal_get_smm_range(uint64_t *base, uint64_t *length);

/**
 *  Return the value of MIN_SEV_ASID from the APCB.
 *
 *  Parameters:
 *      *min_sev_asid : pointer to ASID watermark for non-ES SEV guests (out)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success.
 *      ERR_INVALID_PARAMS if min_sev_asid is NULL.
 */
sev_status_t sev_hal_get_min_sev_asid(uint32_t *min_sev_asid);

/**
 *  Return a pointer to the SEV reserved DRAM region.
 *
 *  Parameters:
 *      size : Expected size of the DRAM reservation    (in)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success.
 *      ERR_OUT_OF_RESOURCES if the requested size is too large.
 */
sev_status_t sev_hal_get_reserved_dram(void **buffer, size_t size);

/**
 *  Read a 32-bit value from a register via SMN.
 *
 *  Parameters:
 *      die      : target die                                   (in)
 *      smn_addr : SMN address of the target register on 'die'  (in)
 *      mask     : bit mask to apply after the read operation   (in)
 *      *value   : pointer to store the result of the read      (out)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success.
 */
sev_status_t sev_hal_read_reg_on_die(size_t die, uint32_t smn_addr,
                                     uint32_t mask, uint32_t *value);

/**
 *  Read a 32-bit value from a register via SMN.
 *
 *  Parameters:
 *      smn_addr : SMN address of the target register on 'die'  (in)
 *      mask     : bit mask to apply after the read operation   (in)
 *      *value   : pointer to store the result of the read      (out)
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success.
 */
sev_status_t sev_hal_read_reg(uint32_t smn_addr, uint32_t mask, uint32_t *value);

/**
 *  Acquire/release access to the data fabric. sev_hal_df_acquire() will
 *  disable DF C-states using the RSMU, and sev_hal_df_release() will enable
 *  DF C-states and allow the fabric to sleep.
 *
 *  Parameters:
 *      none.
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success, or ERR_OUT_OF_RESOURCES on failure.
 */
sev_status_t sev_hal_df_acquire(void);
sev_status_t sev_hal_df_release(void);

/**
 *  Read the fused hash value of the active AMD Root Key.
 *
 *  Parameters:
 *      hash : (out) buffer to store the hash value
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success, or ERR_INVALID_PARAMS on failure.
 */
sev_status_t sev_hal_get_root_key_hash(digest_sha_t *hash);

/**
 *  Pass a new SEV FW image to the bootloader. The BL will verify it
 *  and install it in the SEV FW image cache.
 *
 *  Parameters:
 *      x86_addr : 64-bit pointer to the SEV FW image
 *      len      : The length of the SEV FW image
 *      op       : SEV_NEWFW_SUBOP_ENUM value
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_cache_new_image(uint64_t x86_addr, uint32_t len,
                                     SEV_NEWFW_SUBOP_ENUM op);

/**
 *  Read the MCM information containing CCD and Core information and
 *  store into gSev.
 *
 *  Parameters:
 *      persistent : global gPersistent
 *
 *  Return value:
 *      SEV_STATUS_SUCCESS on success, or ERR_HAL_MCM_INFO on failure.
 */
sev_status_t sev_hal_get_mcm_info(sev_persistent_globals_t *persistent);

/**
 *  Enqueue the CCP command descriptions into the actual software CCP queue
 *  which is maintained by PSP bootloader.
 *
 *  Parameters:
 *      cmds  : Address of the CCP command descriptions
 *      eids  : Array of command handles
 *      count : Number of commands to queue
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_enqueue_and_run_commands(void *cmds, uint32_t *eids, uint32_t count);

/**
 *  Query the status of commands enqueued in the CCP engine.
 *
 *  Parameters:
 *      eids       : Array of command handles
 *      count      : Number of commands to query
 *      wait4ready : Wait until job completed or failed
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_query_commands(uint32_t *eids, uint32_t count, int wait4ready);

sev_status_t sev_hal_flush_tlb(void);

/**
 *  Retrieve the TCB version stick from BL.
 *
 *  Parameters:
 *     tcb_version - return the tcb version from BL (without the microcode)
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_get_tcb_version(snp_tcb_version_t *tcb_version);

/**
 *  Get the HASHSTICKs at given index
 *
 *  Parameters:
 *      seed - output buffer for the seed
 *      length - length of the buffer, must be at least SH384 digest size (48)
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_get_seed_at_idx(uint8_t *seed, uint32_t length, uint32_t idx);

/**
 * Get INITPKG addresses from DRAM area
 *
 *  Parameters:
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_get_initpkg_dram(sev_scfctp_init_pkg_regs_t **initpkg);

/**
 * Get SOC Version
 *
 *  Parameters:
 *
 *  Return value:
 *      Various SEV_STATUS values
 */
sev_status_t sev_hal_get_soc_version(SOC_VER_E *soc_version);

/**
 * Yield Function for SEV
 *   Calls Bootloader to yield for other interrupts
 *
 *   Parameters: none
 *
 */
sev_status_t sev_hal_yield(void);

sev_status_t sev_hal_write_snp_globals(uint8_t *data);
sev_status_t sev_hal_read_snp_globals(uint8_t *data);

/**
 * Get the address to the scratch 2mb memory (8 mb PSP secure dram, last 2mb)
 *   Calls BL to get the sev reserve address and calculate the 6mb offset from
 *   the beginning.
 *   A check is conducted to make sure we got the right aligned address.
 *
 * Parameters:
 *   Pointer to the pointer of the virtual address to be returned.
 *
 * Return value:
 *   Various SEV_STATUS values
 */
sev_status_t sev_hal_get_dram_2mb(void **buffer);

/**
 * The BL sends a PSP-SMU command where PSP passes in a register number,
 * the SMU reads the MSR for every core/thread and returns if the result
 * is the same for all cores/threads and what the data is.
 *
 * Parameters:
 *  Input:  msr_register: MSR to read
 *  Output: msr_value: Value of the MSR register
 *          same: If the MSRs match and their value
 *
 * Return value:
 *   Various SEV_STATUS values
 */
sev_status_t sev_hal_check_msr(uint32_t msr_register, uint32_t *same, uint64_t *msr_value);

/**
 * @brief This returns the previously read MSR value
 *
 * @param msr The MSR we want the value of
 * @param value Pointer to where to save the value
 * @param is_same Pointer to where to save the is_same flag
 * @return sev_status_t
 */
sev_status_t sev_hal_get_msr_value(uint32_t msr, uint64_t *value, bool *is_same);

/**
 * PLAT-76815: Read and check certain MSRs to avoid security issues
 * Parameters:
 *  Output: msr_values: Output array to write the msr_values to
 */
sev_status_t sev_hal_check_msrs(uint64_t *msr_values);

/**
 * Test if SNP is enabled across all cores
 */
bool snp_is_enabled_all_cores(void);

/**
 * Get the memory map from the bootloader of all DRAM, Hole, MMIO regions, etc
 *
 * Parameters:
 *  Input:  None
 *  Output: mem_map: A populated mem_map which can then be validated
 *
 * Return value:
 *   Various SEV_STATUS values
 */
sev_status_t get_memory_map(SYS_MEM_MAP *mem_map);

/**
 * Read INITPKG7
 *
 * Parameters:
 *  Input:  Pointer to the variable to store the initpkg7 value
 *  Output: initpkg7: INITPKG7 register content
 *
 * Return value:
 *   Various SEV_STATUS values
 */
sev_status_t sev_hal_read_initpkg7(uint32_t *initpkg7);

/**
 * Retrieve Skip RSMUs from BL for this socket
 *
 * Parameters:
 *    Input:  None
 *    Output:  Writes to gPersistent.skip_rsmus
 * Return value:
 *   Various SEV_STATUS values
 */
sev_status_t sev_hal_get_skip_rsmus(void);

enum bitop {
    BITOP_NOP   = 0,
    BITOP_FLIP  = 1,
    BITOP_CLEAR = 2,
    BITOP_SET   = 3,
    BITOP_MASK  = 3
};

sev_status_t sev_hal_update_msr(uint32_t msr, uint32_t bit1, enum bitop op1, uint32_t bit2, enum bitop op2);

#endif /* SEV_HAL_H */


