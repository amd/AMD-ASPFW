// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_MCMD_H
#define SEV_MCMD_H

#include <stddef.h>
#include <stdint.h>

#include "c2p.h"
#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "cpuid_lookup.h"
#include "helper.h"
#include "sev_errors.h"
#include "sev_fw_image.h"

extern volatile SEV_FW_IMAGE_HEADER Image$$SEV_UAPP_CODE$$Base;

/**
 * Below three SEV versioning info was not placed at fixed location inside of SEV binary
 * In an effort to enable PSP BL to parse the SEV versioning info, place them into the SEV FW header region (first 0x100), namely:
 * 0x62 - SEV_API_MAJOR
 * 0x61 - SEV_API_MINOR
 * 0x60 - SEV_BUILD_ID
 */
/* Below macro definitions get the version info from the SEV FW header which is placed at 0x1B000 by PSP Bootloader */
#define SEV_API_MAJOR   (Image$$SEV_UAPP_CODE$$Base.FWVersion >> 16 & 0xff)
#define SEV_API_MINOR   (Image$$SEV_UAPP_CODE$$Base.FWVersion >> 8 & 0xff)
#define SEV_BUILD_ID    (Image$$SEV_UAPP_CODE$$Base.FWVersion & 0xff)
#define SEV_FW_SVN      (Image$$SEV_UAPP_CODE$$Base.SecPatchLevel & 0xff)

/* SNP uint64 address space is defined as bit 0 (page_size), bit 1-11 reserved, bit 12-63 corresponds to
   bit 12 and 63 of the actual page address */
#define SNP_PAGE_SIZE(x) ((x) & 1)
#define SNP_PAGE_ADDR(x) ((x) & ~(PAGE_SIZE_4K-1))

/* Define the address reserved bit fields (0 to 11) - subject to change by spec in the future */
#define SNP_ADDR_RESERVED_MASK (PAGE_SIZE_4K-1) /* This is for SNP_INIT* */
/* SNP_PAGE_SET_STATE BASE addresses have to be 2M aligned */
#define SNP_PAGE_SET_STATE_ADDR_RESERVED_MASK (PAGE_SIZE_2M-1)

/* LaunchFinish API has reserved bits from 1 to 11 */
#define SNP_ADDR_LAUNCH_FINISH_RESERVED_MASK (0xFFEULL)

/* Reclaim API has reserved bits from 1 to 11 */
#define SNP_ADDR_PAGE_RECLAIM_RESERVED_MASK (0xFFEULL)

#define SEV_CMD_RESP_REG            MP0_C2PMSG_32
#define SEV_CMD_BUF_ADDR_LO_REG     MP0_C2PMSG_56
#define SEV_CMD_BUF_ADDR_HI_REG     MP0_C2PMSG_57
#define SEV_X86_RESPONSE_IOC_REG    MP0_P2CMSG_1

#define SEV_CMD_RB_X86_TAIL         SEV_CMD_BUF_ADDR_HI_REG
#define SEV_CMD_RB_SEV_HEAD         SEV_CMD_BUF_ADDR_LO_REG

#define PADDR_INVALID  ~(0x0ull)            /* -1 */

/* FEATURE_INFO */
#define SEV_FEATURE_INFO_x00_EAX (1)                        /* Maximum supported is x01 */
#define SEV_FEATURE_INFO_x00_EBX (1)                        /* SEV Legacy command Supported */
#define SEV_FEATURE_INFO_x00_ECX_VLEK (1UL << 0)            /* VLEK */
#define SEV_FEATURE_INFO_x00_ECX_X86_SNP_SHUTDOWN (1UL << 1)/* X86SnpShutdown bit */
#define SEV_FEATURE_INFO_x00_ECX SEV_FEATURE_INFO_x00_ECX_VLEK | SEV_FEATURE_INFO_x00_ECX_X86_SNP_SHUTDOWN

#define SEV_FEATURE_INFO_x00_EDX (0)                        /* Reserved */

/**
 * Guest supported messages:
 *   Bit 8 - MSG_TSC_INFO_REQ guest message
 *   Bit 7 - MSG_ABSORB_NOMA_REQ guest message
 *   Bit 6 - MSG_VMRK_REQ guest message
 *   Bit 5 - MSG_ABSORB_REQ guest message
 *   Bit 4 - MSG_IMPORT_REQ guest message
 *   Bit 3 - MSG_EXPORT_REQ guest message
 *   Bit 2 - MSG_REPORT_REQ guest message
 *   Bit 1 - MSG_KEY_REQ guest message
 *   Bit 0 - MSG_CPUID_REQ guest message
 */
#define SEV_FEATURE_INFO_x01_EAX (0x1FF)                    /* Bits 0 to 8, all supported */
#define SEV_FEATURE_INFO_x01_EBX (0)                        /* Reserved */
#define SEV_FEATURE_INFO_x01_ECX (0)                        /* Reserved */
#define SEV_FEATURE_INFO_x01_EDX (0)                        /* Reserved */

/**
 * Test if the requested API version is supported.
 */
static inline bool api_version_supported(uint8_t major, uint8_t minor)
{
    return SEV_API_MAJOR > major || (SEV_API_MAJOR == major && SEV_API_MINOR >= minor);
}

/* Use forward declarations here to avoid circular dependencies on sev_plat.h */
typedef struct sev sev_t;

typedef enum sev_mcmd_id
{
    /* SEV Platform commands */
    SEV_MCMD_ID_INIT                 = 0x001,   /* Initialize the platform */
    SEV_MCMD_ID_SHUTDOWN             = 0x002,   /* Shut down the platform */
    SEV_MCMD_ID_PLATFORM_RESET       = 0x003,   /* Delete the persistent platform state */
    SEV_MCMD_ID_PLATFORM_STATUS      = 0x004,   /* Return status of the platform */
    SEV_MCMD_ID_PEK_GEN              = 0x005,   /* Generate a new PEK */
    SEV_MCMD_ID_PEK_CSR              = 0x006,   /* Generate a PEK certificate signing request */
    SEV_MCMD_ID_PEK_CERT_IMPORT      = 0x007,   /* Import the signed PEK certificate */
    SEV_MCMD_ID_PDH_CERT_EXPORT      = 0x008,   /* Export the PDH and its certificate chains */
    SEV_MCMD_ID_PDH_GEN              = 0x009,   /* Generate a new PDH and PEK signature */
    SEV_MCMD_ID_DF_FLUSH             = 0x00A,   /* Flush the data fabric */
    SEV_MCMD_ID_DOWNLOAD_FIRMWARE    = 0x00B,   /* Download new SEV FW */
    SEV_MCMD_ID_GET_ID               = 0x00C,   /* Get the platform ID needed for KDS */
    SEV_MCMD_ID_INIT_EX              = 0x00D,   /* Initialize the platform, extended */
    SEV_MCMD_ID_NOP                  = 0x00E,   /* No operation */
    SEV_MCMD_ID_RING_BUFFER          = 0x00F,   /* Initialize Ring Buffer */

    /* SEV Guest commands */
    SEV_MCMD_ID_DECOMMISSION         = 0x020,   /* Delete the guest's SEV context */
    SEV_MCMD_ID_ACTIVATE             = 0x021,   /* Load a guest's key into the UMC */
    SEV_MCMD_ID_DEACTIVATE           = 0x022,   /* Unload a guest's key from the UMC */
    SEV_MCMD_ID_GUEST_STATUS         = 0x023,   /* Query the status and metadata of a guest */
    SEV_MCMD_ID_COPY                 = 0x024,   /* Copy/move encrypted guest page(s) */
    SEV_MCMD_ID_ACTIVATE_EX          = 0x025,   /* The guest is bound to a particular ASID and to CCX(s) which will be
                                                   allowed to run the guest. Then guest's key is loaded into the UMC */

    /* SEV Guest launch commands */
    SEV_MCMD_ID_LAUNCH_START         = 0x030,   /* Begin to launch a new SEV enabled guest */
    SEV_MCMD_ID_LAUNCH_UPDATE_DATA   = 0x031,   /* Encrypt guest data for launch */
    SEV_MCMD_ID_LAUNCH_UPDATE_VMSA   = 0x032,   /* Encrypt guest VMCB save area for launch */
    SEV_MCMD_ID_LAUNCH_MEASURE       = 0x033,   /* Output the launch measurement */
    SEV_MCMD_ID_LAUNCH_SECRET        = 0x034,   /* Import a guest secret sent from the guest owner */
    SEV_MCMD_ID_LAUNCH_FINISH        = 0x035,   /* Complete launch of guest */
    SEV_MCMD_ID_ATTESTATION          = 0x036,   /* Attestation report containing guest measurement */

    /* SEV Guest migration commands (outgoing) */
    SEV_MCMD_ID_SEND_START           = 0x040,   /* Begin to send guest to new remote platform */
    SEV_MCMD_ID_SEND_UPDATE_DATA     = 0x041,   /* Re-encrypt guest data for transmission */
    SEV_MCMD_ID_SEND_UPDATE_VMSA     = 0x042,   /* Re-encrypt guest VMCB save area for transmission */
    SEV_MCMD_ID_SEND_FINISH          = 0x043,   /* Complete sending guest to remote platform */
    SEV_MCMD_ID_SEND_CANCEL          = 0x044,   /* Cancel sending guest to remote platform */

    /* SEV Guest migration commands (incoming) */
    SEV_MCMD_ID_RECEIVE_START        = 0x050,   /* Begin to receive guest from remote platform */
    SEV_MCMD_ID_RECEIVE_UPDATE_DATA  = 0x051,   /* Re-encrypt guest data from transmission */
    SEV_MCMD_ID_RECEIVE_UPDATE_VMSA  = 0x052,   /* Re-encrypt guest VMCB save area from transmission */
    SEV_MCMD_ID_RECEIVE_FINISH       = 0x053,   /* Complete receiving guest from remote platform */

    /* SEV Debugging commands */
    SEV_MCMD_ID_DBG_DECRYPT          = 0x060,   /* Decrypt guest memory region for debugging */
    SEV_MCMD_ID_DBG_ENCRYPT          = 0x061,   /* Encrypt guest memory region for debugging */

    /* SEV Page Migration commands */
    SEV_MCMD_ID_SWAP_OUT             = 0x070,   /* Encrypt guest memory region for temporary storage */
    SEV_MCMD_ID_SWAP_IN              = 0x071,   /* Reverse of SEV_MCMD_ID_SWAP_OUT */

    /* End of SEV Command */
    SEV_MCMD_ID_END                  = SEV_MCMD_ID_SWAP_IN,

    /* SNP Platform commands */
    SNP_MCMD_ID_INIT                 = 0x081,   /* Initialize the platform */
    SNP_MCMD_ID_SHUTDOWN             = 0x082,   /* Shut down the platform */
    SNP_MCMD_ID_PLATFORM_STATUS      = 0x083,   /* Return status of the platform */
    SNP_MCMD_ID_DF_FLUSH             = 0x084,   /* Flush the data fabric */
    SNP_MCMD_ID_INIT_EX              = 0x085,   /* Initialize the platform with RMP state check */
    SNP_MCMD_ID_SHUTDOWN_EX          = 0x086,   /* Shut down the platform and reclaim iommu pages */

    /* SNP Guest commands */
    SNP_MCMD_ID_DECOMMISSION         = 0x090,   /* Delete the guest's SNP context */
    SNP_MCMD_ID_ACTIVATE             = 0x091,   /* Load a guest's key into the UMC */
    SNP_MCMD_ID_GUEST_STATUS         = 0x092,   /* Query the status and metadata of a guest */
    SNP_MCMD_ID_GCTX_CREATE          = 0x093,   /* Create a Guest context */
    SNP_MCMD_ID_GUEST_REQUEST        = 0x094,   /* Process a Guest request */
    SNP_MCMD_ID_ACTIVATE_EX          = 0x095,   /* The guest is bound to a particular ASID and to CCX(s) which will be
                                                   allowed to run the guest. Then guest's key is loaded into the UMC */

    /* SNP Guest launch commands */
    SNP_MCMD_ID_LAUNCH_START         = 0x0A0,   /* Begin to launch a new SNP enabled guest */
    SNP_MCMD_ID_LAUNCH_UPDATE        = 0x0A1,   /* Encrypt guest data for launch */
    SNP_MCMD_ID_LAUNCH_FINISH        = 0x0A2,   /* Complete launch of guest */

    /* SNP Debugging commands */
    SNP_MCMD_ID_DBG_DECRYPT          = 0x0B0,   /* Decrypt guest memory region for debugging */
    SNP_MCMD_ID_DBG_ENCRYPT          = 0x0B1,   /* Encrypt guest memory region for debugging */

    /* SNP Page Migration commands */
    SNP_MCMD_ID_SWAP_OUT             = 0x0C0,   /* Encrypt guest memory region for temporary storage */
    SNP_MCMD_ID_SWAP_IN              = 0x0C1,   /* Reverse of SNP_MCMD_ID_SWAP_OUT */
    SNP_MCMD_ID_PAGE_MOVE            = 0x0C2,   /* Moves contents of SNP-protected pages */
    SNP_MCMD_ID_MD_INIT              = 0x0C3,   /* Init the Metadata page */

    /* SNP misc commands */
    SNP_MCMD_ID_PAGE_SET_STATE       = 0x0C6,   /* Transitions 'n' pages Firmware to HV-fixed state */
    SNP_MCMD_ID_PAGE_RECLAIM         = 0x0C7,   /* Clear the immutable bit on a page */
    SNP_MCMD_ID_PAGE_UNSMASH         = 0x0C8,   /* Combine 512 4k pages into one 2M page in RMP */
    SNP_MCMD_ID_CONFIG               = 0x0C9,   /* Set the system wide configuration values */
    SNP_MCMD_ID_DOWNLOAD_FIRMWARE_EX = 0x0CA,   /* Perform a live update of SNP firmware */
    SNP_MCMD_ID_COMMIT               = 0x0CB,   /* Commit the current firmware */
    SNP_MCMD_ID_DLFW_CONTINUE        = 0x0CC,   /* NOT PUBLISHED. INTERNAL TO FW ONLY. */
    SNP_MCMD_ID_VLEK_LOAD            = 0x0CD,   /* Load an attestation key */
    SNP_MCMD_ID_FEATURE_INFO         = 0x0CE,   /* Feature discovery */

    SEV_MCMD_ID_LIMIT,                          /* Invalid command ID */

    SEV_MCMD_FORCE_32_BIT_ENUM       = 0x7FFFFFFF /*!< [UNUSED] Added to force this enum to 32-bits */
} sev_mcmd_id_t;

/* Keep these in order of Command ID */
/**
 * The following commands don't have args
 * sev_mcmd_shutdown_t
 * sev_mcmd_platform_reset_t
 * sev_mcmd_pek_gen_t
 * sev_mcmd_pdh_gen_t
 * sev_mcmd_df_flush_t
 * sev_mcmd_nop_t
 * snp_mcmd_init_t
 * snp_mcmd_shutdown_t
 * snp_mcmd_df_flush_t
 */
/* SEV Commands */
typedef struct sev_mcmd_init {
    uint16_t flags;
    uint8_t  reserved[6];
    uint64_t tmr_paddr;
    uint32_t tmr_length;
} sev_mcmd_init_t;

typedef struct sev_mcmd_platform_status {
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  state;
    uint8_t  platform_flags;
    uint16_t config_flags;
    uint8_t  reserved;
    uint8_t  build_id;
    uint32_t guest_count;
} sev_mcmd_platform_status_t;

typedef struct sev_mcmd_pek_csr {
    uint64_t pek_csr_paddr;
    uint32_t pek_csr_len;
} sev_mcmd_pek_csr_t;

typedef struct sev_mcmd_pek_cert_import {
    uint64_t pek_cert_paddr;
    uint32_t pek_cert_len;
    uint32_t reserved;
    uint64_t oca_cert_paddr;
    uint32_t oca_cert_len;
} sev_mcmd_pek_cert_import_t;

typedef struct sev_mcmd_pdh_cert_export {
    uint64_t pdh_cert_paddr;
    uint32_t pdh_cert_len;
    uint32_t reserved;
    uint64_t cert_chain_paddr;
    uint32_t certs_len;
} sev_mcmd_pdh_cert_export_t;

typedef struct sev_mcmd_download_firmware {
    uint64_t firmware_paddr;
    uint32_t firmware_len;
} sev_mcmd_download_firmware_t;

typedef struct sev_mcmd_get_id {
    uint64_t id_paddr;
    uint32_t id_len;
} sev_mcmd_get_id_t;

typedef struct sev_mcmd_init_ex {
    uint32_t iex_len;
    uint16_t flags;
    uint8_t  reserved1[2];
    uint64_t tmr_paddr;
    uint32_t tmr_length;
    uint32_t reserved2;
    uint64_t nv_paddr;
    uint32_t nv_length;
} sev_mcmd_init_ex_t;

typedef struct sev_mcmd_decommission {
    uint32_t handle;
} sev_mcmd_decommission_t;

typedef struct sev_mcmd_activate {
    uint32_t handle;
    uint32_t asid;
} sev_mcmd_activate_t;

typedef struct sev_mcmd_deactivate {
    uint32_t handle;
} sev_mcmd_deactivate_t;

typedef struct sev_mcmd_guest_status {
    uint32_t handle;
    uint32_t policy;
    uint32_t asid;
    uint8_t  state;
} sev_mcmd_guest_status_t;

typedef struct sev_mcmd_copy {
    uint32_t handle;
    uint32_t length;
    uint64_t src_paddr;
    uint64_t dst_paddr;
} sev_mcmd_copy_t;

typedef struct sev_mcmd_activate_ex {
    uint32_t ex_len;    /* Length of the command buffer. 18h for 0.17 of the API */
    uint32_t handle;    /* Guest handle */
    uint32_t asid;      /* ASID to activate the guest with */
    uint32_t numids;    /* Number of APIC IDs in IDs_PADDR list. */
    uint64_t ids_paddr; /* System physical address of the list of APIC IDs */
} sev_mcmd_activate_ex_t;

typedef struct sev_mcmd_launch_start {
    uint32_t handle;
    uint32_t policy;
    uint64_t dh_cert_paddr;
    uint32_t dh_cert_len;
    uint32_t reserved;
    uint64_t session_paddr;
    uint32_t session_len;
} sev_mcmd_launch_start_t;

typedef struct sev_mcmd_launch_update {
    uint32_t handle;
    uint32_t reserved;
    uint64_t paddr;
    uint32_t length;
} sev_mcmd_launch_update_t;

typedef struct sev_mcmd_launch_measure {
    uint32_t handle;
    uint32_t reserved;
    uint64_t measure_paddr;
    uint32_t measure_len;
} sev_mcmd_launch_measure_t;

typedef struct sev_mcmd_transport {
    uint32_t handle;
    uint32_t reserved;
    uint64_t hdr_paddr;
    uint32_t hdr_size;
    uint32_t reserved2;
    uint64_t guest_paddr;
    uint32_t guest_len;
    uint32_t reserved3;
    uint64_t trans_paddr;
    uint32_t trans_len;
} sev_mcmd_transport_t;

typedef struct sev_mcmd_launch_finish {
    uint32_t handle;
} sev_mcmd_launch_finish_t;

typedef struct sev_mcmd_attestation {
    uint32_t handle;
    uint32_t reserved;
    uint64_t paddr;
    uint8_t mnonce[16];
    uint32_t length;
} sev_mcmd_attestation_t;

typedef struct sev_mcmd_attestation_report {
    uint8_t mnonce[16];
    uint8_t launch_digest[32];
    uint32_t policy;
    uint32_t sig_usage;
    uint32_t sig_algo;
    uint32_t reserved;
    uint8_t sig1[144];
} sev_mcmd_attestation_report_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_mcmd_attestation_report_t) == 0xD0, this_file);

typedef struct sev_mcmd_send_start {
    uint32_t handle;
    uint32_t policy;
    uint64_t pdh_cert_paddr;
    uint32_t pdh_cert_len;
    uint32_t reserved2;
    uint64_t plat_certs_paddr;
    uint32_t plat_certs_len;
    uint32_t reserved3;
    uint64_t amd_certs_paddr;
    uint32_t amd_certs_len;
    uint32_t reserved4;
    uint64_t session_paddr;
    uint32_t session_len;
} sev_mcmd_send_start_t;

typedef struct sev_mcmd_send_finish {
    uint32_t handle;
} sev_mcmd_send_finish_t;

typedef struct sev_mcmd_send_cancel {
    uint32_t handle;
} sev_mcmd_send_cancel_t;

typedef struct sev_mcmd_receive_start {
    uint32_t handle;
    uint32_t policy;
    uint64_t pdh_cert_paddr;
    uint32_t pdh_cert_len;
    uint32_t reserved2;
    uint64_t session_paddr;
    uint32_t session_len;
} sev_mcmd_receive_start_t;

typedef struct send_receive_update_aad {
    uint8_t  pad[3];
    uint8_t  channel_ctx;        /* [in] --->  0  keep these fields together */
    uint32_t header_flags;       /* [in] --->  1 */
    uint8_t  iv[16];             /* [out] -->  5 */
    uint32_t uncompressed_size;  /* [in] ---> 21 */
    uint32_t trans_size;         /* [in] ---> 25 */
} send_receive_update_aad_t;

typedef struct sev_mcmd_receive_finish {
    uint32_t handle;
} sev_mcmd_receive_finish_t;

typedef struct sev_mcmd_debug {
    uint32_t handle;
    uint32_t reserved;
    uint64_t src_paddr;
    uint64_t dst_paddr;
    uint32_t length;
} sev_mcmd_debug_t;

typedef struct sev_mcmd_swap_out {
    uint32_t handle;
    uint32_t page_size      : 1;    /* bit 0            0h is 4k page, 1h is 2MB page */
    uint32_t page_type      : 2;    /* bits 1 to 2      0h is data page, 2h is VMSA page page */
    uint32_t reserved3      : 29;   /* bits 3 to 31 */
    uint64_t src_paddr;
    uint64_t dst_paddr;
    uint64_t mdata_paddr;
    uint64_t software_data;
} __attribute__((packed)) sev_mcmd_swap_out_t;

typedef struct sev_mcmd_swap_in {
    uint32_t handle;
    uint32_t page_size      : 1;    /* bit 0            0h is 4k page, 1h is 2MB page */
    uint32_t page_type      : 2;    /* bits 1 to 2      0h is data page, 2h is VMSA page page */
    uint32_t swap_in_place  : 1;    /* bit 3            Indicates src and dst pAddr's are the same */
    uint32_t reserved2      : 28;   /* bits 4 to 31 */
    uint64_t src_paddr;
    uint64_t dst_paddr;
    uint64_t mdata_paddr;
} __attribute__((packed)) sev_mcmd_swap_in_t;

typedef struct sev_mcmd_swap_io_mdata {
    uint64_t software_data; /* Supplied by hypervisor */
    uint64_t iv;            /* oek_iv_count */
    uint8_t  auth_tag[16];
    uint64_t reserved;
    uint64_t reserved2;
    uint32_t reserved3;
    uint64_t reserved4;
    uint32_t page_size      : 1;    /* bit 0            0h is 4k page, 1h is 2MB page */
    uint32_t page_type      : 2;    /* bits 1 to 2      0h is data page, 2h is VMSA page page */
    uint32_t reserved5      : 29;   /* bits 3 to 31 */
} __attribute__((packed)) sev_mcmd_swap_io_mdata_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_mcmd_swap_io_mdata_t) == 0x40, this_file);

typedef struct sev_mcmd_ring_buffer {
    uint64_t low_priority_cmd_ptr;
    uint64_t low_priority_status_ptr;
    uint64_t high_priority_cmd_ptr;
    uint64_t high_priority_status_ptr;
    uint8_t  low_priority_queue_size;
    uint8_t  high_priority_queue_size;
    uint16_t low_q_threshold;
    uint16_t high_q_threshold;
    uint16_t int_on_empty;
} __attribute__((packed)) sev_mcmd_ring_buffer_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_mcmd_ring_buffer_t) == 0x28, this_file);

/* Return values from SNP_FEATURE_INFO command */
typedef struct snp_feature_info {
    uint32_t eax, ebx, ecx, edx;
} snp_feature_info_t;

/* SNP commands */
/**
 * Note that we are not using bitfields for the paddr's below because you
 * can't pass the address to our get_rmp_paddr functions. So pass the entire
 * 64bit value and just don't touch the lowest 12 bits
 */
typedef struct snp_mcmd_platform_status {
    uint64_t status_paddr;   /* sPA of region to write platform information */
} snp_mcmd_platform_status_t;

typedef struct snp_platform_status_buffer {
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  state;
    uint8_t  is_rmp_init  : 1;  /* bit 0 */
    uint8_t  reserved     : 7;  /* bits 1 to 7 */
    uint32_t build_id;
    uint8_t  mask_chip_id : 1;  /* bit 0 */
    uint8_t  mask_chip_key : 1; /* bit 1 */
    uint8_t  vlek_en      : 1;  /* bit 2 */
    uint8_t  feature_info : 1;  /* bit 3 */
    uint32_t reserved2    : 28; /* bits 4 to 31 */
    uint32_t guest_count;       /* SNP Guest count */
    uint64_t tcb_version;       /* Platform/installed version */
    uint64_t reported_tcb;      /* snp_config() version */
} snp_platform_status_buffer_t;

typedef struct snp_mcmd_init_ex {
    uint32_t init_rmp      : 1;     /* bit 0 */
    uint32_t list_paddr_en : 1;     /* bit 1 */
    uint32_t reserved      : 30;    /* bits 2 to 31 */
    uint32_t reserved2;
    uint64_t list_paddr;
    uint8_t  reserved3[0x40-0x10];
} __attribute__((packed)) snp_mcmd_init_ex_t;

typedef struct snp_mcmd_shutdown_ex {
    uint32_t length;
    uint32_t iommu_snp_shutdown : 1;    /* bit 0 */
    uint32_t x86_snp_shutdown   : 1;    /* bit 1 */
    uint32_t reserved           : 30;   /* bits 2 to 31 */
} __attribute__((packed)) snp_mcmd_shutdown_ex_t;

typedef struct snp_mcmd_decommission {
    uint64_t gctx_paddr;    /* sPA of the guest context page */
} snp_mcmd_decommission_t;

typedef struct snp_mcmd_activate {
    uint64_t gctx_paddr;    /* sPA of the guest context page */
    uint32_t asid;
} snp_mcmd_activate_t;

typedef struct snp_mcmd_guest_status {
    uint64_t gctx_paddr;    /* sPA of the guest context page */
    uint64_t status_paddr;  /* sPA of page to receive status information */
} snp_mcmd_guest_status_t;

typedef struct snp_guest_status_buffer {
    uint64_t policy;
    uint32_t asid;
    uint8_t state;
    uint8_t reserved;
    uint8_t reserved2[2];
    uint32_t vcek_dis : 1;  /* Bit 0 - Value of VcekDis for this guest */
    uint32_t reservedbits : 31;  /* Bits 1 to 31 */
    uint32_t reserved3;
    uint64_t reserved4;
} snp_guest_status_buffer_t;

typedef struct snp_mcmd_activate_ex {
    uint32_t ex_len;        /* Length of command buffer. 20h for this version */
    uint32_t reserved;
    uint64_t gctx_paddr;    /* sPA of the guest context page */
    uint32_t asid;          /* ASID to activate the guest with */
    uint32_t numids;        /* Number of APIC IDs in IDs_PADDR list. */
    uint64_t ids_paddr;     /* System physical address of the list of APIC IDs */
} snp_mcmd_activate_ex_t;

typedef struct snp_mcmd_gctx_create {
    uint64_t gctx_paddr;    /* sPA of the guest context page */
} snp_mcmd_gctx_create_t;

typedef struct snp_mcmd_guest_request {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint64_t request_paddr;     /* Request message */
    uint64_t response_paddr;    /* Response message */
} snp_mcmd_guest_request_t;

typedef struct snp_mcmd_launch_start {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint64_t policy;
    uint64_t ma_gctx_paddr;     /* sPA of the guest context of the migration agent */
    uint32_t ma_en      : 1;    /* bit 0        1=guest associated with a migration agent, else 0 */
    uint32_t imi_en     : 1;    /* bit 1        1=launch flow is launching an IMI for guest-assisted migration */
    uint32_t reserved   : 30;   /* bits 2 to 31 reserved */
    uint32_t desired_tsc_freq;  /* Hypervisor desired TSC frequency in MHz */
    uint8_t  gosvw[16];         /* HV provided value for guest OS visible workarounds */
} snp_mcmd_launch_start_t;

typedef struct snp_mcmd_launch_update {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint32_t page_size   : 1;   /* bit 0        0h is 4k page, 1h is 2MB page */
    uint32_t page_type   : 3;   /* bits 1 to 3 */
    uint32_t imi_page    : 1;   /* bit 4 */
    uint32_t reserved    : 27;  /* bits 5 to 31 */
    uint32_t reserved2;
    uint64_t page_paddr;
    uint32_t reserved3   : 8;   /* bits 0 to 7 */
    uint32_t vmpl1_perms : 8;   /* bits 8 to 15 */
    uint32_t vmpl2_perms : 8;   /* bits 16 to 23 */
    uint32_t vmpl3_perms : 8;   /* bits 24 to 31 */
    uint32_t reserved4   : 32;  /* bits 32 to 63 */
} snp_mcmd_launch_update_t;

typedef struct snp_mcmd_launch_update_page_info {  // digest
    uint8_t digest_cur[48];
    uint8_t contents[48];
    uint16_t length;
    uint8_t page_type;
    uint8_t imi_page : 1;       /* bit 0 */
    uint8_t reserved : 7;       /* bits 1 to 7 */
    uint8_t reserved2;
    uint8_t vmpl1_perms;
    uint8_t vmpl2_perms;
    uint8_t vmpl3_perms;
    uint64_t gpa;
} __attribute__((packed)) snp_mcmd_launch_update_page_info_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_mcmd_launch_update_page_info_t) == 0x70, this_file);

#define SNP_LAUNCH_UPDATE_SECRETS_PAGE_VERSION  3
typedef struct snp_launch_update_secrets_page {
    uint32_t version;
    uint8_t imi_en    : 1;      /* bit 0 */
    uint32_t reserved : 31;     /* bits 1 to 31 */
    uint32_t fms;               /* family, model, stepping */
    uint32_t reserved2;
    uint8_t gosvw[16];
    uint8_t vmpck0[32];
    uint8_t vmpck1[32];
    uint8_t vmpck2[32];
    uint8_t vmpck3[32];
    uint8_t reserved_guest_os[0x100-0xA0];
    uint8_t vmsa_tweak_bitmap[0x140-0x100];
    uint8_t reserved3[0x160-0x140]; /* Reserved for guest OS usage */
    uint32_t tsc_factor;
    uint8_t reserved4[0x1000-0x164];
} snp_launch_update_secrets_page_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_launch_update_secrets_page_t) == 0x1000, this_file);

typedef struct snp_launch_update_cpuid_page {
    uint32_t count;
    uint32_t reserved;
    uint64_t reserved2;
    snp_cpuid_function_t cpuids[SNP_CPUID_COUNT_MAX];
} snp_launch_update_cpuid_page_t;

typedef struct snp_mcmd_launch_finish {
    uint64_t gctx_paddr;
    uint64_t id_block_paddr;
    uint64_t id_auth_paddr;
    uint8_t id_block_en     : 1;    /* bit 0 */
    uint8_t auth_key_en     : 1;    /* bit 1 */
    uint8_t vcek_dis        : 1;    /* bit 2 */
    uint64_t reserved       : 61;   /* bits 3 to 63 */
    uint8_t  host_data[32];
} snp_mcmd_launch_finish_t;

#define SNP_LAUNCH_FINISH_ID_BLOCK_MAX_VERSION 1
typedef struct snp_mcmd_launch_finish_id_block {
    uint8_t  ld[48];            /* The expected launch digest of the guest */
    uint8_t  family_id[16];     /* Family ID of the guest */
    uint8_t  image_id[16];      /* Image ID of the guest */
    uint32_t version;           /* Version of the ID block format */
    uint32_t guest_svn;         /* SVN of the guest */
    uint64_t policy;            /* The policy of the guest */
} snp_mcmd_launch_finish_id_block_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_mcmd_launch_finish_id_block_t) == 0x290-0x230, this_file);  /* Must fit into Import/Export struct */

typedef struct snp_mcmd_launch_finish_id_auth_page {
    uint32_t id_key_algo;               /* The algorithm of the ID Key */
    uint32_t auth_key_algo;             /* The algorithm of the Author Key */
    uint8_t reserved[0x40-0x8];
    uint8_t id_block_sig[0x240-0x40];   /* The signature of the ID block */
    uint8_t id_key[0x644-0x240];        /* The public component of the ID key */
    uint8_t reserved2[0x680-0x644];
    uint8_t id_key_sig[0x880-0x680];    /* The signature of the ID_KEY */
    uint8_t author_key[0xC84-0x880];    /* The public component of the Author key */
    uint8_t reserved3[0x1000-0xC84];
} snp_mcmd_launch_finish_id_auth_page_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_mcmd_launch_finish_id_auth_page_t) == 0x1000, this_file);

typedef struct snp_mcmd_dbg_decrypt {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint64_t src_paddr;
    uint64_t dst_paddr;
} snp_mcmd_dbg_decrypt_t;

typedef struct snp_mcmd_dbg_encrypt {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint64_t src_paddr;
    uint64_t dst_paddr;
} snp_mcmd_dbg_encrypt_t;

typedef struct snp_mcmd_swap_out {
    uint64_t gctx_paddr;            /* sPA of the guest context page */
    uint64_t src_paddr;             /* sPA of src page */
    uint64_t dst_paddr;             /* sPA of dst page */
    uint64_t mdata_paddr;           /* sPA of metadata entry (mdata) */
    uint64_t software_data;         /* software available data supplied by hypervisor */
    uint32_t page_size      : 1;    /* bit 0            0h is 4k page, 1h is 2MB page */
    uint32_t page_type      : 2;    /* bits 1 to 2      0h is data page, 1h is Metadata, 2 is VMSA page page */
    uint32_t reserved       : 1;    /* bit 3 */
    uint32_t root_mdata_en  : 1;    /* bit 4            MDATA entry will be stored in gctx, not in MDATA_PADDR. */
    uint64_t reserved2      : 59;   /* bits 5 to 63 */
} snp_mcmd_swap_out_t;

typedef struct snp_mcmd_swap_in {
    uint64_t gctx_paddr;            /* sPA of the guest context page */
    uint64_t src_paddr;             /* sPA of src page */
    uint64_t dst_paddr;             /* sPA of dst page */
    uint64_t mdata_paddr;           /* sPA of metadata entry (mdata) */
    uint64_t reserved;
    uint32_t page_size      : 1;    /* bit 0            0h is 4k page, 1h is 2MB page */
    uint32_t page_type      : 2;    /* bits 1 to 2      0h is data page, 1h is Metadata, 2 is VMSA page page */
    uint32_t swap_in_place  : 1;    /* bit 3            Indicates src and dst pAddr's are the same */
    uint32_t root_mdata_en  : 1;    /* bit 4            MDATA entry will be stored in gctx, not in MDATA_PADDR. */
    uint64_t reserved2      : 59;   /* bits 5 to 63 */
} snp_mcmd_swap_in_t;

typedef struct snp_mcmd_page_move {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint32_t page_size  : 1;    /* bit 0                0h is 4k page, 1h is 2MB page. */
    uint32_t reserved   : 31;   /* bits 1 to 31 */
    uint32_t reserved2;
    uint64_t src_paddr;         /* sPA of src page */
    uint64_t dst_paddr;         /* sPA of dst page */
} snp_mcmd_page_move_t;

typedef struct snp_mcmd_md_init {
    uint64_t gctx_paddr;        /* sPA of the guest context page */
    uint64_t page_paddr;        /* sPA of page to turn into metadata page */
} snp_mcmd_md_init_t;

typedef struct snp_mcmd_page_set_state {
    uint32_t length;
    uint32_t reserved;
    uint64_t list_paddr;
} snp_mcmd_page_set_state_t;

typedef struct snp_mcmd_page_reclaim {
    uint64_t page_paddr_size;   /* both params */
} snp_mcmd_page_reclaim_t;

typedef struct snp_mcmd_page_unsmash {
    uint64_t page_paddr;        /* 4K page, 2MB aligned */
} snp_mcmd_page_unsmash_t;

typedef struct snp_mcmd_config {
    uint64_t reported_tcb;
    uint8_t  mask_chip_id : 1;  /* bit 0 */
    uint8_t  mask_chip_key : 1; /* bit 1 */
    uint32_t reserved     : 30; /* bits 2 to 31 */
    uint8_t  reserved2[0x40-0xC];
} snp_mcmd_config_t;

typedef struct snp_mcmd_download_firmware_ex {
    uint32_t length;
    uint32_t reserved;
    uint64_t fw_paddr;
    uint32_t fw_len;
    uint8_t commit     : 1;  /* bit 0 */
    uint32_t reserved2 : 31; /* bits 1 to 31 */
} snp_mcmd_download_firmware_ex_t;

typedef struct snp_mcmd_commit {
    uint32_t length;
} snp_mcmd_commit_t;

typedef struct snp_mcmd_vlek_load {
    uint32_t length;
    uint8_t vlek_wrapped_version;
    uint8_t reserved[3];
    uint64_t vlek_wrapped_paddr;
} snp_mcmd_vlek_load_t;

typedef struct snp_mcmd_feature_info {
    uint32_t length;
    uint32_t ecx_in;
    uint64_t feature_info_paddr;
} snp_mcmd_feature_info_t;

/* Defines */
typedef enum snp_launch_update_page
{
    SNP_PAGE_TYPE_RESERVED   = 0x0,
    SNP_PAGE_TYPE_NORMAL     = 0x1, /* Normal data page */
    SNP_PAGE_TYPE_VMSA       = 0x2, /* VMSA page */
    SNP_PAGE_TYPE_ZERO       = 0x3, /* Page full of zeros */
    SNP_PAGE_TYPE_UNMEASURED = 0x4, /* Encrypted but not measured */
    SNP_PAGE_TYPE_SECRETS    = 0x5, /* Where firmware stores secrets for the guest */
    SNP_PAGE_TYPE_CPUID      = 0x6, /* Where hypervisor provides CPUID function values */
} snp_launch_update_page_t;

typedef enum snp_signature_algo
{
    SNP_SIGNATURE_ALGO_ECDSA_P384_SHA384 = 0x1,
} snp_signature_algo_t;

typedef enum swap_io_page
{                                   /*  METADATA    VMSA */
    SWAP_IO_DATA_PAGE     = 0x0,    /*  0           0    */
    SWAP_IO_METADATA_PAGE = 0x1,    /*  1           0    */
    SWAP_IO_VMSA_PAGE     = 0x2,    /*  0           1    */
    SWAP_IO_INVALID,
} swap_io_page_t;

#define SNP_RANGE_LIST_MAX_COUNT (4096/sizeof(snp_range_t)-1)
// Really want it to be: ((4096 - (offsetof(struct snp_range_list, ranges)))/sizeof(snp_range_t)) /* 255 */
typedef struct snp_range
{
    uint64_t base;
    uint32_t page_count;
    uint32_t reserved;
} snp_range_t;

typedef struct snp_range_list
{
    uint32_t n;
    uint32_t reserved;
    snp_range_t ranges[SNP_RANGE_LIST_MAX_COUNT];     /* First byte of sizeof(snp_range_t)*n bytes */
} snp_range_list_t;

/* Keep these in order of Command ID */
/* Some commands (Platforms, Dbg) have common params between SEV and SNP */
typedef union sev_mcmd
{
    sev_mcmd_init_t                 sev_init;
//  sev_mcmd_shutdown_t             shutdown;          /* No args */
//  sev_mcmd_platform_reset_t       platform_reset;    /* No args */
    sev_mcmd_platform_status_t      sev_platform_status;
//  sev_mcmd_pek_gen_t              pek_gen;           /* No args */
    sev_mcmd_pek_csr_t              pek_csr;
    sev_mcmd_pek_cert_import_t      pek_cert_import;
    sev_mcmd_pdh_cert_export_t      pdh_cert_export;
//  sev_mcmd_pdh_gen_t              pdh_gen;           /* No args */
//  sev_mcmd_df_flush_t             df_flush;          /* No args */
    sev_mcmd_download_firmware_t    download_firmware;
    sev_mcmd_get_id_t               get_id;
    sev_mcmd_init_ex_t              sev_init_ex;
//  sev_mcmd_nop_t                  nop;               /* No args */
    sev_mcmd_ring_buffer_t          ring_buffer;
    sev_mcmd_decommission_t         sev_decommission;
    sev_mcmd_activate_t             sev_activate;
    sev_mcmd_deactivate_t           sev_deactivate;
    sev_mcmd_guest_status_t         sev_guest_status;
    sev_mcmd_copy_t                 sev_copy;
    sev_mcmd_activate_ex_t          sev_activate_ex;
    sev_mcmd_launch_start_t         sev_launch_start;
    sev_mcmd_launch_update_t        sev_launch_update;
    sev_mcmd_launch_measure_t       sev_launch_measure;
    sev_mcmd_transport_t            sev_launch_secret;
    sev_mcmd_launch_finish_t        sev_launch_finish;
    sev_mcmd_attestation_t          attestation;
    sev_mcmd_send_start_t           sev_send_start;
    sev_mcmd_transport_t            sev_send_update;
    sev_mcmd_send_finish_t          sev_send_finish;
    sev_mcmd_send_cancel_t          sev_send_cancel;
    sev_mcmd_receive_start_t        sev_receive_start;
    sev_mcmd_transport_t            sev_receive_update;
    sev_mcmd_receive_finish_t       sev_receive_finish;
    sev_mcmd_debug_t                debug;
    sev_mcmd_swap_out_t             sev_swap_out;
    sev_mcmd_swap_in_t              sev_swap_in;

//  snp_mcmd_init_t                 snp_init;              /* No args */
//  sev_mcmd_shutdown_t             snp_shutdown;          /* No args */
    snp_mcmd_platform_status_t      snp_platform_status;
//  sev_mcmd_df_flush_t             snp_df_flush;          /* No args */
    snp_mcmd_init_ex_t              snp_init_ex;
    snp_mcmd_shutdown_ex_t          snp_shutdown_ex;
    snp_mcmd_decommission_t         snp_decommission;
    snp_mcmd_activate_t             snp_activate;
    snp_mcmd_guest_status_t         snp_guest_status;
    snp_mcmd_activate_ex_t          snp_activate_ex;
    snp_mcmd_gctx_create_t          snp_gctx_create;
    snp_mcmd_guest_request_t        snp_guest_request;
    snp_mcmd_launch_start_t         snp_launch_start;
    snp_mcmd_launch_update_t        snp_launch_update;
    snp_mcmd_launch_finish_t        snp_launch_finish;
    snp_mcmd_dbg_decrypt_t          snp_dbg_decrypt;
    snp_mcmd_dbg_encrypt_t          snp_dbg_encrypt;
    snp_mcmd_swap_out_t             snp_swap_out;
    snp_mcmd_swap_in_t              snp_swap_in;
    snp_mcmd_page_move_t            snp_page_move;
    snp_mcmd_md_init_t              snp_md_init;
    snp_mcmd_page_reclaim_t         snp_page_reclaim;
    snp_mcmd_page_unsmash_t         snp_page_unsmash;
    snp_mcmd_config_t               snp_config;
    snp_mcmd_download_firmware_ex_t snp_download_firmware_ex;
    snp_mcmd_commit_t               snp_commit;
    snp_mcmd_page_set_state_t       snp_page_set_state;
    snp_mcmd_vlek_load_t            snp_vlek_load;
    snp_mcmd_feature_info_t         snp_feature_info;

    /** XXX may add more here **/
} sev_mcmd_t;

/* Keep these in order of Command ID */
sev_status_t sev_mcmd_init(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_shutdown(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t sev_mcmd_platform_reset(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t sev_mcmd_platform_status(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_pek_gen(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t sev_mcmd_pek_csr(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_pek_cert_import(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_pdh_cert_export(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_pdh_gen(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t sev_mcmd_df_flush(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t sev_mcmd_download_firmware(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_get_id(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_init_ex(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_nop(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t sev_mcmd_ring_buffer(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_decommission(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_activate(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_deactivate(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_guest_status(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_copy(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_activate_ex(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_launch_start(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_launch_update_data(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_launch_update_vmsa(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_launch_measure(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_launch_secret(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_launch_finish(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_attestation(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_send_start(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_send_update_data(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_send_update_vmsa(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_send_finish(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_send_cancel(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_receive_start(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_receive_update_data(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_receive_update_vmsa(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_receive_finish(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_dbg_decrypt(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_dbg_encrypt(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_swap_out(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t sev_mcmd_swap_in(sev_t *sev, sev_mcmd_t *cmd);

sev_status_t snp_mcmd_init(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t snp_mcmd_shutdown(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t snp_mcmd_platform_status(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_df_flush(sev_t *sev, sev_mcmd_t *ignored);
sev_status_t snp_mcmd_init_ex(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_shutdown_ex(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_decommission(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_activate(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_guest_status(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_activate_ex(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_gctx_create(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_guest_request(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_launch_start(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_launch_update(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_launch_finish(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_dbg_decrypt(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_dbg_encrypt(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_swap_out(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_swap_in(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_page_move(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_md_init(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_page_reclaim(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_page_unsmash(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_config(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_download_firmware_ex(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_commit(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_page_set_state(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_dlfw_continue(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_vlek_load(sev_t *sev, sev_mcmd_t *cmd);
sev_status_t snp_mcmd_feature_info(sev_t *sev, sev_mcmd_t *cmd);

#endif /* SEV_MCMD_H */
