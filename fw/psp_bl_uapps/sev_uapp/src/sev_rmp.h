// Copyright(C) 2019-2021 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_RMP_H
#define SEV_RMP_H

#include <stddef.h>
#include <stdint.h>

#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "sev_errors.h"

/**
 * 0x3ff is an invalid ASID used specifically here to prevent the x86 from
 * racing to the 2MB RMP entry and updating RMP.Sub_Pages count
 */
#define RMP_INVALID_ASID        0x3ff

#define ALIGNMENT_BITS_4K       12
#define PAGE_SIZE_4K            4096            // 1<<ALIGNMENT_BITS_4K
#define PAGE_SIZE_2M            (512*PAGE_SIZE_4K)

enum DRAM_PAGE_SIZE
{
    DRAM_PAGE_SIZE_4K = 0 << 0,
    DRAM_PAGE_SIZE_2M = 1 << 0,

    DRAM_PAGE_SIZE_LIMIT = 2 << 0,
};

#define RMP_NUM_ASID_COUNTERS   2048

/**
 *  RMP Table Struture:
 *      16Kbytes total (rmp_asid_counters)
 *      rmp_entry tables ()
 */
typedef struct rmp_asid_counters
{
    uint64_t counters[RMP_NUM_ASID_COUNTERS];
} rmp_asid_counters_t;

// http://twiki.amd.com/twiki/bin/view/ZPArch/RMPEntryFormat
typedef struct rmp_fields
{
    uint64_t assigned      : 1;
    uint64_t page_size     : 1;
    uint64_t immutable     : 1;
    uint64_t subpage_count : 9;
    uint64_t gpa           : 39;
    uint64_t asid          : 10;
    uint64_t vmsa          : 1;
    uint64_t validated     : 1;
    uint64_t lock          : 1;
} rmp_fields_t;

typedef union rmp_quadword1
{
    rmp_fields_t f;
    uint64_t     val;
} rmp_quadword1_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(rmp_quadword1_t) == sizeof(uint64_t), this_file);

/* 6.1 Page Security Attributes */
typedef union vmpl_perm_mask
{
    struct
    {
        uint32_t read            : 1;   /* If page is readable by the VMPL */
        uint32_t write           : 1;   /* If page is writable by the VMPL */
        uint32_t exec_user       : 1;   /* If page is executable by the VMPL at CPL3 */
        uint32_t exec_supervisor : 1;   /* If page is executable by the VMPL at CPL0, CPL1, or CPL2 */
        uint32_t sss             : 1;   /* If page can be used by the VMPL as a Supervisor Shadow Stack page */
        uint32_t reserved        : 3;
    } __attribute__((packed)) f;
    uint8_t val;
} __attribute__((packed)) vmpl_perm_mask_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(vmpl_perm_mask_t) == sizeof(uint8_t), this_file);

/**
 * implicit_key_select: Indicates which encryption key to use for this page
 *                      0 = non-persistent key, 1 = persistent key
 * root_port_id:        (Unused in Genoa)
 * pcie_ide_stream_id:  (Unused in Genoa)
 * page_migration:      Indicates that page is being migrated by the PSP
 */
typedef union rmp_quadword2
{
    struct
    {
        vmpl_perm_mask_t vmpl0;
        vmpl_perm_mask_t vmpl1;
        vmpl_perm_mask_t vmpl2;
        vmpl_perm_mask_t vmpl3;
        uint32_t implicit_key_select : 1;   /* bit 32        */
        uint32_t reserved            : 16;  /* bits 33 to 48 */
        uint32_t root_port_id        : 5;   /* bit 49 to 53  */
        uint32_t pcie_ide_stream_id  : 8;   /* bit 54 to 61  */
        uint32_t page_migration      : 2;   /* bits 62 to 63 */
    } __attribute__((packed)) f;
    uint64_t val;
} __attribute__((packed)) rmp_quadword2_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(rmp_quadword2_t) == sizeof(uint64_t), this_file);

typedef struct rmp_entry
{
    rmp_quadword1_t q1;
    rmp_quadword2_t q2;
} rmp_entry_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(rmp_entry_t) == 2*sizeof(uint64_t), this_file);

/**
 * 3.1 Metadata Entries (MDATA)
 * Metadata entry within a metadata page. Each entry is 64 bits, a page is 4k
 * Not bit-for-bit compatible
 */
typedef struct mdata_perm_mask
{
    /* uint64_t of the following */
    uint32_t    valid          : 1;  /* bit 0 */
    uint32_t    page_validated : 1;  /* bit 1 */
    uint32_t    vmsa           : 1;  /* bit 2 */
    uint32_t    metadata       : 1;  /* bit 3 */
    uint32_t    page_size      : 1;  /* 0 = 4k, 1 = 2MB, bit 4 */
    uint32_t    reserved1      : 7;  /* bits 5 to 11 reserved */
    uint64_t    gpa            : 52; /* bits 12 to 63 */
} mdata_perm_mask_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(mdata_perm_mask_t) == sizeof(uint64_t), this_file);

typedef union snp_metadata_entry
{
    mdata_perm_mask_t   f;
    uint64_t            val;
} snp_metadata_entry_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_metadata_entry_t) == sizeof(uint64_t), this_file);

typedef struct snp_metadata_page    /* MDATA */
{
    uint64_t             software_data;  /* 00h */
    uint64_t             iv;             /* 08h */
    uint8_t              auth_tag[16];   /* 10h */
    snp_metadata_entry_t mdata_entry;    /* 20h */
    rmp_quadword2_t      vmpl;           /* 28h */
    uint64_t             reserved2;      /* 30h */
    uint64_t             reserved3;      /* 38h */
} snp_metadata_page_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_metadata_page_t) == 8*sizeof(uint64_t), this_file);

#define RMP_ASID_COUNTERS_SIZE      (sizeof(rmp_asid_counters_t))
#define RMP_QUADPAGE_SIZE           (sizeof(rmp_quadword1_t))       /* 64 bits, 8 bytes */
#define RMP_ENTRY_SIZE              (sizeof(rmp_entry_t))           /* 128 bits, 16 bytes */
#define SNP_METADATA_ENTRY_SIZE     (sizeof(snp_metadata_page_t))   /* 64 bytes */

#define PSP_HASHSTICK_LENGTH        48

typedef enum tcb_hashstick_index
{
    TCB_HASHSTICK_INDEX_PSP_BL        = 0,
    TCB_HASHSTICK_INDEX_PSP_TEE       = 1,
    TCB_HASHSTICK_INDEX_RESERVED_1    = 2,
    TCB_HASHSTICK_INDEX_RESERVED_2    = 3,
    TCB_HASHSTICK_INDEX_RESERVED_3    = 4,
    TCB_HASHSTICK_INDEX_RESERVED_4    = 5,
    TCB_HASHSTICK_INDEX_SEV_UAPP      = 6,
    TCB_HASHSTICK_INDEX_CPU_MICROCODE = 7,
} tcb_hashstick_index_t;

/**
 * 3.2 TCB Version
 * A version string that represents the version of the firmware
 */
typedef union snp_tcb_version    /* TCB */
{
    struct
    {
        uint8_t boot_loader;    /* SVN of PSP bootloader */
        uint8_t tee;            /* SVN of PSP operating system */
        uint8_t reserved[4];
        uint8_t snp;            /* SVN of SNP firmware */
        uint8_t microcode;      /* Lowest current patch level of all the cores */
    } __attribute__((packed)) f;
    uint64_t val;
} __attribute__((packed)) snp_tcb_version_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_tcb_version_t) == sizeof(uint64_t), this_file);

/**
 * 5.1 Guest Context
 * This is the data that's stored into the guest context page (GCTX_PADDR)
 * for each guest
 * All secrets must not be in the same 16B block as any HV-controlled param
 */
typedef struct guest_context_page
{
    sev_guest_t guest;

    /* asid, state, policy, ld, oek, vek, are in sev_guest_t */
    uint64_t msg_count0;        /* Number of successful vmpck0 messages sent since Guest was created */
    uint64_t msg_count1;        /* Number of successful vmpck1 messages sent since Guest was created */
    uint64_t msg_count2;        /* Number of successful vmpck2 messages sent since Guest was created */
    uint64_t msg_count3;        /* Number of successful vmpck3 messages sent since Guest was created */
    uint64_t migration_agent_paddr; /* The migration agent of the guest, if the guest is associated with a migration agent */
    uint8_t vmpck0[32] __attribute__((aligned (GUEST_MIN_ALIGN)));  /* Virtual Machine Platform Communication Key */
    uint8_t vmpck1[32];
    uint8_t vmpck2[32];
    uint8_t vmpck3[32];
    uint8_t vmrk[32];           /* VM root key generated during Guest launch start or provided by the migration agent at Guest import */
    uint8_t host_data[32];      /* Host data provided by the hypervisor during launch finish */
    bool id_block_en;           /* Indicates whether an ID block was associated with the guest */
    snp_mcmd_launch_finish_id_block_t id_block; /* The associated ID block, if any */
    uint8_t id_key_digest[48];      /* The ID key digest, if any */
    bool author_key_en;             /* Indicates if an Author key signed the ID key */
    uint8_t author_key_digest[48];  /* The Author key digest, if any */
    uint8_t report_id[32];      /* Generated during launch start */
    uint8_t report_id_ma[32];   /* Copied from MA during LaunchStart */
    snp_metadata_page_t root_md_entry;
    uint8_t imd[48];            /* The measurement of the Incoming Migration Image (IMI) */
    bool imi_en;                /* Indicates whether the current launch flow is an IMI migration or not */
    uint8_t measurement[48];    /* The measurement of every Launch Update page */
    uint8_t gosvw[16];          /* Guest OS visible workarounds. Provided by hypervisor during launch */
    uint32_t desired_tsc_freq;  /* Desired TSC frequency of the guest in kHz */
    uint64_t psp_tsc_offset;    /* Offset applied to guest TSC reads */
    snp_tcb_version_t launch_tcb; /* The TCB version that this guest was launched or migrated in at */
    uint8_t current_build_id;   /* The firmware version that last updated or created this guest context page */
    uint8_t current_api_minor;
    uint8_t current_api_major;
    bool vcek_dis;
} guest_context_page_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(guest_context_page_t) <= PAGE_SIZE_4K, this_file);

/* 6.2 Page States */
typedef enum snp_page_state
{                        // Controlled by:   SW       HW        SW   SW        HW   SW  HW
    // Page State                            Assigned Validated ASID Immutable Lock GPA VMSA
    SNP_PAGE_STATE_INVALID        = 0x0,
    SNP_PAGE_STATE_DEFAULT        = 0x1,
    SNP_PAGE_STATE_HYPERVISOR     = 0x2,  // 0        0         0    0         -    -   -
    SNP_PAGE_STATE_HV_FIXED       = 0x3,  // 0        0         0    1         0    -   -
    SNP_PAGE_STATE_FIRMWARE       = 0x4,  // 1        0         0    1         -    0   0
    SNP_PAGE_STATE_FIRMWARE_IOMMU = 0x5,  // 1        0         0    1         -    1   0
    SNP_PAGE_STATE_RECLAIM        = 0x6,  // 1        0         0    0         -    -   -
    SNP_PAGE_STATE_CONTEXT        = 0x7,  // 1        0         0    1         -    0   1
    SNP_PAGE_STATE_METADATA       = 0x8,  // 1        0         0    1         -    >0  -
    SNP_PAGE_STATE_PRE_GUEST      = 0x9,  // 1        0         >0   1         -    -   -
    SNP_PAGE_STATE_PRE_SWAP       = 0xA,  // 1        1         >0   1         -    -   -
    SNP_PAGE_STATE_GUEST_INVALID  = 0xB,  // 1        0         >0   0         -    -   -
    SNP_PAGE_STATE_GUEST_VALID    = 0xC,  // 1        1         >0   0         -    -   -
    SNP_PAGE_STATE_LIMIT,
} snp_page_state_t;

/**
 * CSF-983. This is a setting the firmware uses to track the difference between
 * FIRMWARE, FIRMWARE_IOMMU, and METADATA pages besides relying solely on the
 * GPA (0 is valid). This is stored in the upper (unused) bits of rmp.gpa
 */
#define RMP_ENTRY_GPA_SHIFT                 (12ULL)
#define RMP_GPA_STATE_SHIFT                 (36ULL)    // Bits [38:36]
#define RMP_GPA_STATE_FLAG                  (0x7ULL << RMP_GPA_STATE_SHIFT)

#define PADDR_GET_GPA(paddr)                (((uint64_t)(paddr) & ~SEV_CBIT_MASK) >> RMP_ENTRY_GPA_SHIFT)
#define PADDR_TO_GPA_FIELD(paddr, state)    (PADDR_GET_GPA(paddr) | ((uint64_t)state << RMP_GPA_STATE_SHIFT))
#define RMP_GET_GPA_STATE(gpa)              (RMP_GPA_STATE_T)(((uint64_t)gpa) >> RMP_GPA_STATE_SHIFT)
#define RMP_GET_GPA(gpa)                    ((uint64_t)gpa & ~(RMP_GPA_STATE_FLAG))
#define RMP_GPA_TO_PADDR(gpa)               ((uint64_t)gpa << RMP_ENTRY_GPA_SHIFT)

typedef enum RMP_GPA_STATE
{                                  // snp_page_state_t
    RMP_GPA_STATE_FIRMWARE = 0x0,  // SNP_PAGE_STATE_FIRMWARE
    RMP_GPA_STATE_METADATA = 0x1,  // SNP_PAGE_STATE_METADATA
    RMP_GPA_STATE_FW_IOMMU = 0x2,  // SNP_PAGE_STATE_FIRMWARE_IOMMU
    RMP_GPA_STATE_LIMIT,
} RMP_GPA_STATE_T;

/* See SNP_GUEST_REQUEST "Message Type Encodings" in spec */
#define SNP_GMSG_MAX_HDR_VERSION                    1
#define SNP_GMSG_MAX_MSG_VERSION_CPUID_REQ          1
#define SNP_GMSG_MAX_MSG_VERSION_CPUID_RSP          1
#define SNP_GMSG_MAX_MSG_VERSION_KEY_REQ            1
#define SNP_GMSG_MAX_MSG_VERSION_KEY_RSP            1
#define SNP_GMSG_MAX_MSG_VERSION_REPORT_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_REPORT_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_EXPORT_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_EXPORT_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_IMPORT_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_IMPORT_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_VMRK_REQ           1
#define SNP_GMSG_MAX_MSG_VERSION_VMRK_RSP           1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_NOMA_REQ    1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_NOMA_RSP    1
#define SNP_GMSG_MAX_MSG_VERSION_TSC_INFO_REQ       1
#define SNP_GMSG_MAX_MSG_VERSION_TSC_INFO_RSP       1
typedef struct snp_guest_message_header /* GMSG */
{
    uint8_t  auth_tag[32];
    uint64_t msg_seqno;     /* Message sequence number */
    uint8_t  reserved[8];
    uint8_t  algo;          /* The AEAD used to encrypt this message */
    uint8_t  hdr_version;
    uint32_t hdr_size : 16;
    uint8_t  msg_type;
    uint8_t  msg_version;
    uint32_t msg_size : 16;
    uint32_t reserved2;
    uint8_t  msg_vmpck;     /* The ID of the VMPCK used to protect this message */
    uint8_t  reserved3;
    uint8_t  reserved4[2];
    uint8_t  reserved5[0x60-0x40];
    uint8_t  payload;       /* Start of payload */
} __attribute__((packed)) snp_guest_message_header_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_guest_message_header_t) == 0x61, this_file);

#define GUEST_REQUEST_HEADER_SIZE offsetof(snp_guest_message_header_t, payload)
#define SNP_GMSG_HDR_AAD_SIZE  (offsetof(snp_guest_message_header_t, payload)-offsetof(snp_guest_message_header_t, algo))
COMMON_COMPILE_TIME_ASSERT(SNP_GMSG_HDR_AAD_SIZE == (0x60-0x30), this_file);

/* AEAD Algorithm Encodings */
enum
{
    AEAD_ALGO_INVALID     = 0,
    AEAD_ALGO_AES_256_GCM = 1,
};

/* key_sel values */
enum
{
    KEY_SEL_VLEK_VCEK = 0,
    KEY_SEL_VCEK_ONLY = 1,
    KEY_SEL_VLEK_ONLY = 2,
    KEY_SEL_RESERVED = 3,
};

/* signing_key values */
enum
{
    SIGNING_KEY_VCEK = 0,
    SIGNING_KEY_VLEK = 1,
    SIGNING_KEY_NONE = 7,
};

/* 8.2 Key Derivation */
typedef struct snp_msg_key_req
{
    uint32_t root_key_select : 1; /* Selects the root key to derive the key from. 0 indicates VCEK. 1 indicates VMRK */
    uint32_t key_sel         : 2; /* Selects which key to use for derivation */
    uint32_t reserved        : 29;
    uint32_t reserved2;
    uint64_t guest_field_select;
    uint32_t vmpl;
    uint32_t guest_svn;
    snp_tcb_version_t tcb_version;
} snp_msg_key_req_t;

#define KEY_REQ_LABEL "gmsg-keyreq"

typedef struct snp_mix_data
{
    uint32_t root_key_select    : 1;    /* bit 0 */
    uint32_t idblock_key_select : 2;    /* bits 1 to 2 */
    uint32_t reserved           : 29;   /* bits 3 to 31 */
    uint32_t reserved2;
    uint64_t gfs;
    uint32_t vmpl;
    uint32_t guest_svn;
    snp_tcb_version_t tcb_version;
    uint64_t guest_policy;
    uint8_t image_id[16];
    uint8_t family_id[16];
    uint8_t measurement[32];
    uint8_t host_data[32];
    uint8_t idblock_key[32];
} __attribute__((packed)) snp_mix_data_t;

/* GUEST_FIELD_SELECT fields */
#define SNP_GUEST_FIELD_GUEST_POLICY_FLAG  (1<<0ULL)    /* The guest policy will be mixed into the key */
#define SNP_GUEST_FIELD_IMAGE_ID_FLAG      (1<<1ULL)    /* The image ID of the guest will be mixed into the key */
#define SNP_GUEST_FIELD_FAMILY_ID_FLAG     (1<<2ULL)    /* The family ID of the guest will be mixed into the key */
#define SNP_GUEST_FIELD_MEASUREMENT_FLAG   (1<<3ULL)    /* The measurement of the guest during launch will be mixed into the key */
#define SNP_GUEST_FIELD_GUEST_SVN_FLAG     (1<<4ULL)    /* The guest-provided SVN will be mixed into the key */
#define SNP_GUEST_FIELD_TCB_VERSION_FLAG   (1<<5ULL)    /* The guest-provided TCB version string will be mixed into the key */
#define SNP_GUEST_FIELD_ALL   (SNP_GUEST_FIELD_GUEST_POLICY_FLAG|SNP_GUEST_FIELD_IMAGE_ID_FLAG|\
                               SNP_GUEST_FIELD_FAMILY_ID_FLAG|SNP_GUEST_FIELD_MEASUREMENT_FLAG|\
                               SNP_GUEST_FIELD_GUEST_SVN_FLAG|SNP_GUEST_FIELD_TCB_VERSION_FLAG)

typedef struct snp_msg_key_rsp
{
    uint32_t status;                /* 0x0 Success, 0x16 Invalid parameters */
    uint8_t reserved[0x20-0x4];
    uint8_t derived_key[32];        /* The requested derived key if STATUS is 0h */
} snp_msg_key_rsp_t;

/* 7.3 Attestation */
typedef struct snp_msg_report_req
{
    uint8_t report_data[64];    /* Guest-provided data for the attestation report */
    uint32_t vmpl;              /* The VMPL to put into the attestation report */
    uint32_t key_sel       : 2;       /* Selects which key to use for derivation */
    uint32_t reserved_bits : 30;
    uint8_t reserved[0x60-0x48];
} snp_msg_report_req_t;

typedef struct snp_attestation_report_platform_info
{
    uint32_t smt_en   : 1;
    uint32_t tsme_en  : 1;
    uint64_t reserved : 62;
} __attribute__((packed)) snp_platform_info_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_platform_info_t) == sizeof(uint64_t), this_file);

#define SNP_GMSG_MAX_REPORT_VERSION 2       /* See "ATTESTATION_REPORT Structure" in spec */
typedef struct snp_attestation_report
{
    uint32_t version;               /* 0h */
    uint32_t guest_svn;             /* 4h */
    uint64_t policy;                /* 8h */
    uint8_t family_id[16];          /* 10h */
    uint8_t image_id[16];           /* 20h */
    uint32_t vmpl;                  /* 30h */
    uint32_t signature_algo;        /* 34h */
    snp_tcb_version_t tcb_version;  /* 38h */
    snp_platform_info_t platform_info; /* 40h */
    uint32_t author_key_en : 1;     /* 48h */
    uint32_t mask_chip_key : 1;
    uint32_t signing_key : 3;
    uint32_t reserved      : 27;
    uint32_t reserved2;             /* 4C */
    uint8_t report_data[64];        /* 50h */
    uint8_t measurement[48];        /* 90h */
    uint8_t host_data[32];          /* C0h */
    uint8_t id_key_digest[48];      /* E0h */
    uint8_t author_key_digest[48];  /* 110h */
    uint8_t report_id[32];          /* 140h */
    uint8_t report_id_ma[32];       /* 160h */
    snp_tcb_version_t reported_tcb; /* 180h */
    uint8_t reserved3[0x1A0-0x188]; /* 188h-19Fh */
    uint8_t chip_id[64];            /* 1A0h */
    snp_tcb_version_t committed_tcb; /* 1E0h */
    uint8_t current_build_id;       /* 1E8h */
    uint8_t current_api_minor;      /* 1E9h */
    uint8_t current_api_major;      /* 1EAh */
    uint8_t reserved4;              /* 1EBh */
    uint8_t committed_build_id;     /* 1ECh */
    uint8_t committed_api_minor;    /* 1EDh */
    uint8_t committed_api_major;    /* 1EEh */
    uint8_t reserved5;              /* 1EFh */
    snp_tcb_version_t launch_tcb;   /* 1F0h */
    uint8_t reserved6[0x2A0-0x1F8]; /* 1F8h */
    uint8_t signature[0x4A0-0x2A0]; /* 2A0h-49Fh */
} __attribute__((packed)) snp_attestation_report_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_attestation_report_t) == 0x4A0, this_file);

typedef struct snp_msg_report_rsp
{
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[0x20-0x08];
    snp_attestation_report_t report;
} __attribute__((packed)) snp_msg_report_rsp_t;

/* 7.4 VM Export */
#define SNP_GMSG_MAX_XPORT_GCTX_VERSION 3   /* Export, Import, Absorb, Absorb_NoMA */
typedef struct snp_msg_export_req
{
    uint64_t gctx_paddr;
    uint32_t imi_en   : 1;
    uint32_t reserved : 31;
    uint32_t reserved2;
} snp_msg_export_req_t;

typedef struct snp_msg_gctx
{
    uint8_t ld[48];
    uint8_t oek[32];
    uint8_t vmpck0[32];
    uint8_t vmpck1[32];
    uint8_t vmpck2[32];
    uint8_t vmpck3[32];
    uint8_t vmrk[32];
    uint8_t host_data[32];
    uint8_t id_key_digest[48];
    uint8_t author_key_digest[48];
    uint8_t report_id[32];
    uint8_t imd[48];
    uint64_t msg_count0;
    uint64_t msg_count1;
    uint64_t msg_count2;
    uint64_t msg_count3;
    snp_metadata_page_t root_md_entry;
    uint32_t author_key_en : 1;  /* bit 0 */
    uint32_t id_block_en   : 1;  /* bit 1 */
    uint32_t vcek_dis      : 1;  /* bit 2 */
    uint64_t reserved      : 61; /* bits 63:3 */
    uint64_t policy;
    uint8_t state;
    uint8_t reserved1[7];
    uint64_t oek_iv_count;
    snp_mcmd_launch_finish_id_block_t id_block;
    uint8_t gosvw[16];
    uint32_t desired_tsc_freq;
    uint32_t reserved2;
    uint64_t psp_tsc_offset;
    uint64_t launch_tcb;
    uint8_t reserved3[0x300-0x2C8];
} snp_msg_gctx_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_msg_gctx_t) == 0x300, this_file);

typedef struct snp_msg_export_rsp
{
    uint32_t status;
    uint32_t gctx_size;
    uint32_t gctx_version;
    uint8_t reserved[0x20-0x0C];
    snp_msg_gctx_t gctx;
} snp_msg_export_rsp_t;

/* 7.5 VM Import */
typedef struct snp_msg_import_req
{
    uint64_t gctx_paddr;
    uint32_t in_gctx_size;
    uint32_t in_gctx_version;
    uint8_t reserved[0x20-0x10];
    snp_msg_gctx_t incoming_gctx;
} snp_msg_import_req_t;

typedef struct snp_msg_import_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_import_rsp_t;

/* 7.6 VM Absorb */
typedef struct snp_msg_absorb_req
{
    uint64_t gctx_paddr;
    uint32_t in_gctx_size;
    uint32_t in_gctx_version;
    uint8_t reserved[0x20-0x10];
    snp_msg_gctx_t incoming_gctx;
} snp_msg_absorb_req_t;

typedef struct snp_msg_absorb_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_absorb_rsp_t;

/* 7.7 VM Absorb - No MA */
typedef struct snp_msg_absorb_noma_req
{
    uint64_t reserved;
    uint32_t in_gctx_size;
    uint32_t in_gctx_version;
    uint8_t reserved2[0x20-0x10];
    snp_msg_gctx_t incoming_gctx;
} snp_msg_absorb_noma_req_t;

typedef struct snp_msg_absorb_noma_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_absorb_noma_rsp_t;

/* 7.8 VMRK Message */
typedef struct snp_msg_vmrk_req
{
    uint64_t gctx_paddr;
    uint8_t reserved[0x20-0x08];
    uint8_t vmrk[32];
} snp_msg_vmrk_req_t;

typedef struct snp_msg_vmrk_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_vmrk_rsp_t;

/* 7.9 TSC Info Message */
typedef struct snp_msg_tsc_info_req
{
    uint8_t reserved[0x80-0x00];
} snp_msg_tsc_info_req_t;

typedef struct snp_msg_tsc_info_rsp
{
    uint32_t status;
    uint32_t reserved;
    uint64_t guest_tsc_scale;
    uint64_t guest_tsc_offset;
    uint32_t tsc_factor;
    uint8_t reserved2[0x80-0x1C];
} snp_msg_tsc_info_rsp_t;

typedef struct vlek_wrapped {
    uint8_t             iv[12];              /* IV to use in GCM to unwrap the VLEK */
    uint8_t             rsvd[4];
    uint8_t             vlek_wrapped[0x180]; /* VLEK seed wrapped with a chip-unique key using AES-256-GCM. */
    snp_tcb_version_t   tcb_version;         /* The TCB version associated with this VLEK seed */
    uint8_t             reserved[8];         /* Reserved. Must be zero. */
    uint8_t             vlek_auth_tag[16];   /* AES-256-GCM authentication tag of vlek_wrapped */
} vlek_wrapped_t;

/**
 * The TSC_FACTOR is a consequence of spread-spectrum clocking (SSC)
 * SSC adjustments by hardware adjust that amount DOWN (only) by
 * 0.4%, to 99.6% of max. The actual clock, over time, shifts between
 * the 100% and 99.6%, resulting in an average of 99.8%. Or an
 * average decrease of 0.2%.
 * TSC_FACTOR is this, scaled up by 1000 and converted to uint32_t.
 */
#define TSC_FACTOR_GENOA    ((uint32_t)((100000 - 99600) / 2))

/* 9.21 Data Structores and Encodings */
typedef enum snp_guest_message
{
    SNP_MSG_INVALID         = 0x0,
    SNP_MSG_CPUID_REQ       = 0x1,
    SNP_MSG_CPUID_RSP       = 0x2,
    SNP_MSG_KEY_REQ         = 0x3,
    SNP_MSG_KEY_RSP         = 0x4,
    SNP_MSG_REPORT_REQ      = 0x5,
    SNP_MSG_REPORT_RSP      = 0x6,
    SNP_MSG_EXPORT_REQ      = 0x7,
    SNP_MSG_EXPORT_RSP      = 0x8,
    SNP_MSG_IMPORT_REQ      = 0x9,
    SNP_MSG_IMPORT_RSP      = 0xA,
    SNP_MSG_ABSORB_REQ      = 0xB,
    SNP_MSG_ABSORB_RSP      = 0xC,
    SNP_MSG_VMRK_REQ        = 0xD,
    SNP_MSG_VMRK_RSP        = 0xE,
    SNP_MSG_ABSORB_NOMA_REQ = 0xF,
    SNP_MSG_ABSORB_NOMA_RSP = 0x10,
    SNP_MSG_TSC_INFO_REQ    = 0x11,
    SNP_MSG_TSC_INFO_RSP    = 0x12,

    SNP_MSG_LIMIT,
} snp_guest_message_t;

/* Size must match bootloader gData.SnpGlobals (32 bytes) */
typedef struct sev_snp_globals_field
{
    uint32_t rmp_initialized            :  1;
    uint32_t reserved                   : 31;
    snp_tcb_version_t tcb;  /* TCB of code that initialized the RMP */
    uint32_t reserved2[4];
    uint32_t signal_sdu_snp_initialized :  1;
    uint32_t diag_mode_enabled          :  1;
    uint32_t reserved3                  : 14;
    uint32_t signal_snp_sdu_unlocked    :  1;
    uint32_t reserved4                  : 15;
} __attribute__((packed)) sev_snp_globals_field_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_snp_globals_field_t) == 32, this_file);

typedef union sev_snp_globals
{
    sev_snp_globals_field_t f;
    uint8_t val[32];
} sev_snp_globals_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_snp_globals_t) == 32, this_file);

sev_status_t get_rmp_bounds(void);
sev_status_t get_rmp_paddr(uint64_t sPA, uint64_t *rmp_paddr);
sev_status_t rmp_entry_read(uint64_t rmp_paddr, rmp_entry_t *rmp_data);
sev_status_t rmp_entry_write(uint64_t rmp_paddr, rmp_entry_t *rmp_data);
sev_status_t mdata_entry_read(uint64_t mdata_paddr, snp_metadata_page_t *mdata_data);
sev_status_t mdata_entry_write(uint64_t mdata_paddr, snp_metadata_page_t *mdata_data);
snp_page_state_t rmp_entry_get_state(rmp_entry_t *entry);
sev_status_t rmp_get_addr_entry_state(uint64_t x86_paddr, uint64_t *rmp_paddr,
                                      rmp_entry_t *rmp_entry, snp_page_state_t *state);
snp_page_state_t rmp_get_state_rmp_base(void);
sev_status_t setup_and_validate_initial_rmp_table(void);
sev_status_t check_rmp_for_asid(uint32_t asid, uint64_t *count);
bool is_rmp_table_initialized(void);
void rmp_is_uninitialized(void);

/**
 * Reclaim a buffer from Firmware state to Reclaim state
 */
sev_status_t snp_reclaim_buffer(uint64_t address);

sev_status_t set_rmp_range_to_firmware_iommu_state(uint64_t rmp_entry_start,
                                                   uint64_t rmp_entry_end);
sev_status_t set_rmp_range_to_hypervisor_state(uint64_t rmp_entry_start, uint64_t rmp_entry_end);
sev_status_t set_rmp_range_to_reclaim_state(uint64_t rmp_entry_start, uint64_t rmp_entry_end);
sev_status_t require_rmp_reinit(sev_t *sev, sev_snp_globals_t *snp_globals, bool *required_init);

/**
 * Increment sub page count for 2mb aligned portion of the range of 4K buffers.
 * This assumes the start and end are multiple 4k aligned buffers as well as assumes the range
 * in between are set to FIRMWARE/FIRMWARE-IOMMU state.
 *
 * x86_buffer_start - physical address of 4K aligned page of the starting point
 * x86_buffer_end   - physical address of the "end point". Should be (4K-1).
 * overlap_range - boolean to indicate whether this is for RMP table within the RMP entries or for IOMMU type of address
 *
 */
sev_status_t set_rmp_sub_page_count(uint64_t x86_buffer_start,
                                    uint64_t x86_buffer_end, bool overlap_range);

/* Check that pages within range are FIRMWARE or DEFAULT pages
   Used for SEV commands that firmware writes to when SNP is enabled */
sev_status_t check_page_range_firmware_writable(uint64_t start_paddr, uint32_t length);

/* Validate the memory map to make sure RMP isn't overlapping MMIO regions */
sev_status_t validate_memory_map(SYS_MEM_MAP *mem_map, uint64_t base_addr, uint64_t limit_addr);

/* Initialize the entire RMP */
bool configure_rmp(uint64_t reserved_list_paddr);

/* Set a list of address ranges to HV_FIXED */
sev_status_t page_set_hv_fixed(uint64_t list_paddr);

#endif /* SEV_RMP_H */
