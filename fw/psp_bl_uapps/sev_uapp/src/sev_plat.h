// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_PLAT_H
#define SEV_PLAT_H

#include <stddef.h>
#include <stdint.h>

#include "bootrom_mailbox.h"
#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "df_regs.h"
#include "sev_cert.h"
#include "sev_errors.h"
#include "sev_guest.h"
#include "sev_hal_interface.h"
#include "sev_hal_iommu.h"
#include "sev_ring_buffer.h"
#include "sev_rmp.h"            // for snp_tcb_version_t
#include "tmr_cache.h"

/* Use forward declarations here to avoid circular dependencies on sev_mcmd.h */
typedef enum sev_mcmd_id sev_mcmd_id_t;

#define MP0_DIE_CNT_2P                      (2)     /* PSP die count for 2P */
#define SEV_GUEST_COUNT_MAX                 (1024)
#define SEV_GLOBAL_MASTER_DIE_ID            (0)
#define SEV_SLAVE_SOCKET_MASTER_DIE         (1)     /* 1 IOD/die/PSP on each socket */
#define SEV_MAX_NUM_SOCKETS                 (2)

/* Platform Status platform_flags */
#define SEV_PLATFORM_OWNER_BIT      (0)    /* bit 0: 0 = self owned, 1 = externally owned */
#define SEV_PLATFORM_OWNER_FLAG     (1ul << (SEV_PLATFORM_OWNER_BIT))

/* Platform Status config_flags */
#define SEV_CONFIG_ES_BIT           (0)    /* bit 0: 0 = SEV-ES is disabled for all guests, 1 = SEV-ES is initialized for the platform */
#define SEV_CONFIG_ES_FLAG          (1ul << (SEV_CONFIG_ES_BIT))

/**
 * See Key_Table_Proposal.docx
 * KeyId  0         Unencrypted
 * KeyId  1-1006    Guest keys associated with ASID values 1-1026
 * KeyId  1008      IOMMU key (used by IOMMU for internal state)
 * KeyId  1016-1022 (Reserved for ranges)
 * KeyId  1023      TSME/SME (hypervisor) key
 */
#define MAX_SEV_ASIDS               (1006)
#define SEV_ASID_ARRAY_SIZE         (1024)

/* Maximum APIC IDs */
#define MAX_APIC_IDS                (512)

/* VCEK Defines */
#define MICROCODE_SEED_LENGTH       (48)

/* Mean Reference clock Frequency of PSP in kHz, less spread spectrum variance */
#define REF_CLK_GENOA               (99800U)      /* 100MHz - 0.2% */

/**
 * PLAT-76815: MSRs that need to be checked on SNP_INIT to avoid security issues:
 * MSR C001_1006h (Core::X86::Msr::DEBUG_STATUS)
 *    All threads should have bit 2 and 7 equal to 0.
 *    This ensures the x86 threads are not in guest or SMM mode at the time of
 *    SNP_INIT which is needed to ensure RMP security.
 * MSR 250h/258h/259h and 268-26Fh (Fixed MTRRs)
 *    All cores should be consistent. These MSRs are shared across SMT threads
 * MSR C001_0016h/C001_0018h (Core::X86::Msr::IORR_BASE)
 *    All cores should be consistent. These MSRs are shared across SMT threads.
 * MSR C001_0017h/C001_0019h (Core::X86::Msr::IORR_MASK)
 *    All cores should be consistent. These MSRs are shared across SMT threads.
 * MSR C001_001Ah/C001_001Dh (Core::X86::Msr::TOP_MEM)/Core::X86::Msr::TOM2)
 *    All cores should be consistent. These MSRs are shared across SMT threads
 */
#define MSR_DEBUG_STATUS        (0xC0011006)
#define MSR_DEBUG_STATUS_MASK   (0x00000084ULL)     /* Bit 2 and 7 */
#define MSR_MTRRFIX_64K         (0x00000250)
#define MSR_MTRRFIX_16K_0       (0x00000258)
#define MSR_MTRRFIX_16K_1       (0x00000259)
#define MSR_MTRRFIX_4K_0        (0x00000268)
#define MSR_MTRRFIX_4K_1        (0x00000269)
#define MSR_MTRRFIX_4K_2        (0x0000026A)
#define MSR_MTRRFIX_4K_3        (0x0000026B)
#define MSR_MTRRFIX_4K_4        (0x0000026C)
#define MSR_MTRRFIX_4K_5        (0x0000026D)
#define MSR_MTRRFIX_4K_6        (0x0000026E)
#define MSR_MTRRFIX_4K_7        (0x0000026F)
#define MSR_SYS_CFG             (0xC0010010)
#define MSR_HWCR                (0xC0010015)
#define MSR_IORR_BASE_16        (0xC0010016)
#define MSR_IORR_BASE_18        (0xC0010018)
#define MSR_IORR_MASK_17        (0xC0010017)
#define MSR_IORR_MASK_19        (0xC0010019)
#define MSR_TOP_MEM             (0xC001001A)
#define MSR_TOM2                (0xC001001D)
#define MSR_TSEG_BASE           (0xC0010112)
#define MSR_TSEG_MASK           (0xC0010113)
#define MSR_VM_HSAVE_PA         (0xC0010117)

/* Make an array of all MSR values we preload and check */
static uint32_t SNP_INIT_MSR_ARRAY[] = {MSR_SYS_CFG, MSR_DEBUG_STATUS, MSR_MTRRFIX_64K, MSR_MTRRFIX_16K_0,
                                 MSR_MTRRFIX_16K_1, MSR_MTRRFIX_4K_0, MSR_MTRRFIX_4K_1, MSR_MTRRFIX_4K_2,
                                 MSR_MTRRFIX_4K_3, MSR_MTRRFIX_4K_4, MSR_MTRRFIX_4K_5, MSR_MTRRFIX_4K_6,
                                 MSR_MTRRFIX_4K_7, MSR_IORR_BASE_16, MSR_IORR_BASE_18, MSR_IORR_MASK_17,
                                 MSR_IORR_MASK_19, MSR_TOP_MEM, MSR_TOM2, MSR_TSEG_BASE, MSR_TSEG_MASK,
                                 MSR_HWCR};
#define SNP_INIT_MSR_ARRAY_INDICES (sizeof(SNP_INIT_MSR_ARRAY)/sizeof(SNP_INIT_MSR_ARRAY[0]))


/* MSRC001_0010 [System Configuration] (Core::X86::Msr::SYS_CFG) */
#define MSR_SYS_CFG_MFDE_BIT     (18)
#define MSR_SYS_CFG_MFDE_FLAG    (1ul << (MSR_SYS_CFG_MFDE_BIT))
#define MSR_SYS_CFG_MFDM_EN_BIT  (19)
#define MSR_SYS_CFG_MFDM_EN_FLAG (1ul << (MSR_SYS_CFG_MFDM_EN_BIT))
#define MSR_SYS_CFG_TOM2_EN_BIT  (21)
#define MSR_SYS_CFG_TOM2_EN_FLAG (1ul << (MSR_SYS_CFG_TOM2_EN_BIT))
#define MSR_SYS_CFG_SNP_EN_BIT   (24)
#define MSR_SYS_CFG_SNP_EN_FLAG  (1ul << (MSR_SYS_CFG_SNP_EN_BIT))

/* MSRC001_0015 [Hardware Configuration] (Core::X86::Msr::HWCR) */
#define MSR_HWCR_SMM_LOCK_BIT    (0)
#define MSR_HWCR_SMM_LOCK_FLAG   (1ul << (MSR_HWCR_SMM_LOCK_BIT))

typedef enum sev_state
{
    SEV_STATE_UNINIT  = 0,
    SEV_STATE_INIT    = 1,
    SEV_STATE_WORKING = 2,

    SEV_STATE_LIMIT,
} sev_state_t;

typedef enum snp_state
{
    SNP_STATE_UNINIT    = 0,
    SNP_STATE_INIT      = 1,

    SNP_STATE_LIMIT,
} snp_state_t;

/**
 * The only data saved to persistent storage are the PEK key pair and its
 * certificate, and OCA key pair and its certificate.
 */
typedef struct sev_persistent
{
    sev_cert_keypair_t      pdh;
    sev_cert_t              pdh_cert;

    sev_cert_keypair_t      pek;
    sev_cert_t              pek_cert;

    /* "OCA" is the Owner Certificate Authority */
    uint8_t                 is_ext_owned;  /* 0: self owned, non-zero: externally owned */
    union
    {
        sev_cert_keypair_t  self_owned;
        sev_cert_pubkey_t   ext_owned;
    } oca;
    sev_cert_t              oca_cert;
} sev_persistent_t;

typedef struct sev_identity
{
    /*
     *  XXX: the CEK is signed by the ASK, which is an RSA key.
     *  Therefore, the sev_cert_t doesn't make sense here until either we use
     *  a different ASK or we add the ability to select algorithms to the
     *  certificate.
     *
     *  The CEK and its certificate are re-derived each boot cycle.
     */
    sev_cert_keypair_t  cek;
    sev_persistent_t    persistent;
} sev_identity_t;

typedef struct snp_identity
{
    /* The VCEK and its certificate are re-derived each boot cycle */
    uint8_t             vcek_hash[DIGEST_SHA384_SIZE_BYTES];
    sev_cert_keypair_t  vcek;
} snp_identity_t;

typedef struct sev_ccd_core_info
{
    /* Area for ccd core information (MCM_INFO that is per-socket) */
    uint32_t    ccd_present_bit_mask;                   /* Bit mask for CCD Present, 1:CCD Present, 0:CCD not present */
    uint16_t    core_present_in_ccd_bit_mask[MAX_CCDS]; /* Bit mask for cores present for each CCDs, 1:Core Present, 0: Core not present */
    uint64_t    ppin;                                   /* Processor Serial Number */
    uint32_t    umc_present_bit_mask;                   /* Bit mask of present UMCs (needed for harvesting) */
    uint8_t     ecc_seed_hash[32];                      /* Hash of the ECC SEED value from LSB1 */
} sev_per_socket_info_t;

/**
 * APIC ID format derived from INITPKG7
 */
typedef struct apicid_fmt_specifier {
   uint8_t thread_bit_shift;
   uint8_t core_bit_shift;
   uint8_t zero_bit_shift;
   uint8_t ccx_bit_shift;
   uint8_t ccd_bit_shift;
   uint8_t sock_bit_shift;
} apicid_fmt_specifier_t;

/**
 * This struct is for data that needs to exist before sev_init, persist outside
 * of Init-Shutdown and needs to be available/restored from DRAM after SDU
 *
 * Note, you can't reorganize these variables; you can only add to the bottom.
 * If there is valid data being stored into DRAM and then you load it back into
 * this struct but the variables are moved around, then you get garbage data.
 */
typedef struct sev_persistent_globals
{
    /* Populated in sev_init */
    uint64_t  smm_base;             /* Set in sev_init() */
    uint64_t  smm_length;
    SOC_VER_E soc_version;          /* Set in sev_init() */
    bool      smke_enabled;

    /* Populated in sev_hal_get_mcm_info */
    uint32_t  bl_fw_version;
    sev_per_socket_info_t socket_info[MAX_SOCKET_NUM];  /* Per-socket info */
    uint32_t  ccx_present_bit_mask;     /* Combined/all-socket bit mask for PHYSICAL CCX on all sockets. 0-15 bit is CCX0,CCX1 on CCD0, CCX0,1 on CCD1, etc. */
    uint32_t  umc_present_bit_mask;     /* Combined/all-socket bit mask for PHYSICAL UMCs on all sockets. 0-7 are socket 0, 8-15 are socket 1, etc. */
    bool      smt_enabled;

    sev_scfctp_init_pkg_regs_t *initpkg_addr;

    /* Populated in snp_mcmd_config */
    snp_tcb_version_t config_tcb;     /* Set by SNP_CONFIG... or 0 */

    /* Populated first time needed, per TMR entry */
    tmr_cache_t tmr_cache;

    /* RS has 8 cores/CCD and RSDN has 16 cores/CCD */
    uint32_t max_cores_per_ccd;

    /* APIC ID format, as specified by INITPKG7 */
    apicid_fmt_specifier_t afs;

    /* INITPKG7 cached value */
    uint32_t initpkg7;

    bool   skip_rsmus[RSMU_PRESENT_COUNT];
} sev_persistent_globals_t;

/**
 * The data in this structure is only valid between mcmd_init and mcmd_shutdown.
 * Don't try to store anything in here that needs to persist between shutdown commands
 */
typedef struct sev
{
    /* Common */
    bool                    common_context_initialized;

    /* Initialized by create_apicid_table */
    bool                    activate_ex_enable;
    uint8_t                 apic_ids[MAX_APIC_IDS];

    /* SEV state isn't preserved across DLFW_EX */
    struct                  /* SEV Only */
    {
        sev_state_t         state;
        sev_identity_t      identity;       /* Cert chain */
        size_t              guest_count;
        sev_guest_t         *guests;        /* Pointer to guests_dram[SEV_GUEST_COUNT_MAX] */
        sev_es_platform_t   es;
        bool                context_initialized;
        uint64_t            init_ex_nv_paddr;
        uint32_t            config_flags;
    } sev;

    struct                  /* SNP only */
    {
        bool                context_initialized;
        uint8_t             vmsa_tweak_bitmap[VMSA_TWEAK_BITMAP_SIZE]; /* Set in LaunchUpdate VMSA, reported in LaunchUpdate Secret */
    } snp;
} sev_t;

/**
 * P1 misc storage in dram
 */
typedef struct p1_misc
{
    /* Populated in sev_scmd_get_mcm_info */
    sev_per_socket_info_t socket_info;
    /* Populated in sev_scmd_get_apicid */
    bool        activate_ex_enable;
    uint8_t     apic_ids[MAX_APIC_IDS];
    /* Populated in sev_scmd_get_cuk */
    uint8_t     p1cuk[32];              /* Cleared immediately after using */
    /* Populated in sev_scmd_check_msrs */
    uint64_t    msrs[SNP_INIT_MSR_ARRAY_INDICES];
} p1_misc_t;

/**
 * Note that this data survives across DLFW_EX, but not DLFW!
 * That is, a DLFW will rebuild this area from scratch on "FIRST_RUN".
 * DLFW_EX sets the CONTINUED flag that is preserved by BL across the
 * loading of the new image. That flag, plus FIRST_RUN, indicates we
 * are running the new image as part of the old image's DLFW_EX command.
 * The new image will attempt to 'upgrade' the preserved data structures
 * and keep everything running.
 * Upgrading means adding things.
 * In general, fields in this structure should be initialized ONLY on
 * first _INIT command, NOT in sev_uapp_init() or callees like sev_init().
 * The exception is on a FIRST_RUN when the magic value is not set. Then
 * initialization is required, e.g., rb_config.rb_enable.
 */
typedef struct perm_globals {
    uint32_t            magic;                  /* Magic value for recognizing valid area */
    uint32_t            version;                /* Version of this data structure */
    uint32_t            length;                 /* Length of data last saved here */
    uint32_t            reserved;               /* Pad out this header area to 16 bytes */

    /* Each CCX gets a bit. max CCXs in Genoa: 32 (2P). */
    uint32_t            asid_dirty[SEV_ASID_ARRAY_SIZE];      /* ASID no longer in use, but not clean. */
    uint32_t            asid_clean[SEV_ASID_ARRAY_SIZE];      /* ASID clean. */
    uint32_t            asid_allocated[SEV_ASID_ARRAY_SIZE];  /* ASID allocated to guest waiting to go to Running. */
    uint32_t            asid_in_use[SEV_ASID_ARRAY_SIZE];     /* ASID in use in running guest. */

    /* Count of SNP guests is not re-creatable after DLFW_EX */
    size_t              snp_guest_count;

    /* Ring Buffer config info must survive DLFW_EX */
    sev_rb_config_t     rb_config;

    uint64_t            rmp_base;               /* Set in sev_mcmd_init()/snp_mcmd_init() */
    uint64_t            rmp_end;
    snp_state_t         snp_state;
    snp_identity_t      snp_identity;           /* vcek hash and key. Either associated with tcb_version or requested_tcb */

    bool                snp_iommu_enabled;      /* Set in snp_mcmd_init() */
    uint64_t            iommu_entry_list_start[MAX_IOMMU_TABLE_STATES]; /* Store all the FIRMWARE_IOMMU page RMP entries */
    uint64_t            iommu_entry_list_end[MAX_IOMMU_TABLE_STATES];   /* to manually reclaim during SNP_SHUTDOWN_EX */
    uint32_t            iommu_entry_ctr;

    /* Flag from DLFW_EX about whether to commit on a successful continue or not */
    bool                dlfw_ex_commit;

    /* Committed FW version and corresponding TCB */
    snp_tcb_version_t committed_tcb;  /* CommittedSvn. Committed in DLFW or SNP_COMMIT */
    uint8_t committed_build_id;
    uint8_t committed_api_minor;
    uint8_t committed_api_major;

    /* Bits from SNP_CONFIG */
    uint32_t         mask_chip_id:1;
    uint32_t         mask_chip_key:1;
    uint32_t         config_reserved:30;

    /* Substitute attestation key hashsticks & derived key */
    uint8_t         vlek[8][PSP_HASHSTICK_LENGTH];
    ecc_keypair_t   vlek_key;
} perm_globals_t;

#define SEV_PERM_MAGIC              0x534E5044U /* 'SNPD' Something recognizable */
#define SEV_PERM_VERSION            1           /* If we get to 0xFFFF_FFFF... ;-) */
#define SEV_PERM_SIZE               sizeof(perm_globals_t)
#define MAX_PERM_SIZE               32768       /* Allow some room to grow */

/* Minimum PSP Bootloader version for feature support */
#define MIN_BL_VERSION_MASK       (0xFFFF00FFul)    /* Ignore the second to last byte */
#define MIN_BL_VERSION_BERGAMO    (0x00290068)    /* Genoa PI 1002RC3 */
#define MIN_BL_VERSION_ASPT       (0x00290070)    /* Genoa PI 1002RC4 */
#define MIN_BL_VERSION_SVC_HASHSTICKS (0x00290075) /* Genoa PI 1003RC2 */
#define MIN_BL_VERSION_SVC_SKIP_RSMU  (0x00290075) /* Genoa PI 1003RC2 */

/**
 * Overlay structure for SEV Reserved DRAM
 *
 * For smm_base and smm_length, this data comes from Bootloader using HAL
 * and gets put into DRAM for access by slaves. Then everyone immediately
 * copies to global variables for use (x86_copy)
 */
typedef struct sev_rsvd_dram
{
    perm_globals_t      perm;                   /* Variables that persist across DLFW_EX. MUST be first in DRAM! */
    uint8_t             buffer[MAX_PERM_SIZE-sizeof(perm_globals_t)]; /* Room to grow... needed for rollback case */
    sev_persistent_globals_t persistent_bkup;   /* Gets stored every command. Loaded in RELOADED after SDU/DLFW_EX */
    sev_t               sev_bkup;               /* Gets stored every command. Loaded in RELOADED after SDU/DLFW_EX */
    p1_misc_t           p1_info __attribute__((aligned (32)));
    sev_guest_t         guests_dram[SEV_GUEST_COUNT_MAX] __attribute__((aligned (32)));
    SYS_MEM_MAP         mem_map;
} sev_rsvd_dram_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(sev_rsvd_dram_t) <= DRAM_SEV_RESERVED_MEMORY_SIZE, this_file);

/**
 * GetID structure
 */
typedef struct get_id       /* One socket's ID length */
{
    uint8_t x[32];
    uint8_t y[32];
} get_id_t;

/**
 * Initialize the SEV platform context.
 *
 * XXX parameters to be determined
 */
sev_status_t sev_init(sev_t *sev);

/**
 * Clear the SEV platform context.
 * NOTE: Expects the platform state to be set to UNINIT before being called
 *
 * XXX parameters to be determined
 */
sev_status_t sev_clear(sev_t *sev);


/* PDH management functions */
sev_status_t sev_pdh_generate(sev_identity_t *identity);
sev_status_t sev_pdh_delete(sev_identity_t *identity);

/* PEK management functions */
sev_status_t sev_pek_generate(sev_identity_t *identity);
sev_status_t sev_pek_delete(sev_identity_t *identity);

/* CEK management functions */
sev_status_t sev_cek_derive(sev_identity_t *identity);
sev_status_t sev_cek_delete(sev_identity_t *identity);

/* OCA management functions */
sev_status_t sev_oca_generate(sev_identity_t *identity);
sev_status_t sev_oca_delete(sev_identity_t *identity);

/* GetID management functions */
sev_status_t sev_get_id(uint32_t id_len, uint8_t *out_buf, uint32_t *bytes_wrote);

/* VCEK management functions */
sev_status_t vcek_hash_derive(uint8_t *vcek, uint32_t length,
                              snp_tcb_version_t *old_tcb_version);
sev_status_t vcek_derive(snp_identity_t *identity);

typedef enum {
    KEYTYPE_VCEK = 1,
    KEYTYPE_VLEK = 2,
} keytype;

sev_status_t key_from_hash(ecc_keypair_t *key, const uint8_t *hash, keytype type);

/**
 * Get the up-to-date TCB
 */
sev_status_t get_running_tcb(snp_tcb_version_t *tcb, SEV_FW_IMAGE_HEADER *hdr);

/**
 * Get the TCB at the time of the last COMMIT
 */
void get_committed_tcb(snp_tcb_version_t *tcb);

/**
 * Get either the TCB set by an SNP_CONFIG command or the committed TCB
 */
void get_reported_tcb(snp_tcb_version_t *tcb);

/**
 * Transition the platform to the provided sev state.
 */
sev_status_t sev_state_transition(sev_t *sev, sev_mcmd_id_t cmd);

/**
 * Transition the platform to the provided snp state.
 */
sev_status_t snp_state_transition(sev_t *sev, sev_mcmd_id_t cmd);

uint32_t GetMaxSEVASID(void);

static inline sev_status_t get_asid_bit_index(uint32_t asid, uint32_t *index, uint32_t *bit)
{
    sev_status_t status = SEV_STATUS_SUCCESS;

    if (index == NULL || bit == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *index = asid / 32;
    *bit = 1ul << (asid - (*index * 32));

end:
    return status;
}

/**
 * Test if the given ASID has already been activated.
 */
static inline bool asid_is_active(sev_t *sev, uint32_t asid)
{
    extern sev_rsvd_dram_t *gpDram;

    if (!sev || asid == 0 || asid > GetMaxSEVASID())
        return false;

    return ((gpDram->perm.asid_in_use[asid-1])     ||
            (gpDram->perm.asid_dirty[asid-1])      ||
            (gpDram->perm.asid_allocated[asid-1]));
}

#define HASH_STICK_INTERMEDIATE_NULL_BYTES_LEN      8

int tcb_compare_versions(const snp_tcb_version_t *tcb_a, const snp_tcb_version_t *tcb_b);

#endif /* SEV_PLAT_H */
