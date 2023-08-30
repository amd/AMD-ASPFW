// Copyright(C) 2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef CPUID_LOOKUP_H
#define CPUID_LOOKUP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "common_utilities.h" // COMMON_COMPILE_TIME_ASSERT
#include "sev_status.h"

/* ------ SNP Specification Definitions ------- */
#define CPUID_STD_RANGE_MIN 0x00000000
#define CPUID_STD_RANGE_MAX 0x0000FFFF
#define CPUID_EXT_RANGE_MIN 0x80000000
#define CPUID_EXT_RANGE_MAX 0x8000FFFF

/* 8.1 CPUID Reporting */
#define SNP_CPUID_COUNT_MAX 64
typedef struct snp_cpuid_function
{
    uint32_t eax_in;        /* Input */
    uint32_t ecx_in;
    uint64_t xcr0_in;
    uint64_t xss_in;
    uint32_t eax;           /* Output */
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint64_t reserved;
} snp_cpuid_function_t;

typedef struct snp_msg_cpuid_req
{
    uint32_t count;
    uint32_t reserved;
    uint64_t reserved2;
    snp_cpuid_function_t cpuid_function[SNP_CPUID_COUNT_MAX];
} snp_msg_cpuid_req_t;
COMMON_COMPILE_TIME_ASSERT(sizeof(snp_msg_cpuid_req_t) < 4096, this_file);  /* 4k>=snp_guest_message_header_t+snp_msg_cpuid_req_t */

typedef struct snp_msg_cpuid_rsp
{
    uint32_t status;
    uint32_t count;
    uint64_t reserved;
    snp_cpuid_function_t cpuid_function[SNP_CPUID_COUNT_MAX];
} snp_msg_cpuid_rsp_t;
/* ------ End of SNP Spec Definitions  ------- */


/* CPUID lookup internal definitions */
enum CPUID_REG_INDEX
{
    EAX_REG = 0,
    EBX_REG = 1,
    ECX_REG = 2,
    EDX_REG = 3
};

/* PPR 2.1.5.3 CPUID Policy Enforcement */
#define CPUID_RULE_EXACT            (0)     /* Define if the eax_out is exactly as stated in eax_out, etc. */
#define CPUID_RULE_MASK             (1)     /* Define if only the bit mask can contain values */
#define CPUID_RULE_CUSTOM           (2)     /* Define if this register out for this cpuid function has custom rules.*/
#define CPUID_RULE_LESSTHAN         (3)     /* Define if it is less than value */
#define CPUID_RULE_UNCHECKED        (4)     /* Define if there is no checked value */
#define CPUID_RULE_DOES_NOT_EXIST   (0xFF)  /* Define if the CPUID does not exist */

typedef struct
{
    uint8_t eax_rule;
    uint8_t ebx_rule;
    uint8_t ecx_rule;
    uint8_t edx_rule;
} cpuid_ruleset;

typedef struct
{
    uint32_t eax_in;
    uint32_t ecx_in;
    sev_status_t (*custom_func)(uint32_t eax_in, uint32_t ecx_in,     \
                                uint64_t xcr0_in, uint64_t xss,       \
                                uint32_t *eax_out, uint32_t *ebx_out, \
                                uint32_t *ecx_out, uint32_t *edx_out);
    uint32_t eax_out;
    uint32_t ebx_out;
    uint32_t ecx_out;
    uint32_t edx_out;
    uint32_t eax_reserved;
    uint32_t ebx_reserved;
    uint32_t ecx_reserved;
    uint32_t edx_reserved;
    cpuid_ruleset rules;
} cpuid_lookup;

/* XCR0 Bit definitions */
#define XCR0_X87   (1 << 0ULL)
#define XCR0_SSE   (1 << 1ULL)
#define XCR0_AVX   (1 << 2ULL)
#define XCR0_KREGS (1 << 5ULL)
#define XCR0_ZMMHI (1 << 6ULL)
#define XCR0_HIZMM (1 << 7ULL)
#define XCR0_MPK   (1 << 9ULL)

#define CET_U      (1 << 11ULL)
#define CET_S      (1 << 12ULL)

#define FNXXXXXXXX_CUSTOM (0)   /* Placeholder cpuid_lookup for Custom functions which don't use the table */
#define FNXXXXXXXX_CPUID_DOES_NOT_EXIST     (0x000000000)
#define FNXXXXXXXX_RESERVED_DOES_NOT_EXIST  (~(0))  /* If CPUID does not exist, all reserved bits are set */

/* FN00000000 Defines */
#define FN00000000_EAX_DEFAULT  (0x00000010)
#define FN00000000_EAX_RESERVED (0x00000000)
#define FN00000000_EBX_DEFAULT  (0x68747541)
#define FN00000000_EBX_RESERVED (0x00000000)
#define FN00000000_ECX_DEFAULT  (0x444D4163)
#define FN00000000_ECX_RESERVED (0x00000000)
#define FN00000000_EDX_DEFAULT  (0x69746E65)
#define FN00000000_EDX_RESERVED (0x00000000)


/* FN00000001_EAX defines */
#define FN00000001_EAX_STEPPING_SHIFT   0
#define FN00000001_EAX_STEPPING_MASK    (0xF << FN00000001_EAX_STEPPING_SHIFT)
#define FN00000001_EAX_BMODEL_SHIFT     4
#define FN00000001_EAX_BMODEL_MASK      (0xF << FN00000001_EAX_BMODEL_SHIFT)
#define FN00000001_EAX_BFAMILY_SHIFT    8
#define FN00000001_EAX_BFAMILY_MASK     (0xF << FN00000001_EAX_BFAMILY_SHIFT)
#define FN00000001_EAX_EMODEL_SHIFT     16
#define FN00000001_EAX_EMODEL_MASK      (0xF << FN00000001_EAX_EMODEL_SHIFT)
#define FN00000001_EAX_EFAMILY_SHIFT    20
#define FN00000001_EAX_EFAMILY_MASK     (0xFF << FN00000001_EAX_EFAMILY_SHIFT)
#define FN00000001_EAX_RESERVED         (0xF000F000)

#define FMS_FAMILY(eax)   (((eax & FN00000001_EAX_EFAMILY_MASK) >> FN00000001_EAX_EFAMILY_SHIFT) + \
                           ((eax & FN00000001_EAX_BFAMILY_MASK) >> FN00000001_EAX_BFAMILY_SHIFT))
#define FMS_MODEL(eax)    (((eax & FN00000001_EAX_EMODEL_MASK)  >> FN00000001_EAX_EMODEL_SHIFT)  + \
                           ((eax & FN00000001_EAX_BMODEL_MASK)  >> FN00000001_EAX_BMODEL_SHIFT))
#define FMS_STEPPING(eax) ((eax & FN00000001_EAX_STEPPING_MASK) >> FN00000001_EAX_STEPPING_SHIFT)

/* FN00000001_EBX defines */
#define FN00000001_EBX_CFLUSH_MASK  (0xFF00) /* Dynamic */
#define FN00000001_EBX_CFLUSH_SHIFT (8)
#define FN00000001_EBX_CFLUSH_EXACT (8)
#define FN00000001_EBX_RESERVED     (0x000000FF)

/* FN00000001_ECX defines */
#define FN00000001_ECX_RESHV     (1UL << 31)  /* Dynamic */
#define FN00000001_ECX_RDRAND    (1 << 30)
#define FN00000001_ECX_F16C      (1 << 29)
#define FN00000001_ECX_AVX       (1 << 28)
#define FN00000001_ECX_OSXSAVE   (1 << 27)  /* Dynamic */
#define FN00000001_ECX_XSAVE     (1 << 26)
#define FN00000001_ECX_AES       (1 << 25)
#define FN00000001_ECX_POPCNT    (1 << 23)
#define FN00000001_ECX_MOVBE     (1 << 22)
#define FN00000001_ECX_X2APIC    (1 << 21)
#define FN00000001_ECX_SSE42     (1 << 20)
#define FN00000001_ECX_SSE41     (1 << 19)
#define FN00000001_ECX_PCID      (1 << 17)
#define FN00000001_ECX_CMPXCH16B (1 << 13)
#define FN00000001_ECX_FMA       (1 << 12)
#define FN00000001_ECX_SSSSE3    (1 << 9)
#define FN00000001_ECX_MONITOR   (1 << 3)
#define FN00000001_ECX_PCLMULQDQ (1 << 1)
#define FN00000001_ECX_SSE3      (1 << 0)
#define FN00000001_ECX_RESERVED  (0x105CDF4)

/* OSXSAVE and RESHV are unchecked, so not part of the mask */
#define FN00000001_ECX_DEFAULT (FN00000001_ECX_RDRAND    | \
                                FN00000001_ECX_F16C      | \
                                FN00000001_ECX_AVX       | \
                                FN00000001_ECX_XSAVE     | \
                                FN00000001_ECX_AES       | \
                                FN00000001_ECX_POPCNT    | \
                                FN00000001_ECX_MOVBE     | \
                                FN00000001_ECX_X2APIC    | \
                                FN00000001_ECX_SSE42     | \
                                FN00000001_ECX_SSE41     | \
                                FN00000001_ECX_PCID      | \
                                FN00000001_ECX_CMPXCH16B | \
                                FN00000001_ECX_FMA       | \
                                FN00000001_ECX_SSSSE3    | \
                                FN00000001_ECX_MONITOR   | \
                                FN00000001_ECX_PCLMULQDQ | \
                                FN00000001_ECX_SSE3)

/* FN00000001_EDX defines */
#define FN00000001_EDX_HTT        (1 << 28)
#define FN00000001_EDX_SSE2       (1 << 26)
#define FN00000001_EDX_SSE3       (1 << 25)
#define FN00000001_EDX_FXSR       (1 << 24)
#define FN00000001_EDX_MMX        (1 << 23)
#define FN00000001_EDX_CLFSH      (1 << 19)
#define FN00000001_EDX_PSE36      (1 << 17)
#define FN00000001_EDX_PAT        (1 << 16)
#define FN00000001_EDX_CMOV       (1 << 15)
#define FN00000001_EDX_MCA        (1 << 14)
#define FN00000001_EDX_PGE        (1 << 13)
#define FN00000001_EDX_MTRR       (1 << 12)
#define FN00000001_EDX_SYSENTEXIT (1 << 11)
#define FN00000001_EDX_APIC       (1 << 9)  /* Dynamic */
#define FN00000001_EDX_CMPXCHG8B  (1 << 8)
#define FN00000001_EDX_MCE        (1 << 7)
#define FN00000001_EDX_PAE        (1 << 6)
#define FN00000001_EDX_MSR        (1 << 5)
#define FN00000001_EDX_TSC        (1 << 4)
#define FN00000001_EDX_PSE        (1 << 3)
#define FN00000001_EDX_DE         (1 << 2)
#define FN00000001_EDX_VME        (1 << 1)
#define FN00000001_EDX_FPU        (1 << 0)
#define FN00000001_EDX_RESERVED   (0xE8740400)

#define FN00000001_EDX_DEFAULT    (FN00000001_EDX_HTT        | \
                                   FN00000001_EDX_HTT        | \
                                   FN00000001_EDX_SSE2       | \
                                   FN00000001_EDX_SSE3       | \
                                   FN00000001_EDX_FXSR       | \
                                   FN00000001_EDX_MMX        | \
                                   FN00000001_EDX_CLFSH      | \
                                   FN00000001_EDX_PSE36      | \
                                   FN00000001_EDX_PAT        | \
                                   FN00000001_EDX_CMOV       | \
                                   FN00000001_EDX_MCA        | \
                                   FN00000001_EDX_PGE        | \
                                   FN00000001_EDX_MTRR       | \
                                   FN00000001_EDX_SYSENTEXIT | \
                                   FN00000001_EDX_APIC       | \
                                   FN00000001_EDX_CMPXCHG8B  | \
                                   FN00000001_EDX_MCE        | \
                                   FN00000001_EDX_PAE        | \
                                   FN00000001_EDX_MSR        | \
                                   FN00000001_EDX_TSC        | \
                                   FN00000001_EDX_PSE        | \
                                   FN00000001_EDX_DE         | \
                                   FN00000001_EDX_VME        | \
                                   FN00000001_EDX_FPU)


/* FN00000002 Defines */   /* Not actually in the PPR */


/* FN00000004 Defines */   /* Not actually in the PPR */


/* FN00000005 Defines */
#define FN00000005_EAX_DEFAULT     (0x00000040)
#define FN00000005_EAX_RESERVED    (0xFFFF0000)
#define FN00000005_EBX_DEFAULT     (0x00000040)
#define FN00000005_EBX_RESERVED    (0xFFFF0000)
#define FN00000005_ECX_DEFAULT     (0x00000003)
#define FN00000005_ECX_RESERVED    (0xFFFFFFFC)
#define FN00000005_EDX_DEFAULT     (0x00000011)
#define FN00000005_EDX_RESERVED    (0xFFFFFF00)


/* FN00000006 Defines */
#define FN00000006_EAX_DEFAULT     (0x00000004)
#define FN00000006_EAX_RESERVED    (0xFFFFFFFB)
#define FN00000006_EBX_DEFAULT     (0x00000000)
#define FN00000006_EBX_RESERVED    (0xFFFFFFFF)
#define FN00000006_ECX_DEFAULT     (0x00000001)
#define FN00000006_ECX_RESERVED    (0xFFFFFFFE)
#define FN00000006_EDX_DEFAULT     (0x00000000)
#define FN00000006_EDX_RESERVED    (0xFFFFFFFF)


/* FN00000007_x00 Defines */
#define FN00000007_x00_EAX_DEFAULT  (0x00000001)
#define FN00000007_x00_EAX_RESERVED (0x00000000)

/* FN00000007_x00 EBX Defines */
#define FN00000007_x00_EBX_AVX512VL (1UL << 31)
#define FN00000007_x00_EBX_AVX512BW (1 << 30)
#define FN00000007_x00_EBX_SHA      (1 << 29)
#define FN00000007_x00_EBX_AVX512CD (1 << 28)
#define FN00000007_x00_EBX_CLWB     (1 << 24)
#define FN00000007_x00_EBX_CLFSHOPT (1 << 23)
#define FN00000007_x00_EBX_PCOMMIT  (0 << 22)
#define FN00000007_x00_EBX_AVX512_IFMA (1 << 21)
#define FN00000007_x00_EBX_SMAP     (1 << 20)
#define FN00000007_x00_EBX_ADX      (1 << 19)
#define FN00000007_x00_EBX_RDSEED   (1 << 18)
#define FN00000007_x00_EBX_AVX512DQ (1 << 17)
#define FN00000007_x00_EBX_AVX512F  (1 << 16)
#define FN00000007_x00_EBX_PQE      (1 << 15)
#define FN00000007_x00_EBX_PQM      (1 << 12)
#define FN00000007_x00_EBX_INVPCID  (1 << 10)
#define FN00000007_x00_EBX_ERMS     (1 << 9)
#define FN00000007_x00_EBX_BMI2     (1 << 8)
#define FN00000007_x00_EBX_SMEP     (1 << 7)
#define FN00000007_x00_EBX_AVX2     (1 << 5)
#define FN00000007_x00_EBX_HLE      (0 << 4)
#define FN00000007_x00_EBX_BMII     (1 << 3)
#define FN00000007_x00_EBX_FSGSBASE (1 << 0)
#define FN00000007_x00_EBX_RESERVED (0xE006846)

#define FN00000007_x00_EBX_DEFAULT  (FN00000007_x00_EBX_AVX512VL    | \
                                     FN00000007_x00_EBX_AVX512BW    | \
                                     FN00000007_x00_EBX_SHA         | \
                                     FN00000007_x00_EBX_AVX512CD    | \
                                     FN00000007_x00_EBX_CLWB        | \
                                     FN00000007_x00_EBX_CLFSHOPT    | \
                                     FN00000007_x00_EBX_PCOMMIT     | \
                                     FN00000007_x00_EBX_AVX512_IFMA | \
                                     FN00000007_x00_EBX_SMAP        | \
                                     FN00000007_x00_EBX_ADX         | \
                                     FN00000007_x00_EBX_RDSEED      | \
                                     FN00000007_x00_EBX_AVX512DQ    | \
                                     FN00000007_x00_EBX_AVX512F     | \
                                     FN00000007_x00_EBX_PQE         | \
                                     FN00000007_x00_EBX_PQM         | \
                                     FN00000007_x00_EBX_INVPCID     | \
                                     FN00000007_x00_EBX_ERMS        | \
                                     FN00000007_x00_EBX_BMI2        | \
                                     FN00000007_x00_EBX_SMEP        | \
                                     FN00000007_x00_EBX_AVX2        | \
                                     FN00000007_x00_EBX_HLE         | \
                                     FN00000007_x00_EBX_BMII        | \
                                     FN00000007_x00_EBX_FSGSBASE)

/* FN00000007_x00 ECX Define */
#define FN00000007_x00_ECX_RDPID         (1 << 22)
#define FN00000007_x00_ECX_LA57          (1 << 16)
#define FN00000007_x00_ECX_AVX512_VPOP   (1 << 14)
#define FN00000007_x00_ECX_AVX512_BITALG (1 << 12)
#define FN00000007_x00_ECX_AVX512_VNNI   (1 << 11)
#define FN00000007_x00_ECX_VPCLMULQDQ    (1 << 10) /* Dynamic */
#define FN00000007_x00_ECX_VAES_256      (1 << 9)  /* Dynamic */
#define FN00000007_x00_ECX_GFNI          (1 << 8)
#define FN00000007_x00_ECX_CET_SS        (1 << 7)
#define FN00000007_x00_ECX_AVX512_VBMI2  (1 << 6)
#define FN00000007_x00_ECX_OSPKE         (1 << 4)  /* Dynamic */
#define FN00000007_x00_ECX_PKU           (1 << 3)
#define FN00000007_x00_ECX_UMIP          (1 << 2)
#define FN00000007_x00_ECX_AVX512_VBMI   (1 << 1)
#define FN00000007_x00_ECX_RESERVED      (0xFFBEA021)

/* OSPKE is not included in the check */
#define FN00000007_x00_ECX_DEFAULT    (FN00000007_x00_ECX_RDPID         | \
                                       FN00000007_x00_ECX_LA57          | \
                                       FN00000007_x00_ECX_AVX512_VPOP   | \
                                       FN00000007_x00_ECX_AVX512_BITALG | \
                                       FN00000007_x00_ECX_AVX512_VNNI   | \
                                       FN00000007_x00_ECX_VPCLMULQDQ    | \
                                       FN00000007_x00_ECX_VAES_256      | \
                                       FN00000007_x00_ECX_GFNI          | \
                                       FN00000007_x00_ECX_CET_SS        | \
                                       FN00000007_x00_ECX_AVX512_VBMI2  | \
                                       FN00000007_x00_ECX_PKU           | \
                                       FN00000007_x00_ECX_UMIP          | \
                                       FN00000007_x00_ECX_AVX512_VBMI)

/* FN00000007_x00_EDX  */
#define FN00000007_x00_EDX_DEFAULT    (0x10000010)  /* (DECBRTL-17950) */
#define FN00000007_x00_EDX_RESERVED   (0xEFFFFFEF)

/* FN00000007_x01 EAX Defines */
#define FN00000007_x01_EAX_AVX512_BF16  (1 << 5)
#define FN00000007_x01_EAX_DEFAULT      (FN00000007_x01_EAX_AVX512_BF16)
#define FN00000007_x01_EAX_RESERVED     ~(FN00000007_x01_EAX_DEFAULT)

/* FN00000007_x01 EBX Defines */
#define FN00000007_x01_EBX_DEFAULT      (0)
#define FN00000007_x01_EBX_RESERVED     ~(FN00000007_x01_EBX_DEFAULT)

/* FN00000007_x01 ECX Defines */
#define FN00000007_x01_ECX_DEFAULT      (0)
#define FN00000007_x01_ECX_RESERVED     ~(FN00000007_x01_ECX_DEFAULT)

/* FN00000007_x01 EDX Defines */
#define FN00000007_x01_EDX_DEFAULT      (0)
#define FN00000007_x01_EDX_RESERVED     ~(FN00000007_x01_ECX_DEFAULT)



/* FN0000000B_x00 Defines */
#define FN0000000B_x00_EAX_DEFAULT    (0x00000001)  /* Dynamic */
#define FN0000000B_x00_EAX_RESERVED   (0xFFFFFFE0)
#define FN0000000B_x00_EBX_DEFAULT    (0x00000003)  /* Dynamic, Supports SMT on or off */
#define FN0000000B_x00_EBX_RESERVED   (0xFFFF0000)
#define FN0000000B_x00_ECX_DEFAULT    (0x00000100)
#define FN0000000B_x00_ECX_RESERVED   (0xFFFF0000)
/* EDX for FN00000008 is the same regardless of ECX, it returns extended APIC_ID */
#define FN0000000B_EDX_DEFAULT        (0xFFFFFFFF)  /* Dynamic */
#define FN0000000B_EDX_RESERVED       (0x00000000)

/* FN0000000B_x01 Defines */
#define FN0000000B_x01_EAX_DEFAULT    (0x00000007)  /* Dynamic. */
#define FN0000000B_x01_EAX_RESERVED   (0xFFFFFFE0)
#define FN0000000B_x01_EBX_DEFAULT    (0x000000FF)  /* Dynamic - Mask */
#define FN0000000B_x01_EBX_RESERVED   (0xFFFF0000)
#define FN0000000B_x01_ECX_DEFAULT    (0x00000201)
#define FN0000000B_x01_ECX_RESERVED   (0xFFFF0000)

/* FN0000000B_x02 Defines */
#define FN0000000B_x02_EAX_DEFAULT    (0x00000000)
#define FN0000000B_x02_EAX_RESERVED   (0xFFFFFFE0)
#define FN0000000B_x02_EBX_DEFAULT    (0x00000000)
#define FN0000000B_x02_EBX_RESERVED   (0xFFFF0000)
#define FN0000000B_x02_ECX_DEFAULT    (0x00000002)
#define FN0000000B_x02_ECX_RESERVED   (0xFFFF0000)


/* FN0000000D_x00 defines - these depends on XCR0 values */
#define FN0000000D_x00_EAX_MPK        (1 << 9)
#define FN0000000D_x00_EAX_HIZMM      (1 << 7)
#define FN0000000D_x00_EAX_ZMMHI      (1 << 6)
#define FN0000000D_x00_EAX_KREGS      (1 << 5)
#define FN0000000D_x00_EAX_AVX        (1 << 2)
#define FN0000000D_x00_EAX_SSE        (1 << 1)
#define FN0000000D_x00_EAX_X87        (1 << 0)
#define FN0000000D_x00_EAX_RESERVED   (0xFFFFFD18)

#define FN0000000D_x00_EAX_DEFAULT    (FN0000000D_x00_EAX_MPK   | \
                                       FN0000000D_x00_EAX_HIZMM | \
                                       FN0000000D_x00_EAX_ZMMHI | \
                                       FN0000000D_x00_EAX_KREGS | \
                                       FN0000000D_x00_EAX_AVX   | \
                                       FN0000000D_x00_EAX_SSE   | \
                                       FN0000000D_x00_EAX_X87)

#define FN0000000D_x00_EBX_DEFAULT    (0x0000FFFF) /* Dynamic. XFeatureEnabledSizeMax depends on XCR0 - Mask */
#define FN0000000D_x00_EBX_RESERVED   (0x00000000)
#define FN0000000D_x00_ECX_DEFAULT    (0x00000988)
#define FN0000000D_x00_ECX_RESERVED   (0x00000000)
#define FN0000000D_x00_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x00_EDX_RESERVED   (0x00000000)


/* FN0000000D_x01 defines */
#define FN0000000D_x01_EAX_XSAVES     (1 << 3)
#define FN0000000D_x01_EAX_XGETBV     (1 << 2)
#define FN0000000D_x01_EAX_XSAVEC     (1 << 1)
#define FN0000000D_x01_EAX_XSAVEOPT   (1 << 0)
#define FN0000000D_x01_EAX_RESERVED   (0xFFFFFFF0)

#define FN0000000D_x01_EAX_DEFAULT    (FN0000000D_x01_EAX_XSAVES   | \
                                       FN0000000D_x01_EAX_XGETBV   | \
                                       FN0000000D_x01_EAX_XSAVEC   | \
                                       FN0000000D_x01_EAX_XSAVEOPT)

#define FN0000000D_x01_EBX_DEFAULT    (0x0000FFFF) /* Dynamic. XFeatureEnabledSizeMax depends on XCR0 and IA32_XSS - Mask */
#define FN0000000D_x01_EBX_RESERVED   (0x00000000)
#define FN0000000D_x01_ECX_DEFAULT    (0x00001800)
#define FN0000000D_x01_ECX_RESERVED   (0x00000000)
#define FN0000000D_x01_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x01_EDX_RESERVED   (0x00000000)


/* FN0000000D_x02 defines */
#define FN0000000D_x02_EAX_DEFAULT    (0x00000100)
#define FN0000000D_x02_EAX_RESERVED   (0x00000000)
#define FN0000000D_x02_EBX_DEFAULT    (0x00000240)
#define FN0000000D_x02_EBX_RESERVED   (0x00000000)
#define FN0000000D_x02_ECX_DEFAULT    (0x00000000)
#define FN0000000D_x02_ECX_RESERVED   (0xFFFFFFFC)
#define FN0000000D_x02_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x02_EDX_RESERVED   (0xFFFFFFFF)

/* FN0000000D_x05 defines */
#define FN0000000D_x05_EAX_DEFAULT    (0x00000040)
#define FN0000000D_x05_EAX_RESERVED   (0x00000000)
#define FN0000000D_x05_EBX_DEFAULT    (0x00000340)
#define FN0000000D_x05_EBX_RESERVED   (0x00000000)
#define FN0000000D_x05_ECX_DEFAULT    (0x00000003)
#define FN0000000D_x05_ECX_RESERVED   ~(FN0000000D_x05_ECX_DEFAULT)
#define FN0000000D_x05_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x05_EDX_RESERVED   (0xFFFFFFFF)

/* FN0000000D_x06 defines */
#define FN0000000D_x06_EAX_DEFAULT    (0x00000200)
#define FN0000000D_x06_EAX_RESERVED   (0x00000000)
#define FN0000000D_x06_EBX_DEFAULT    (0x00000380)
#define FN0000000D_x06_EBX_RESERVED   (0x00000000)
#define FN0000000D_x06_ECX_DEFAULT    (0x00000003)
#define FN0000000D_x06_ECX_RESERVED   ~(FN0000000D_x06_ECX_DEFAULT)
#define FN0000000D_x06_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x06_EDX_RESERVED   (0xFFFFFFFF)

/* FN0000000D_x07 defines */
#define FN0000000D_x07_EAX_DEFAULT    (0x00000400)
#define FN0000000D_x07_EAX_RESERVED   (0x00000000)
#define FN0000000D_x07_EBX_DEFAULT    (0x00000580)
#define FN0000000D_x07_EBX_RESERVED   (0x00000000)
#define FN0000000D_x07_ECX_DEFAULT    (0x00000003)
#define FN0000000D_x07_ECX_RESERVED   ~(FN0000000D_x07_ECX_DEFAULT)
#define FN0000000D_x07_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x07_EDX_RESERVED   (0xFFFFFFFF)


/* FN0000000D_x09 defines */
#define FN0000000D_x09_EAX_DEFAULT    (0x00000008)
#define FN0000000D_x09_EAX_RESERVED   (0x00000000)
#define FN0000000D_x09_EBX_DEFAULT    (0x00000980)
#define FN0000000D_x09_EBX_RESERVED   (0x00000000)
#define FN0000000D_x09_ECX_DEFAULT    (0x00000000)
#define FN0000000D_x09_ECX_RESERVED   (0xFFFFFFFC)
#define FN0000000D_x09_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x09_EDX_RESERVED   (0xFFFFFFFF)


/* FN0000000D_x0B defines */
#define FN0000000D_x0B_EAX_DEFAULT    (0x00000010)
#define FN0000000D_x0B_EAX_RESERVED   (0x00000000)
#define FN0000000D_x0B_EBX_DEFAULT    (0x00000000)
#define FN0000000D_x0B_EBX_RESERVED   (0x00000000)
#define FN0000000D_x0B_ECX_DEFAULT    (0x00000001)
#define FN0000000D_x0B_ECX_RESERVED   (0xFFFFFFFC)
#define FN0000000D_x0B_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x0B_EDX_RESERVED   (0xFFFFFFFF)


/* FN0000000D_x0C defines */
#define FN0000000D_x0C_EAX_DEFAULT    (0x00000018)
#define FN0000000D_x0C_EAX_RESERVED   (0x00000000)
#define FN0000000D_x0C_EBX_DEFAULT    (0x00000000)
#define FN0000000D_x0C_EBX_RESERVED   (0x00000000)
#define FN0000000D_x0C_ECX_DEFAULT    (0x00000001)
#define FN0000000D_x0C_ECX_RESERVED   (0xFFFFFFFC)
#define FN0000000D_x0C_EDX_DEFAULT    (0x00000000)
#define FN0000000D_x0C_EDX_RESERVED   (0xFFFFFFFF)


/* FN0000000F_x00 defines */
#define FN0000000F_x00_EAX_DEFAULT    (0x00000000)
#define FN0000000F_x00_EAX_RESERVED   (0xFFFFFFFF)
#define FN0000000F_x00_EBX_DEFAULT    (0x000000FF)
#define FN0000000F_x00_EBX_RESERVED   (0x00000000)
#define FN0000000F_x00_ECX_DEFAULT    (0x00000000)
#define FN0000000F_x00_ECX_RESERVED   (0xFFFFFFFF)
#define FN0000000F_x00_EDX_DEFAULT    (0x00000002)
#define FN0000000F_x00_EDX_RESERVED   (0xFFFFFFFD)


/* FN0000000F_x01 defines */
#define FN0000000F_x01_EAX_DEFAULT    (0x00000000)
#define FN0000000F_x01_EAX_RESERVED   (0xFFFFFE00)
#define FN0000000F_x01_EBX_DEFAULT    (0x00000040)
#define FN0000000F_x01_EBX_RESERVED   (0x00000000)
#define FN0000000F_x01_ECX_DEFAULT    (0x000000FF)
#define FN0000000F_x01_ECX_RESERVED   (0x00000000)

#define FN0000000F_x01_EDX_L3CACHELOCALBNDWDTHMON  (1 << 2)
#define FN0000000F_x01_EDX_L3CACHETOTALBNDWDTHMON  (1 << 1)
#define FN0000000F_x01_EDX_L3CACHEOCCUPNCYMON      (1 << 0)
#define FN0000000F_x01_EDX_RESERVED   (0xFFFFFFF8)

#define FN0000000F_x01_EDX_DEFAULT     (FN0000000F_x01_EDX_L3CACHELOCALBNDWDTHMON | \
                                        FN0000000F_x01_EDX_L3CACHETOTALBNDWDTHMON | \
                                        FN0000000F_x01_EDX_L3CACHEOCCUPNCYMON)


/* FN00000010_x00 defines */
#define FN00000010_x00_EAX_DEFAULT    (0x00000000)
#define FN00000010_x00_EAX_RESERVED   (0xFFFFFFFF)
#define FN00000010_x00_EBX_DEFAULT    (0x00000002)
#define FN00000010_x00_EBX_RESERVED   (0xFFFFFFF9)
#define FN00000010_x00_ECX_DEFAULT    (0x00000000)
#define FN00000010_x00_ECX_RESERVED   (0xFFFFFFFF)
#define FN00000010_x00_EDX_DEFAULT    (0x00000000)
#define FN00000010_x00_EDX_RESERVED   (0xFFFFFFFF)


/* FN00000010_x01 defines */
#define FN00000010_x01_EAX_DEFAULT    (0x0000000F)
#define FN00000010_x01_EAX_RESERVED   (0xFFFFFFE0)
#define FN00000010_x01_EBX_DEFAULT    (0x00000000)  /* Dynamic */
#define FN00000010_x01_EBX_RESERVED   (0x00000000)
#define FN00000010_x01_ECX_DEFAULT    (0x00000004)
#define FN00000010_x01_ECX_RESERVED   (0xFFFFFFFB)
#define FN00000010_x01_EDX_DEFAULT    (0x0000000F)
#define FN00000010_x01_EDX_RESERVED   (0xFFFF0000)


/* FN80000000 Defines */
#define FN80000000_EAX_DEFAULT        (0x80000028)
#define FN80000000_EAX_RESERVED       (0x00000000)
#define FN80000000_EBX_DEFAULT        (0x68747541)
#define FN80000000_EBX_RESERVED       (0x00000000)
#define FN80000000_ECX_DEFAULT        (0x444D4163)
#define FN80000000_ECX_RESERVED       (0x00000000)
#define FN80000000_EDX_DEFAULT        (0x69746E65)
#define FN80000000_EDX_RESERVED       (0x00000000)


/* FN80000001 Defines */
/* FN80000001_EAX - see FN00000001_EAX values, it's the same function */

/* FN80000001_EBX defines */
#define FN80000001_EBX_DEFAULT        (0x40000000)
#define FN80000001_EBX_RESERVED       (0x0FFFFFFF)

/* FN80000001_ECX defines */
#define FN80000001_ECX_ADMSKEXTN      (1 << 30)
#define FN80000001_ECX_MWAITEXTENDED  (1 << 29) /* Dynamic */
#define FN80000001_ECX_PERFCTRLEXTLLC (1 << 28)
#define FN80000001_ECX_PERFTSC        (0 << 27)
#define FN80000001_ECX_DATABPEXT      (1 << 26)
#define FN80000001_ECX_STREAMPERFMON  (0 << 25)
#define FN80000001_ECX_PERFCTRLEXTDF  (1 << 24)
#define FN80000001_ECX_PERFCTREXTCORE (1 << 23)
#define FN80000001_ECX_TOPOLOGYEXT    (1 << 22)
#define FN80000001_ECX_TCE            (1 << 17)
#define FN80000001_ECX_FMA4           (0 << 16)
#define FN80000001_ECX_LWP            (0 << 15)
#define FN80000001_ECX_WDT            (1 << 13)
#define FN80000001_ECX_SKINIT         (1 << 12)
#define FN80000001_ECX_XOP            (0 << 11)
#define FN80000001_ECX_IBS            (1 << 10)
#define FN80000001_ECX_OSVW           (1 << 9)
#define FN80000001_ECX_3DNOWPREFETCH  (1 << 8)
#define FN80000001_ECX_MISALIGN       (1 << 7)
#define FN80000001_ECX_SSE4A          (1 << 6)
#define FN80000001_ECX_ABM            (1 << 5)
#define FN80000001_ECX_ALTMOVCR8      (1 << 4)
#define FN80000001_ECX_EXTAPICSPACE   (1 << 3)
#define FN80000001_ECX_SVM            (1 << 2)
#define FN80000001_ECX_CMPLEGACY      (1 << 1)
#define FN80000001_ECX_LAHFSAHF       (1 << 0)
#define FN80000001_ECX_RESERVED       (0x803C4000)

#define FN80000001_ECX_DEFAULT        (FN80000001_ECX_ADMSKEXTN       | \
                                       FN80000001_ECX_MWAITEXTENDED   | \
                                       FN80000001_ECX_PERFCTRLEXTLLC  | \
                                       FN80000001_ECX_PERFTSC         | \
                                       FN80000001_ECX_DATABPEXT       | \
                                       FN80000001_ECX_STREAMPERFMON   | \
                                       FN80000001_ECX_PERFCTRLEXTDF   | \
                                       FN80000001_ECX_PERFCTREXTCORE  | \
                                       FN80000001_ECX_TOPOLOGYEXT     | \
                                       FN80000001_ECX_TCE             | \
                                       FN80000001_ECX_FMA4            | \
                                       FN80000001_ECX_LWP             | \
                                       FN80000001_ECX_WDT             | \
                                       FN80000001_ECX_SKINIT          | \
                                       FN80000001_ECX_XOP             | \
                                       FN80000001_ECX_IBS             | \
                                       FN80000001_ECX_OSVW            | \
                                       FN80000001_ECX_3DNOWPREFETCH   | \
                                       FN80000001_ECX_MISALIGN        | \
                                       FN80000001_ECX_SSE4A           | \
                                       FN80000001_ECX_ABM             | \
                                       FN80000001_ECX_ALTMOVCR8       | \
                                       FN80000001_ECX_EXTAPICSPACE    | \
                                       FN80000001_ECX_SVM             | \
                                       FN80000001_ECX_CMPLEGACY       | \
                                       FN80000001_ECX_LAHFSAHF)

/* FN80000001_EDX defines */
#define FN80000001_EDX_3DNOW          (0UL << 31)
#define FN80000001_EDX_3DNOWEXT       (0 << 30)
#define FN80000001_EDX_LM             (1 << 29)
#define FN80000001_EDX_RDTSCP         (1 << 27)
#define FN80000001_EDX_PAGE1GB        (1 << 26)
#define FN80000001_EDX_FFXSR          (1 << 25)
#define FN80000001_EDX_FXSR           (1 << 24)
#define FN80000001_EDX_MMX            (1 << 23)
#define FN80000001_EDX_MMXEXT         (1 << 22)
#define FN80000001_EDX_NX             (1 << 20)
#define FN80000001_EDX_PSE36          (1 << 17)
#define FN80000001_EDX_PAT            (1 << 16)
#define FN80000001_EDX_CMOV           (1 << 15)
#define FN80000001_EDX_MCA            (1 << 14)
#define FN80000001_EDX_PGE            (1 << 13)
#define FN80000001_EDX_MTRR           (1 << 12)
#define FN80000001_EDX_SYSCALLSYSRET  (1 << 11)
#define FN80000001_EDX_APIC           (1 << 9)  /* Dynamic */
#define FN80000001_EDX_CMPXCHG8B      (1 << 8)
#define FN80000001_EDX_MCE            (1 << 7)
#define FN80000001_EDX_PAE            (1 << 6)
#define FN80000001_EDX_MSR            (1 << 5)
#define FN80000001_EDX_TSC            (1 << 4)
#define FN80000001_EDX_PSE            (1 << 3)
#define FN80000001_EDX_DE             (1 << 2)
#define FN80000001_EDX_VME            (1 << 1)
#define FN80000001_EDX_FPU            (1 << 0)
#define FN80000001_EDX_RESERVED       (0x102C0400)

#define FN80000001_EDX_DEFAULT        (FN80000001_EDX_3DNOW         | \
                                       FN80000001_EDX_3DNOWEXT      | \
                                       FN80000001_EDX_LM            | \
                                       FN80000001_EDX_RDTSCP        | \
                                       FN80000001_EDX_PAGE1GB       | \
                                       FN80000001_EDX_FFXSR         | \
                                       FN80000001_EDX_FXSR          | \
                                       FN80000001_EDX_MMX           | \
                                       FN80000001_EDX_MMXEXT        | \
                                       FN80000001_EDX_NX            | \
                                       FN80000001_EDX_PSE36         | \
                                       FN80000001_EDX_PAT           | \
                                       FN80000001_EDX_CMOV          | \
                                       FN80000001_EDX_MCA           | \
                                       FN80000001_EDX_PGE           | \
                                       FN80000001_EDX_MTRR          | \
                                       FN80000001_EDX_SYSCALLSYSRET | \
                                       FN80000001_EDX_APIC          | \
                                       FN80000001_EDX_CMPXCHG8B     | \
                                       FN80000001_EDX_MCE           | \
                                       FN80000001_EDX_PAE           | \
                                       FN80000001_EDX_MSR           | \
                                       FN80000001_EDX_TSC           | \
                                       FN80000001_EDX_PSE           | \
                                       FN80000001_EDX_DE            | \
                                       FN80000001_EDX_VME           | \
                                       FN80000001_EDX_FPU)


/* FN80000002, FN80000003, FN80000004 Defines - these are all strings, can be any value */
#define FN80000002_DEFAULT  (0xFFFFFFFF) /* Dynamic */
#define FN80000002_RESERVED (0x00000000)
#define FN80000003_DEFAULT  (0xFFFFFFFF) /* Dynamic */
#define FN80000003_RESERVED (0x00000000)
#define FN80000004_DEFAULT  (0xFFFFFFFF) /* Dynamic */
#define FN80000004_RESERVED (0x00000000)


/* FN80000005 Defines */
#define FN80000005_EAX_DEFAULT  (0xFF40FF40)
#define FN80000005_EAX_RESERVED (0x00000000)
#define FN80000005_EBX_DEFAULT  (0xFF40FF40)
#define FN80000005_EBX_RESERVED (0x00000000)
#define FN80000005_ECX_DEFAULT  (0x20080140)
#define FN80000005_ECX_RESERVED (0x00000000)
#define FN80000005_EDX_DEFAULT  (0x20080140)
#define FN80000005_EDX_RESERVED (0x00000000)


/* FN80000006 Defines */
#define FN80000006_EAX_DEFAULT  (0x48002200)    /* Dynamic, L2DTlb2and4MAssoc is not fixed */
#define FN80000006_EAX_RESERVED (0x00000000)
#define FN80000006_EBX_DEFAULT  (0x68004200)    /* Dynamic, L2DTlb4KAssoc is not fixed */
#define FN80000006_EBX_RESERVED (0x00000000)
#define FN80000006_ECX_DEFAULT  (0x02006140)    /* Dynamic, L2Size is not fixed */
#define FN80000006_ECX_RESERVED (0x00000000)
#define FN80000006_EDX_DEFAULT  (0xFFFFFFFF)    /* Dynamic, L3Size is not fixed, changes based on number of CCDs - Mask */
#define FN80000006_EDX_RESERVED (0x00030000)


/* FN80000007 Defines */
#define FN80000007_EAX_DEFAULT             (0x00000000)
#define FN80000007_EAX_RESERVED            (0xFFFFFFFF)

/* FN80000007_EBX Definitions */
#define FN80000007_EBX_LWSMI               (1 << 5)
#define FN80000007_EBX_PFEHSUPPORTPRESENT  (1 << 4)
#define FN80000007_EBX_SCALABLEMCA         (1 << 3)
#define FN80000007_EBX_HWA                 (0 << 2)
#define FN80000007_EBX_SUCCOR              (1 << 1) /* Dynamic */
#define FN80000007_EBX_MCAOVERFLOWRECOV    (1 << 0)
#define FN80000007_EBX_RESERVED            (0xFFFFFFC0)

#define FN80000007_EBX_DEFAULT             (FN80000007_EBX_LWSMI              | \
                                            FN80000007_EBX_PFEHSUPPORTPRESENT | \
                                            FN80000007_EBX_SCALABLEMCA        | \
                                            FN80000007_EBX_HWA                | \
                                            FN80000007_EBX_SUCCOR             | \
                                            FN80000007_EBX_MCAOVERFLOWRECOV)

#define FN80000007_ECX_DEFAULT             (0x00000000)
#define FN80000007_ECX_RESERVED            (0x00000000)

/* FN80000007_EDX Defines */
#define FN80000007_EDX_RAPL                (1 << 14)
#define FN80000007_EDX_CONNECTEDSTANDBY    (1 << 13)
#define FN80000007_EDX_PROCPOWERREPORTING  (0 << 12)
#define FN80000007_EDX_PROCFDBKIFC         (0 << 11)
#define FN80000007_EDX_EFFFREQRO           (1 << 10)
#define FN80000007_EDX_CPB                 (1 << 9)     /* Dynamic */
#define FN80000007_EDX_TSCINVARIANT        (1 << 8)
#define FN80000007_EDX_HWPSTATE            (1 << 7)
#define FN80000007_EDX_ONEHUNDREDMHZSTEP   (0 << 6)
#define FN80000007_EDX_TM                  (1 << 4)
#define FN80000007_EDX_TTP                 (1 << 3)
#define FN80000007_EDX_TS                  (1 << 0)
#define FN80000007_EDX_RESERVED            (0xFFFF8026)

#define FN80000007_EDX_DEFAULT             (FN80000007_EDX_RAPL               | \
                                            FN80000007_EDX_CONNECTEDSTANDBY   | \
                                            FN80000007_EDX_PROCPOWERREPORTING | \
                                            FN80000007_EDX_PROCFDBKIFC        | \
                                            FN80000007_EDX_EFFFREQRO          | \
                                            FN80000007_EDX_CPB                | \
                                            FN80000007_EDX_TSCINVARIANT       | \
                                            FN80000007_EDX_HWPSTATE           | \
                                            FN80000007_EDX_ONEHUNDREDMHZSTEP  | \
                                            FN80000007_EDX_TM                 | \
                                            FN80000007_EDX_TTP                | \
                                            FN80000007_EDX_TS)

/* FN80000008 Defines */
#define FN80000008_EAX_PADDRSIZE_MASK     (0x000000FF)
#define FN80000008_EAX_PADDRSIZE_SHIFT    (0)
#define FN80000008_EAX_PADDRSIZE_EXACT    (0x00000034)
#define FN80000008_EAX_LADDRSIZE_MASK     (0x0000FF00)
#define FN80000008_EAX_LADDRSIZE_SHIFT    (8)
#define FN80000008_EAX_LADDRSIZE_EXACT    (0x00000039)
#define FN80000008_EAX_GPADDRSIZE_MASK    (0x00FF0000)
#define FN80000008_EAX_GPADDRSIZE_SHIFT   (16)
#define FN80000008_EAX_GPADDRSIZE_EXACT   (0x000000FF)
#define FN80000008_EAX_RESERVED           (0xFF000000)

/* FN80000008_EBX Definitions. Most params below are Dynamic */
#define FN80000008_EBX_BRANCHSAMPLE       (0UL << 31)
#define FN80000008_EBX_IBPB_RET           (1UL << 30)
#define FN80000008_EBX_BTC_NO             (1 << 29)
#define FN80000008_EBX_PSFD               (1 << 28)
#define FN80000008_EBX_CPPC               (1 << 27)
#define FN80000008_EBX_SSBD               (1 << 24)
#define FN80000008_EBX_PPIN               (1 << 23)
#define FN80000008_EBX_LBRTSXINFO         (0 << 22)
#define FN80000008_EBX_TLBFLUSHNESTED     (1 << 21)
#define FN80000008_EBX_EFERLMSLEUNSUPP    (1 << 20)
#define FN80000008_EBX_IBRSPRVSSAMEMODE   (1 << 19)
#define FN80000008_EBX_IBRSPREFERRED      (1 << 18)
#define FN80000008_EBX_STIBPALWAYSON      (1 << 17)
#define FN80000008_EBX_IBRSALWAYSON       (0 << 16)
#define FN80000008_EBX_STIBP              (1 << 15)
#define FN80000008_EBX_IBRS               (1 << 14)
#define FN80000008_EBX_INT_WBINVD         (1 << 13)
#define FN80000008_EBX_IBPB               (1 << 12)
#define FN80000008_EBX_LBREXTN            (0 << 10)
#define FN80000008_EBX_WBNOINVD           (1 << 9)
#define FN80000008_EBX_MCOMMIT            (1 << 8)  /* Dynamic */
#define FN80000008_EBX_MBE                (1 << 6)
#define FN80000008_EBX_RDPRU              (1 << 4)
#define FN80000008_EBX_INVLPGB            (1 << 3)
#define FN80000008_EBX_RSTRFPERRPTRS      (1 << 2)
#define FN80000008_EBX_INSTRETCNTMSR      (1 << 1)
#define FN80000008_EBX_CLZERO             (1 << 0)
#define FN80000008_EBX_RESERVED           (0x060008A0)

#define FN80000008_EBX_DEFAULT            (FN80000008_EBX_BRANCHSAMPLE     | \
                                           FN80000008_EBX_IBPB_RET         | \
                                           FN80000008_EBX_BTC_NO           | \
                                           FN80000008_EBX_PSFD             | \
                                           FN80000008_EBX_CPPC             | \
                                           FN80000008_EBX_SSBD             | \
                                           FN80000008_EBX_PPIN             | \
                                           FN80000008_EBX_LBRTSXINFO       | \
                                           FN80000008_EBX_TLBFLUSHNESTED   | \
                                           FN80000008_EBX_EFERLMSLEUNSUPP  | \
                                           FN80000008_EBX_IBRSPRVSSAMEMODE | \
                                           FN80000008_EBX_IBRSPREFERRED    | \
                                           FN80000008_EBX_STIBPALWAYSON    | \
                                           FN80000008_EBX_IBRSALWAYSON     | \
                                           FN80000008_EBX_STIBP            | \
                                           FN80000008_EBX_IBRS             | \
                                           FN80000008_EBX_INT_WBINVD       | \
                                           FN80000008_EBX_IBPB             | \
                                           FN80000008_EBX_LBREXTN          | \
                                           FN80000008_EBX_WBNOINVD         | \
                                           FN80000008_EBX_MCOMMIT          | \
                                           FN80000008_EBX_MBE              | \
                                           FN80000008_EBX_RDPRU            | \
                                           FN80000008_EBX_INVLPGB          | \
                                           FN80000008_EBX_RSTRFPERRPTRS    | \
                                           FN80000008_EBX_INSTRETCNTMSR    | \
                                           FN80000008_EBX_CLZERO)

/* FN80000008_ECX - SizeID - can be dynamic for APICIDSIZE and NC.
   For now, use MASK to allow for all settings on those two regs */
#define FN80000008_ECX_DEFAULT            (0x0000F0FF)  /* Dynamic */
#define FN80000008_ECX_RESERVED           (0xFFFC0F00)

#define FN80000008_EDX_INVLPGBMAX_MASK    (0x0000FFFF)
#define FN80000008_EDX_INVLPGBMAX_SHIFT   (0)
#define FN80000008_EDX_INVLPGBMAX_EXACT   (0x00000007)
#define FN80000008_EDX_RDPRUMAX_MASK      (0x00FF0000)
#define FN80000008_EDX_RDPRUMAX_SHIFT     (16)
#define FN80000008_EDX_RDPRUMAX_EXACT     (0x00000001)
#define FN80000008_EDX_RESERVED           (0xFF000000)


/* FN8000000A Definitions */
#define FN8000000A_EAX_DEFAULT            (0x00000001)
#define FN8000000A_EAX_RESERVED           (0xFFFFFF00)
#define FN8000000A_EBX_DEFAULT            (0x0000FFFF)  /* Dynamic - Can be 10h or 8000h - Mask */
#define FN8000000A_EBX_RESERVED           (0x00000000)
/* FN8000000A_ECX - does NOT exist */
/* FN8000000A_EDX definitions */
#define FN8000000A_EDX_VMCB_ADDR_RANGE    (1 << 28)
#define FN8000000A_EDX_EXTLVTFLTCHG       (1 << 27)
#define FN8000000A_EDX_IBSVIRT            (1 << 26)
#define FN8000000A_EDX_NMIVIRT            (1 << 25)
#define FN8000000A_EDX_TLBSYNC            (1 << 24)
#define FN8000000A_EDX_HOST_MCE_OVERRIDE  (1 << 23)
#define FN8000000A_EDX_NONWRITEGPT        (1 << 21)
#define FN8000000A_EDX_GUESSPECCTL        (1 << 20)
#define FN8000000A_EDX_SUPERVISORSS       (1 << 19)
#define FN8000000A_EDX_X2AVIC             (1 << 18)
#define FN8000000A_EDX_GMET               (1 << 17)
#define FN8000000A_EDX_VGIF               (1 << 16)
#define FN8000000A_EDX_V_VMSAVE_VMLOAD    (1 << 15)
#define FN8000000A_EDX_AVIC               (1 << 13)     /* Mismatch. PPR says 1, Linux has 0 */
#define FN8000000A_EDX_PAUSEFILTERTHRESH  (1 << 12)
#define FN8000000A_EDX_ENCRYPTEDMCODEP    (1 << 11)
#define FN8000000A_EDX_PAUSEFILTER        (1 << 10)
#define FN8000000A_EDX_DECODEASSIST       (1 << 7)
#define FN8000000A_EDX_FLUSHBYASID        (1 << 6)
#define FN8000000A_EDX_VMCBCLEAN          (1 << 5)
#define FN8000000A_EDX_TSCRATEMSR         (1 << 4)
#define FN8000000A_EDX_NRIPS              (1 << 3)
#define FN8000000A_EDX_SVML               (1 << 2)
#define FN8000000A_EDX_LBRVIRT            (1 << 1)
#define FN8000000A_EDX_NP                 (1 << 0)
#define FN8000000A_EDX_RESERVED           (0xE0404300)

#define FN8000000A_EDX_DEFAULT            (FN8000000A_EDX_VMCB_ADDR_RANGE   | \
                                           FN8000000A_EDX_EXTLVTFLTCHG      | \
                                           FN8000000A_EDX_IBSVIRT           | \
                                           FN8000000A_EDX_NMIVIRT           | \
                                           FN8000000A_EDX_TLBSYNC           | \
                                           FN8000000A_EDX_HOST_MCE_OVERRIDE | \
                                           FN8000000A_EDX_NONWRITEGPT       | \
                                           FN8000000A_EDX_GUESSPECCTL       | \
                                           FN8000000A_EDX_SUPERVISORSS      | \
                                           FN8000000A_EDX_X2AVIC            | \
                                           FN8000000A_EDX_GMET              | \
                                           FN8000000A_EDX_VGIF              | \
                                           FN8000000A_EDX_V_VMSAVE_VMLOAD   | \
                                           FN8000000A_EDX_AVIC              | \
                                           FN8000000A_EDX_PAUSEFILTERTHRESH | \
                                           FN8000000A_EDX_ENCRYPTEDMCODEP   | \
                                           FN8000000A_EDX_PAUSEFILTER       | \
                                           FN8000000A_EDX_DECODEASSIST      | \
                                           FN8000000A_EDX_FLUSHBYASID       | \
                                           FN8000000A_EDX_VMCBCLEAN         | \
                                           FN8000000A_EDX_TSCRATEMSR        | \
                                           FN8000000A_EDX_NRIPS             | \
                                           FN8000000A_EDX_SVML              | \
                                           FN8000000A_EDX_LBRVIRT           | \
                                           FN8000000A_EDX_NP)


/* FN80000019 Definitions */
#define FN80000019_EAX_DEFAULT            (0xF040F040)
#define FN80000019_EAX_RESERVED           (0x00000000)
#define FN80000019_EBX_DEFAULT            (0xF0400000)
#define FN80000019_EBX_RESERVED           (0x00000000)
/* FN80000019 ECX, EDX - do NOT exist */


/* FN8000001A Definitions */
#define FN8000001A_EAX_DEFAULT            (0x00000006)
#define FN8000001A_EAX_RESERVED           (0xFFFFFFF8)
/* FN8000001A EBX, ECX, EDX does not exist. */


/* FN8000001B Definitions */
/* FN8000001B_EAX Definition */
#define FN8000001B_EAX_ZEN4IBSEXT         (1 << 11)
#define FN8000001B_EAX_IBSOPDATA4         (0 << 10)
#define FN8000001B_EAX_IBSFETCHCTLEXTD    (1 << 9)
#define FN8000001B_EAX_OPBRNFUSE          (1 << 8)
#define FN8000001B_EAX_RIPINVALIDCHK      (1 << 7)
#define FN8000001B_EAX_OPCNTEXT           (1 << 6)
#define FN8000001B_EAX_BRNTRGT            (1 << 5)
#define FN8000001B_EAX_OPCNT              (1 << 4)
#define FN8000001B_EAX_RDWROPCNT          (1 << 3)
#define FN8000001B_EAX_OPSAM              (1 << 2)
#define FN8000001B_EAX_FETCHSAM           (1 << 1)  /* Dynamic - Mask */
#define FN8000001B_EAX_IBSFFV             (1 << 0)
#define FN8000001B_EAX_RESERVED           (0xFFFFF000)

#define FN8000001B_EAX_DEFAULT            (FN8000001B_EAX_ZEN4IBSEXT      | \
                                           FN8000001B_EAX_IBSOPDATA4      | \
                                           FN8000001B_EAX_IBSFETCHCTLEXTD | \
                                           FN8000001B_EAX_OPBRNFUSE       | \
                                           FN8000001B_EAX_RIPINVALIDCHK   | \
                                           FN8000001B_EAX_OPCNTEXT        | \
                                           FN8000001B_EAX_BRNTRGT         | \
                                           FN8000001B_EAX_OPCNT           | \
                                           FN8000001B_EAX_RDWROPCNT       | \
                                           FN8000001B_EAX_OPSAM           | \
                                           FN8000001B_EAX_FETCHSAM        | \
                                           FN8000001B_EAX_IBSFFV)
/* FN8000001B_EBX, ECX, EDX do not exist. */


/* FN8000001D_x00 definitions */
#define FN8000001D_x00_EAX_DEFAULT       ((0xFFF << 14) | (0 << 9) | (1 << 8) | (1 << 5) | (1 << 0)) /* Dynamic - NumSharingCache is Mask */
#define FN8000001D_x00_EAX_RESERVED      (0xFC003C00)
#define FN8000001D_x00_EBX_DEFAULT       ((7 << 22) | (00 << 12) | (0x3F << 0))
#define FN8000001D_x00_EBX_RESERVED      (0x00000000)
#define FN8000001D_x00_ECX_DEFAULT       (0x0000003F)
#define FN8000001D_x00_ECX_RESERVED      (0x00000000)
#define FN8000001D_x00_EDX_DEFAULT       ((0 << 1) | (0 << 0))
#define FN8000001D_x00_EDX_RESERVED      (0xFFFFFFFC)


/* FN8000001D_x01 definitions */
#define FN8000001D_x01_EAX_DEFAULT       ((0xFFF << 14) | (0 << 9) | (1 << 8) | (1 << 5) | (2 << 0)) /* Dynamic - NumSharingCache is Mask */
#define FN8000001D_x01_EAX_RESERVED      (0xFC003C00)
#define FN8000001D_x01_EBX_DEFAULT       ((7 << 22) | (00 << 12) | (0x3F << 0))
#define FN8000001D_x01_EBX_RESERVED      (0x00000000)
#define FN8000001D_x01_ECX_DEFAULT       (0x0000003F)
#define FN8000001D_x01_ECX_RESERVED      (0x00000000)
#define FN8000001D_x01_EDX_DEFAULT       ((0 << 1) | (0 << 0))
#define FN8000001D_x01_EDX_RESERVED      (0xFFFFFFFC)


/* FN8000001D_x02 definitions */
#define FN8000001D_x02_EAX_DEFAULT       ((0xFFF << 14) | (1 << 8) | (2 << 5) | (3 << 0)) /* Dynamic - NumSharingCache is Mask */
#define FN8000001D_x02_EAX_RESERVED      (0xFC003C00)
#define FN8000001D_x02_EBX_DEFAULT       ((7 << 22) | (00 << 12) | (0x3F << 0))
#define FN8000001D_x02_EBX_RESERVED      (0x00000000)
#define FN8000001D_x02_ECX_DEFAULT       (0x000003FF)
#define FN8000001D_x02_ECX_RESERVED      (0x00000000)
#define FN8000001D_x02_EDX_DEFAULT       ((1 << 1) | (0 << 0))
#define FN8000001D_x02_EDX_RESERVED      (0xFFFFFFFC)


/* FN8000001D_x03 definitions */
#define FN8000001D_x03_EAX_DEFAULT       ((0xFFF << 14) | (1 << 8) | (3 << 5) | (3 << 0)) /* Dynamic - NumSharingCache is Mask */
#define FN8000001D_x03_EAX_RESERVED      (0xFC003C00)
#define FN8000001D_x03_EBX_DEFAULT       ((0xF << 22) | (00 << 12) | (0x3F << 0))
#define FN8000001D_x03_EBX_RESERVED      (0x00000000)
#define FN8000001D_x03_ECX_DEFAULT       (0x0000FFFF)   /* Dynamic */
#define FN8000001D_x03_ECX_RESERVED      (0x00000000)
#define FN8000001D_x03_EDX_DEFAULT       ((0 << 1) | (1 << 0))
#define FN8000001D_x03_EDX_RESERVED      (0xFFFFFFFC)


/* FN8000001D_x04 definitions */
#define FN8000001D_x04_EAX_DEFAULT       (0x00000000)
#define FN8000001D_x04_EAX_RESERVED      (0xFFFFFFF0)
#define FN8000001D_x04_EBX_DEFAULT       (0x00000000)
#define FN8000001D_x04_EBX_RESERVED      (0xFFFFFFFF)
#define FN8000001D_x04_ECX_DEFAULT       (0x00000000)
#define FN8000001D_x04_ECX_RESERVED      (0x00000000)
#define FN8000001D_x04_EDX_DEFAULT       (0x00000000)
#define FN8000001D_x04_EDX_RESERVED      (0xFFFFFFFF)


/* FN8000001E definitions */
#define FN8000001E_EAX_DEFAULT           (0xFFFFFFFF)   /* Dynamic - Mask */
#define FN8000001E_EAX_RESERVED          (0x00000000)
#define FN8000001E_EBX_DEFAULT           (0x0000FFFF)   /* Dynamic - Mask */
#define FN8000001E_EBX_RESERVED          (0xFFFF0000)
#define FN8000001E_ECX_DEFAULT           (0x000000FF)   /* Dynamic - Mask */
#define FN8000001E_ECX_RESERVED          (0xFFFFF800)
/* FN8000001E_EDX does not exist */


/* FN8000001F definitions */
/* FN8000001F_EAX definitions */
#define FN8000001F_EAX_SMT_PROT          (1 << 25)
#define FN8000001F_EAX_VMSAREGPROT       (1 << 24)
#define FN8000001F_EAX_IBSVIRT           (1 << 19)
#define FN8000001F_EAX_VIRTTOMMSR        (1 << 18)
#define FN8000001F_EAX_VMGEXITPARAM      (1 << 17)
#define FN8000001F_EAX_VTE               (1 << 16)
#define FN8000001F_EAX_PREVENTHOSTIBS    (1 << 15)
#define FN8000001F_EAX_DEBUGSTATESWAP    (1 << 14)
#define FN8000001F_EAX_ALTERNATEINJ      (1 << 13)
#define FN8000001F_EAX_RESTRICTINJ       (1 << 12)
#define FN8000001F_EAX_REG64BITHYPERVSR  (1 << 11)
#define FN8000001F_EAX_COHERENCYENFORCED (1 << 10)
#define FN8000001F_EAX_TSCAUXVIRT        (1 << 9)
#define FN8000001F_EAX_SECURETSC         (1 << 8)
#define FN8000001F_EAX_VMPLSSS           (1 << 7)
#define FN8000001F_EAX_RMPQUERY          (1 << 6)
#define FN8000001F_EAX_VMPL              (1 << 5)
#define FN8000001F_EAX_SNP               (1 << 4)
#define FN8000001F_EAX_SEVES             (1 << 3)
#define FN8000001F_EAX_VMPGFLUSH         (1 << 2)
#define FN8000001F_EAX_SEV               (1 << 1)
#define FN8000001F_EAX_SME               (1 << 0)
#define FN8000001F_EAX_RESERVED          (0xFCF00000)

#define FN8000001F_EAX_DEFAULT           (FN8000001F_EAX_SMT_PROT          | \
                                          FN8000001F_EAX_VMSAREGPROT       | \
                                          FN8000001F_EAX_IBSVIRT           | \
                                          FN8000001F_EAX_VIRTTOMMSR        | \
                                          FN8000001F_EAX_VMGEXITPARAM      | \
                                          FN8000001F_EAX_VTE               | \
                                          FN8000001F_EAX_PREVENTHOSTIBS    | \
                                          FN8000001F_EAX_DEBUGSTATESWAP    | \
                                          FN8000001F_EAX_ALTERNATEINJ      | \
                                          FN8000001F_EAX_RESTRICTINJ       | \
                                          FN8000001F_EAX_REG64BITHYPERVSR  | \
                                          FN8000001F_EAX_COHERENCYENFORCED | \
                                          FN8000001F_EAX_TSCAUXVIRT        | \
                                          FN8000001F_EAX_SECURETSC         | \
                                          FN8000001F_EAX_VMPLSSS           | \
                                          FN8000001F_EAX_RMPQUERY          | \
                                          FN8000001F_EAX_VMPL              | \
                                          FN8000001F_EAX_SNP               | \
                                          FN8000001F_EAX_SEVES             | \
                                          FN8000001F_EAX_VMPGFLUSH         | \
                                          FN8000001F_EAX_SEV               | \
                                          FN8000001F_EAX_SME)

/* FN8000001F_EBX defines - VMPL = 4, MemWidth = 4 CBIT = 33h EXACT mode */
#define FN8000001F_EBX_DEFAULT           (0x33 << 0)    /* Dynamic - All bits */
/* Bits[11:6] are unchecked */
#define FN8000001F_EBX_UNCHECKED_SHIFT   (6)
#define FN8000001F_EBX_UNCHECKED_MASK    (0x3F << FN8000001F_EBX_UNCHECKED_SHIFT)
#define FN8000001F_EBX_VMPL_SUP_SHIFT    (12)
#define FN8000001F_EBX_VMPL_SUP_MASK     (0xF << FN8000001F_EBX_VMPL_SUP_SHIFT)
#define FN8000001F_EBX_VMPL_SUP_MAX      (4)            /* Dynamic - Less Than */
#define FN8000001F_EBX_RESERVED          (0xFFFF0000)

#define FN8000001F_ECX_DEFAULT           (0xFFFFFFFF)   /* Dynamic - Mask */
#define FN8000001F_ECX_RESERVED          (0x00000000)
#define FN8000001F_EDX_DEFAULT           (0xFFFFFFFF)   /* Dynamic - Mask */
#define FN8000001F_EDX_RESERVED          (0x00000000)


/* FN80000020_x00 Defines */
#define FN80000020_x00_EAX_DEFAULT       (0x00000000)   /* Dynamic */
#define FN80000020_x00_EAX_RESERVED      (0xFFFFFFFF)
#define FN80000020_x00_EBX_DEFAULT       (0x0000001E)   /* Dynamic */
#define FN80000020_x00_EBX_RESERVED      (0xFFFFFFE1)
#define FN80000020_x00_ECX_DEFAULT       (0x00000000)   /* Dynamic */
#define FN80000020_x00_ECX_RESERVED      (0xFFFFFFFF)
#define FN80000020_x00_EDX_DEFAULT       (0x00000000)   /* Dynamic */
#define FN80000020_x00_EDX_RESERVED      (0xFFFFFFFF)


/* FN80000020_x01 Defines */
#define FN80000020_x01_EAX_DEFAULT       (0x0000000B)   /* Dynamic */
#define FN80000020_x01_EAX_RESERVED      (0x00000000)
#define FN80000020_x01_EBX_DEFAULT       (0x00000000)   /* Dynamic */
#define FN80000020_x01_EBX_RESERVED      (0xFFFFFFFF)
#define FN80000020_x01_ECX_DEFAULT       (0x00000000)   /* Dynamic */
#define FN80000020_x01_ECX_RESERVED      (0xFFFFFFFF)
#define FN80000020_x01_EDX_DEFAULT       (0x0000000F)   /* Dynamic */
#define FN80000020_x01_EDX_RESERVED      (0x00000000)

/* FN80000020_x02 Defines */
#define FN80000020_x02_EAX_DEFAULT       (0x0000000B)   /* Unchecked Dynamic */
#define FN80000020_x02_EAX_RESERVED      (0x00000000)
#define FN80000020_x02_EBX_DEFAULT       (0x00000000)   /* Strict */
#define FN80000020_x02_EBX_RESERVED      (0xFFFFFFFF)
#define FN80000020_x02_ECX_DEFAULT       (0x00000000)   /* Strict */
#define FN80000020_x02_ECX_RESERVED      (0xFFFFFFFF)
#define FN80000020_x02_EDX_DEFAULT       (0x0000000F)   /* Unchecked Dynamic */
#define FN80000020_x02_EDX_RESERVED      (0x00000000)

/* FN80000020_x03 Defines */
#define FN80000020_x03_EAX_DEFAULT       (0x00000000)   /* Strict reserved  */
#define FN80000020_x03_EAX_RESERVED      (0x00000000)
#define FN80000020_x03_EBX_DEFAULT       (0x00000002)   /* Unchecked */
#define FN80000020_x03_EBX_RESERVED      (0x00000000)
#define FN80000020_x03_ECX_DEFAULT       (0x0000007F)   /* Bitmask */
#define FN80000020_x03_ECX_RESERVED      (~(FN80000020_x03_ECX_DEFAULT))
#define FN80000020_x03_EDX_DEFAULT       (0x00000000)   /* Strict */
#define FN80000020_x03_EDX_RESERVED      (0x00000000)

/* FN80000021 Defines */
/* FN80000021_EAX definitions */
#define FN80000021_EAX_IBPB_BRTYPE      (1 << 28)
#define FN80000021_EAX_SBPB             (1 << 27)
#define FN80000021_EAX_EPSF             (1 << 18)   /* Dynamic */
#define FN80000021_EAX_GPONUSERCPUID    (1 << 17)   /* Dynamic */
#define FN80000021_EAX_PREFETCHCTL      (1 << 13)   /* Dynamic */
#define FN80000021_EAX_FSRC             (1 << 11)
#define FN80000021_EAX_FSRS             (1 << 10)
#define FN80000021_EAX_NOSMMCTLMSR      (1 << 9)
#define FN80000021_EAX_AUTOIBRS         (1 << 8)
#define FN80000021_EAX_UPADDRIGNORE     (1 << 7)
#define FN80000021_EAX_NULLSELCLRBASE   (1 << 6)    /* Dynamic */
#define FN80000021_EAX_TXSCTL           (0 << 4)
#define FN80000021_EAX_SMMPGCFGLOCK     (1 << 3)
#define FN80000021_EAX_LFENCE           (1 << 2)
#define FN80000021_EAX_KERNELBASENONSRL (1 << 1)
#define FN80000021_EAX_NONSTDDATABP     (1 << 0)
#define FN80000021_EAX_RESERVED         (0xE7F9D020)

#define FN80000021_EAX_DEFAULT           (FN80000021_EAX_IBPB_BRTYPE      | \
                                          FN80000021_EAX_SBPB              | \
                                          FN80000021_EAX_EPSF             | \
                                          FN80000021_EAX_GPONUSERCPUID    | \
                                          FN80000021_EAX_PREFETCHCTL      | \
                                          FN80000021_EAX_FSRC             | \
                                          FN80000021_EAX_FSRS             | \
                                          FN80000021_EAX_NOSMMCTLMSR      | \
                                          FN80000021_EAX_AUTOIBRS         | \
                                          FN80000021_EAX_UPADDRIGNORE     | \
                                          FN80000021_EAX_NULLSELCLRBASE   | \
                                          FN80000021_EAX_TXSCTL           | \
                                          FN80000021_EAX_SMMPGCFGLOCK     | \
                                          FN80000021_EAX_LFENCE           | \
                                          FN80000021_EAX_KERNELBASENONSRL | \
                                          FN80000021_EAX_NONSTDDATABP)

#define FN80000021_EBX_DEFAULT       (0x00000000)   /* Dynamic */
#define FN80000021_EBX_RESERVED      (0xFFFFF000)
/* FN80000021 ECX, EDX do not exist! */

/* FN80000022 Defines */
#define FN80000022_EAX_DEFAULT       (0x00000007UL)                 /* Mask */
#define FN80000022_EAX_RESERVED      (~(FN80000022_EAX_DEFAULT))

/* FN80000022 EBX defines */
#define FN80000022_EBX_NUM_PERF_CORE_SHIFT (0)
#define FN80000022_EBX_NUM_PERF_CORE_MASK  (0xFUL << FN80000022_EBX_NUM_PERF_CORE_SHIFT)
#define FN80000022_EBX_LIBRV2STACKSZ_SHIFT (4)
#define FN80000022_EBX_LIBRV2STACKSZ_MASK  (0x3FUL << FN80000022_EBX_LIBRV2STACKSZ_SHIFT)

#define FN80000022_EBX_NUM_PERF_CORE_VALUE (0x06)
#define FN80000022_EBX_LIBRV2STACKSZ_VALUE (0x10)

#define FN80000022_EBX_DEFAULT       (0x00000000)                 /* CUSTOM */
#define FN80000022_EBX_RESERVED      (0x00000000)

#define FN80000022_ECX_DEFAULT       (0x00000000)                 /* Dynamic */
#define FN80000022_ECX_RESERVED      (0x00000000)
#define FN80000022_EDX_DEFAULT       (0x00000000)                 /* Strict */
#define FN80000022_EDX_RESERVED      (0x00000000)

/* FN80000023 Defines */
#define FN80000023_EAX_DEFAULT       (0x00000001)                 /* Mask */
#define FN80000023_EAX_RESERVED      ~(FN80000023_EAX_DEFAULT)
#define FN80000023_EBX_DEFAULT       (0x00000063)                 /* Unchecked */
#define FN80000023_EBX_RESERVED      (0x00000000)
#define FN80000023_ECX_DEFAULT       (0x00000000)                 /* strict no fields */
#define FN80000023_ECX_RESERVED      (0xffffffff)
#define FN80000023_EDX_DEFAULT       (0x00000000)                 /* strict no fields */
#define FN80000023_EDX_RESERVED      (0xffffffff)

/* FN80000024 x00 Defines - FEATURE_INFO */
#define FN80000024_x00_EAX_DEFAULT       (SEV_FEATURE_INFO_x00_EAX)     /* Less than */
#define FN80000024_x00_EBX_DEFAULT       (SEV_FEATURE_INFO_x00_EBX)     /* Mask */
#define FN80000024_x00_ECX_DEFAULT       (SEV_FEATURE_INFO_x00_ECX)     /* Mask */
#define FN80000024_x00_EDX_DEFAULT       (SEV_FEATURE_INFO_x00_EDX)     /* Strict */

#define FN80000024_x00_EAX_RESERVED       (0x00000000)                  /* Less than */
#define FN80000024_x00_EBX_RESERVED      ~(FN80000024_x00_EBX_DEFAULT)  /* Mask */
#define FN80000024_x00_ECX_RESERVED      ~(FN80000024_x00_ECX_DEFAULT)  /* Mask */
#define FN80000024_x00_EDX_RESERVED      ~(FN80000024_x00_EDX_DEFAULT)  /* Strict */

/* FN80000024 x01 Defines  FEATURE_INFO */
#define FN80000024_x01_EAX_DEFAULT       (SEV_FEATURE_INFO_x01_EAX)     /* Mask */
#define FN80000024_x01_EBX_DEFAULT       (SEV_FEATURE_INFO_x01_EBX)     /* Strict */
#define FN80000024_x01_ECX_DEFAULT       (SEV_FEATURE_INFO_x01_ECX)     /* Strict */
#define FN80000024_x01_EDX_DEFAULT       (SEV_FEATURE_INFO_x01_EDX)     /* Strict */

#define FN80000024_x01_EAX_RESERVED      ~(FN80000024_x01_EAX_DEFAULT)  /* Mask */
#define FN80000024_x01_EBX_RESERVED      ~(FN80000024_x01_EBX_DEFAULT)  /* Strict */
#define FN80000024_x01_ECX_RESERVED      ~(FN80000024_x01_ECX_DEFAULT)  /* Strict */
#define FN80000024_x01_EDX_RESERVED      ~(FN80000024_x01_EDX_DEFAULT)  /* Strict */


/* FN00000026 x00 x01 x02 are all dynamic and unchecked! */
#define FN80000026_DEFAULT       (0x00000000)
#define FN80000026_RESERVED      (0x00000000)

/**
 * Read CPUID_Fn00000001_EAX [Family, Model, Stepping Identifiers] (Core::X86::Cpuid::FamModStep)
 *
 *  Parameters:
 *     value : [out] CPUID value of FMS register
 */
sev_status_t get_fms(uint32_t *value);

/**
 * Validate a CPUID entry. Mark EAX_IN, ECX_IN, XCR0_IN, if the entry is not available
 *   Overwrite the expected EAX/EBX/ECX/EDX value (sanitize it) if it's not valid.
 *   Inout/Output:  eax_in, ecx_in, xcr0_in, eax_out, ebx_out, edx_out
 *
 * Returns SEV_STATUS_SUCCESS or error code
 */
sev_status_t sanitize_cpuid_entry(uint32_t *eax_in, uint32_t *ecx_in, uint64_t *xcr0_in,
                                  uint64_t *xss_in, uint32_t *eax_out, uint32_t *ebx_out,
                                  uint32_t *ecx_out, uint32_t *edx_out);

/**
 * Takes in the CPUID list and calls sanitize_cpuid_entry on each entry;
 * Assumes req_count has already been validated.
 * rsp_count is needed for GuestRequest but not LaunchUpdate.
 */
sev_status_t sanitize_cpuid_list(snp_cpuid_function_t *cpuid_function,
                                 uint32_t req_count, uint32_t *rsp_count);

#endif /* CPUID_LOOKUP_H */
