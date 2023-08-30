// Copyright(C) 2020 Advanced Micro Devices, Inc. All rights reserved.

#include <stdint.h>

#include "sev_mcmd.h"
#include "cpuid_lookup.h"
#include "psp_reg_hw_gen.h"
#include "sev_hal.h"

sev_status_t get_fms(uint32_t *value)
{
    return sev_hal_read_reg(mmCPUID_FAMILY_MODEL_STEPPING, ~(0), value);
}

/**
 * Compares two CPUID_Fn000001_EAX inputs, assuring the the Family, Model, and
 * Stepping of eax_b are less than or equal the values of eax_a
 */
static bool compare_FMS(uint32_t eax_a, uint32_t eax_b)
{
    uint32_t family_a = 0, model_a = 0, stepping_a = 0;
    uint32_t family_b = 0, model_b = 0, stepping_b = 0;

    family_a = FMS_FAMILY(eax_a);
    model_a = FMS_MODEL(eax_a);
    stepping_a = FMS_STEPPING(eax_a);

    family_b = FMS_FAMILY(eax_b);
    model_b = FMS_MODEL(eax_b);
    stepping_b = FMS_STEPPING(eax_b);

    return ((family_b < family_a) ||
            (family_b == family_a && model_b < model_a) ||
            (family_b == family_a && model_b == model_a && stepping_b <= stepping_a));
}

/**
 * FN00000001  from PPR
 *
 * CPUID_Fn000001_EAX - LessThan Rule
 *
 * CPUID_Fn000001_EBX - CLFlush - strict, Others Unchecked
 *
 * CPUID_Fn000001_ECX - OSXSave Unchecked, rest Bitmask (included in the mask)
 *
 * CPUID_Fn000001_EDX - Bitmask
 */
static sev_status_t FN00000001_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                      uint64_t xcr0_in, uint64_t xss_in,
                                      uint32_t *eax_out, uint32_t *ebx_out,
                                      uint32_t *ecx_out, uint32_t *edx_out)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t clflush = 0;
    uint32_t ecx_check = 0;
    bool failed = false;
    uint32_t actual_fms = 0;

    if (eax_in != 0x00000001 || ecx_in != 0)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN00000001_EAX - LessThan */
    status = get_fms(&actual_fms);
    if (status != SEV_STATUS_SUCCESS)
    {
        actual_fms = 0;
        failed = true;
    }
    if (!compare_FMS(actual_fms, *eax_out))
    {
        failed = true;
        *eax_out = actual_fms;
    }

    /* FN00000001_EAX_RESERVED - Zeros mask */
    if ((~(*eax_out) & FN00000001_EAX_RESERVED) != FN00000001_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN00000001_EAX_RESERVED);
    }

    /* FN00000001_EBX - CLFlush strict, rest unchecked */
    clflush = (*ebx_out & FN00000001_EBX_CFLUSH_MASK) >> FN00000001_EBX_CFLUSH_SHIFT;
    if (clflush != FN00000001_EBX_CFLUSH_EXACT)
    {
        clflush = FN00000001_EBX_CFLUSH_EXACT;
        clflush <<= FN00000001_EBX_CFLUSH_SHIFT;
        *ebx_out &= ~(FN00000001_EBX_CFLUSH_MASK);
        *ebx_out |= clflush;
        failed = true;
    }

    /* FN00000001_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN00000001_EBX_RESERVED) != FN00000001_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN00000001_EBX_RESERVED);
    }

    /* FN00000001ECX - OSXSAVE and RESHV Unchecked, rest Bitmask */
    ecx_check = (*ecx_out & ~FN00000001_ECX_OSXSAVE) & ~FN00000001_ECX_RESHV;
    if ((ecx_check & FN00000001_ECX_DEFAULT) != ecx_check)
    {
        failed = true;
        *ecx_out = *ecx_out & (FN00000001_ECX_DEFAULT | FN00000001_ECX_OSXSAVE | FN00000001_ECX_RESHV);
    }

    /* FN00000001_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN00000001_ECX_RESERVED) != FN00000001_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN00000001_ECX_RESERVED);
    }

    /* FN00000001_EDX - Bitmask */
    if ((*edx_out & FN00000001_EDX_DEFAULT) != *edx_out)
    {
        failed = true;
        *edx_out = *edx_out & FN00000001_EDX_DEFAULT;
    }

    /* FN00000001_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN00000001_EDX_RESERVED) != FN00000001_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN00000001_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * FN00000007  from PPR
 *
 * CPUID_Fn000007_EAX - LessThan
 *
 * CPUID_Fn000007_EBX - Bitmask
 *
 * CPUID_Fn000001_ECX - OSPKE unchecked, Others Bitmask (included in the mask)
 *
 * CPUID_Fn000001_EDX - Bitmask
 */
static sev_status_t FN00000007_x00_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                          uint64_t xcr0_in, uint64_t xss_in,
                                          uint32_t *eax_out, uint32_t *ebx_out,
                                          uint32_t *ecx_out, uint32_t *edx_out)
{
    uint32_t ecx_check = 0;
    bool failed = false;

    if (eax_in != 0x00000007 || ecx_in != 0)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN00000007_x00_EAX - LessThan */
    if (*eax_out > FN00000007_x00_EAX_DEFAULT)
    {
        failed = true;
        *eax_out = FN00000007_x00_EAX_DEFAULT;
    }

    /* FN00000007_EAX_RESERVED - Zeros mask */
    if ((~(*eax_out) & FN00000007_x00_EAX_RESERVED) != FN00000007_x00_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN00000007_x00_EAX_RESERVED);
    }

    /* FN00000007_x00_EBX - Bitmask*/
    if ((*ebx_out & FN00000007_x00_EBX_DEFAULT) != *ebx_out)
    {
        *ebx_out = *ebx_out & FN00000007_x00_EBX_DEFAULT;
        failed = true;
    }

    /* FN00000007_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN00000007_x00_EBX_RESERVED) != FN00000007_x00_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN00000007_x00_EBX_RESERVED);
    }

    /* FN00000007_x00_ECX - OSPKE Unchecked, rest Bitmask */
    ecx_check = *ecx_out & ~FN00000007_x00_ECX_OSPKE;
    if ((ecx_check & FN00000007_x00_ECX_DEFAULT) != ecx_check)
    {
        failed = true;
        *ecx_out = *ecx_out & (FN00000007_x00_ECX_DEFAULT | FN00000007_x00_ECX_OSPKE);
    }

    /* FN00000007_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN00000007_x00_ECX_RESERVED) != FN00000007_x00_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN00000007_x00_ECX_RESERVED);
    }

    /* FN00000007_x00_EDX - Bitmask */
    if ((*edx_out & FN00000007_x00_EDX_DEFAULT) != *edx_out)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN00000007_x00_EDX_DEFAULT);
    }

    /* FN00000007_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN00000007_x00_EDX_RESERVED) != FN00000007_x00_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN00000007_x00_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * FN0000000D - from PPR
 *
 * CPUID_Fn0000000D_EAX_x00 - [0:1] Strict. Bitmask for rest
 *
 * CPUID_Fn0000000D_EBX_x00 - CUSTOM Rules:
 * IF (XCR0[MPK] == 1)
 *      return EBX=0000_0360h // Legacy header + X87/SSE + AVX + MPK size;
 * ELSIF (XCR0[AVX]==1)
 *      return EBX=0000_0340h // legacy header + X87/SSE + AVX size
 * ELSE
 *      return EBX=0000_0240h // legacy header + X87/SSE size
 * END.
 *
 * CPUID_Fn0000000D_ECX_x00 - Unchecked
 * CPUID_Fn0000000D_EDX_x00 - Strict
 */
static sev_status_t FN0000000D_X00_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                          uint64_t xcr0_in, uint64_t xss_in,
                                          uint32_t *eax_out, uint32_t *ebx_out,
                                          uint32_t *ecx_out, uint32_t *edx_out)
{
    bool failed = false;
    uint32_t expected_ebx = 0;

    if (eax_in != 0x0000000d || ecx_in != 0)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN0000000D_x00_EAX - Both X87 and SSE must be set */
    if ((*eax_out & (FN0000000D_x00_EAX_X87 | FN0000000D_x00_EAX_SSE)) != (FN0000000D_x00_EAX_X87 | FN0000000D_x00_EAX_SSE))
    {
        *eax_out |= (FN0000000D_x00_EAX_X87 | FN0000000D_x00_EAX_SSE);
        failed = true;
    }

    /* FN0000000D_x00_EAX - Other bits are Bitmask */
    if ((*eax_out & FN0000000D_x00_EAX_DEFAULT) != *eax_out)
    {
        *eax_out = *eax_out & FN0000000D_x00_EAX_DEFAULT;
        failed = true;
    }

    /* FN0000000D_x00_EAX_RESERVED - Zeros mask */
    if ((~(*eax_out) & FN0000000D_x00_EAX_RESERVED) != FN0000000D_x00_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN0000000D_x00_EAX_RESERVED);
    }

    /* FN0000000D_x00_EBX */
    if (xcr0_in & XCR0_MPK)
    {
        expected_ebx = 0x988;   /* legacy header + X87/SSE + AVX + MPK size */
    }
    else if (xcr0_in & XCR0_HIZMM)
    {
        expected_ebx = 0x980;
    }
    else if (xcr0_in & XCR0_ZMMHI)
    {
        expected_ebx = 0x580;
    }
    else if (xcr0_in & XCR0_KREGS)
    {
        expected_ebx = 0x380;
    }
    else if (xcr0_in & XCR0_AVX)
    {
        expected_ebx = 0x340;   /* legacy header + X87/SSE + AVX size */
    }
    else
    {
        expected_ebx = 0x240;
    }

    if (expected_ebx != *ebx_out)
    {
        failed = true;
        *ebx_out = expected_ebx;
    }

    /* FN0000000D_x00_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN0000000D_x00_EBX_RESERVED) != FN0000000D_x00_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN0000000D_x00_EBX_RESERVED);
    }

    /* ECX - Unchecked */

    /* FN0000000D_x00_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN0000000D_x00_ECX_RESERVED) != FN0000000D_x00_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN0000000D_x00_ECX_RESERVED);
    }

    /* FN0000000D_x00_EDX - exact */
    if (*edx_out != FN0000000D_x00_EDX_DEFAULT)
    {
        *edx_out = FN0000000D_x00_EDX_DEFAULT;
        failed = true;
    }

    /* FN0000000D_x00_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN0000000D_x00_EDX_RESERVED) != FN0000000D_x00_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN0000000D_x00_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * From PPR:
 * FN0000000D_X01 -
 *     EAX: Bitmask
 *     EBX:
 *          EBX = 0000_0240h
 *              + ((XCR0[AVX]==1) ? 0000_0100h : 0)
 *              + ((XCR0[MPK]==1) ? 0000_0020h : 0)
 *              + ((IA32_XSS[CET_U]==1) ? 0000_0020h : 0)
 *              + ((IA32_XSS[CET_S]==1) ? 0000_0020h : 0).
 *     ECX: Bitmask
 *     EDX: Bitmask
 */
static sev_status_t FN0000000D_X01_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                          uint64_t xcr0_in, uint64_t xss_in,
                                          uint32_t *eax_out, uint32_t *ebx_out,
                                          uint32_t *ecx_out, uint32_t *edx_out)
{
    bool failed = false;
    uint32_t ebx_check = 0;

    if (eax_in != 0x0000000D || ecx_in != 0x1)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN0000000D_x01_EAX - Bitmask */
    if (*eax_out != (*eax_out & FN0000000D_x01_EAX_DEFAULT))
    {
        *eax_out = *eax_out & FN0000000D_x01_EAX_DEFAULT;
        failed = true;
    }

    /* FN0000000D_x01_EAX_RESERVED - Zeros mask */
    if ((~(*eax_out) & FN0000000D_x01_EAX_RESERVED) != FN0000000D_x01_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN0000000D_x01_EAX_RESERVED);
    }

    ebx_check = 0x240;
    /* FN0000000D_x01_EBX - strict */
    if (xcr0_in & XCR0_MPK)
    {
        ebx_check += 0x8;
    }

    if (xcr0_in & XCR0_HIZMM)
    {
        ebx_check += 0x400;
    }

    if (xcr0_in & XCR0_ZMMHI)
    {
        ebx_check += 0x200;
    }

    if (xcr0_in & XCR0_KREGS)
    {
        ebx_check += 0x40;
    }

    if (xcr0_in & XCR0_AVX)
    {
        ebx_check += 0x100;
    }

    if (xss_in & CET_U)
    {
        ebx_check += 0x10;
    }

    if (xss_in & CET_S)
    {
        ebx_check += 0x18;
    }

    /* FN0000000D_x01_EBX - Bitmask */
    if (ebx_check != *ebx_out)
    {
        failed = true;
        *ebx_out = ebx_check;
    }

    /* FN0000000D_x01_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN0000000D_x01_EBX_RESERVED) != FN0000000D_x01_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN0000000D_x01_EBX_RESERVED);
    }

    /* FN0000000D_x01_ECX - Bitmask */
    if (*ecx_out != (*ecx_out & FN0000000D_x01_ECX_DEFAULT))
    {
        *ecx_out = *ecx_out & FN0000000D_x01_ECX_DEFAULT;
        failed = true;
    }

    /* FN0000000D_x01_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN0000000D_x01_ECX_RESERVED) != FN0000000D_x01_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN0000000D_x01_ECX_RESERVED);
    }

    /* FN0000000D_x01_EDX - Bitmask */
    if (*edx_out != (*edx_out & FN0000000D_x01_EDX_DEFAULT))
    {
        failed = true;
        *edx_out = *edx_out & FN0000000D_x01_EDX_DEFAULT;
    }

    /* FN0000000D_x01_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN0000000D_x01_EDX_RESERVED) != FN0000000D_x01_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN0000000D_x01_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * FN80000001  from PPR
 *
 * CPUID_Fn800001_EAX - LessThan Rule
 *
 * CPUID_Fn800001_EBX - Unchecked
 *
 * CPUID_Fn800001_ECX - Bitmask
 *
 * CPUID_Fn800001_EDX - Bitmask
 */
static sev_status_t FN80000001_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                      uint64_t xcr0_in, uint64_t xss_in,
                                      uint32_t *eax_out, uint32_t *ebx_out,
                                      uint32_t *ecx_out, uint32_t *edx_out)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool failed = false;
    uint32_t actual_fms = 0;

    if (eax_in != 0x80000001 || ecx_in != 0)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN80000001_EAX - LessThan. Using FN00000001_EAX values */
    status = get_fms(&actual_fms);
    if (status != SEV_STATUS_SUCCESS)
    {
        actual_fms = 0;
        failed = true;
    }
    if (!compare_FMS(actual_fms, *eax_out))
    {
        failed = true;
        *eax_out = actual_fms;
    }

    /* FN80000001_EAX_RESERVED - Bitmask. Using FN00000001_EAX values */
    if ((~(*eax_out) & FN00000001_EAX_RESERVED) != FN00000001_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN00000001_EAX_RESERVED);
    }

    /* FN80000001_EBX - Unchecked */

    /* FN80000001_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN80000001_EBX_RESERVED) != FN80000001_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN80000001_EBX_RESERVED);
    }

    /* FN80000001_ECX - Bitmask */
    if ((*ecx_out & FN80000001_ECX_DEFAULT) != *ecx_out)
    {
        failed = true;
        *ecx_out = *ecx_out & FN80000001_ECX_DEFAULT;
    }

    /* FN80000001_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN80000001_ECX_RESERVED) != FN80000001_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN80000001_ECX_RESERVED);
    }

    /* FN80000001_EDX - Bitmask */
    if ((*edx_out & FN80000001_EDX_DEFAULT) != *edx_out)
    {
        failed = true;
        *edx_out = *edx_out & FN80000001_EDX_DEFAULT;
    }

    /* FN80000001_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN80000001_EDX_RESERVED) != FN80000001_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN80000001_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * FN80000008  from PPR
 *
 * CPUID_Fn800008_EAX - LessThan Rule (applied separately to each field)
 *
 * CPUID_Fn800008_EBX - Bitmask
 *
 * CPUID_Fn800008_ECX - Unchecked
 *
 * CPUID_Fn800008_EDX - LessThan Rule (applied separately to each field)
 */
static sev_status_t FN80000008_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                      uint64_t xcr0_in, uint64_t xss_in,
                                      uint32_t *eax_out, uint32_t *ebx_out,
                                      uint32_t *ecx_out, uint32_t *edx_out)
{
    bool failed = false;
    uint32_t phys_addr_size = 0, lin_addr_size = 0, guest_phys_addr_size = 0;
    uint32_t invlpgb_count_max = 0, rdpru_max = 0;

    if (eax_in != 0x80000008 || ecx_in != 0)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN80000008_EAX_PADDRSIZE - Less Than */
    phys_addr_size = (*eax_out & FN80000008_EAX_PADDRSIZE_MASK) >> FN80000008_EAX_PADDRSIZE_SHIFT;
    if (phys_addr_size > FN80000008_EAX_PADDRSIZE_EXACT)
    {
        failed = true;
        phys_addr_size = FN80000008_EAX_PADDRSIZE_EXACT;
        phys_addr_size <<= FN80000008_EAX_PADDRSIZE_SHIFT;
        *eax_out &= ~(FN80000008_EAX_PADDRSIZE_MASK);
        *eax_out |= phys_addr_size;
    }

    /* FN80000008_EAX_LADDRSIZE - Less Than */
    lin_addr_size = (*eax_out & FN80000008_EAX_LADDRSIZE_MASK) >> FN80000008_EAX_LADDRSIZE_SHIFT;
    if (lin_addr_size > FN80000008_EAX_LADDRSIZE_EXACT)
    {
        failed = true;
        lin_addr_size = FN80000008_EAX_LADDRSIZE_EXACT;
        lin_addr_size <<= FN80000008_EAX_LADDRSIZE_SHIFT;
        *eax_out &= ~(FN80000008_EAX_LADDRSIZE_MASK);
        *eax_out |= lin_addr_size;
    }

    /* FN80000008_EAX_GPADDRSIZE - Less Than */
    guest_phys_addr_size = (*eax_out & FN80000008_EAX_GPADDRSIZE_MASK) >> FN80000008_EAX_GPADDRSIZE_SHIFT;
    if (guest_phys_addr_size > FN80000008_EAX_GPADDRSIZE_EXACT)
    {
        failed = true;
        guest_phys_addr_size = FN80000008_EAX_GPADDRSIZE_EXACT;
        guest_phys_addr_size <<= FN80000008_EAX_GPADDRSIZE_SHIFT;
        *eax_out &= ~(FN80000008_EAX_GPADDRSIZE_MASK);
        *eax_out |= guest_phys_addr_size;
    }

    /* FN80000008_EAX_RESERVED - Zeros mask */
    if ((~(*eax_out) & FN80000008_EAX_RESERVED) != FN80000008_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN80000008_EAX_RESERVED);
    }

    /* FN80000008_EBX - Bitmask */
    if ((*ebx_out & FN80000008_EBX_DEFAULT) != *ebx_out)
    {
        failed = true;
        *ebx_out = *ebx_out & FN80000008_EBX_DEFAULT;
    }

    /* FN80000008_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN80000008_EBX_RESERVED) != FN80000008_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN80000008_EBX_RESERVED);
    }

    /* FN80000008_ECX - unchecked */

    /* FN80000008_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN80000008_ECX_RESERVED) != FN80000008_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN80000008_ECX_RESERVED);
    }

    /* FN80000008_EDX_INVLPGBMAX - Less Than */
    invlpgb_count_max = (*edx_out & FN80000008_EDX_INVLPGBMAX_MASK) >> FN80000008_EDX_INVLPGBMAX_SHIFT;
    if (invlpgb_count_max > FN80000008_EDX_INVLPGBMAX_EXACT)
    {
        failed = true;
        invlpgb_count_max = FN80000008_EDX_INVLPGBMAX_EXACT;
        invlpgb_count_max <<= FN80000008_EDX_INVLPGBMAX_SHIFT;
        *edx_out &= ~(FN80000008_EDX_INVLPGBMAX_MASK);
        *edx_out |= invlpgb_count_max;
    }

    /* FN80000008_EDX_RDPRUMAX - Less Than */
    rdpru_max = (*edx_out & FN80000008_EDX_RDPRUMAX_MASK) >> FN80000008_EDX_RDPRUMAX_SHIFT;
    if (rdpru_max > FN80000008_EDX_RDPRUMAX_EXACT)
    {
        failed = true;
        rdpru_max = FN80000008_EDX_RDPRUMAX_EXACT;
        rdpru_max <<= FN80000008_EDX_RDPRUMAX_SHIFT;
        *edx_out &= ~(FN80000008_EDX_RDPRUMAX_MASK);
        *edx_out |= rdpru_max;
    }

    /* FN80000008_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN80000008_EDX_RESERVED) != FN80000008_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN80000008_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * From PPR:
 * FN8000001F -
 *  EAX = Bitmask
 *  EBX: Bits[11:6]Unchecked, others strict
 *
 *  ECX: Unchecked
 *  EDX: Unchecked
 */
static sev_status_t FN8000001F_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                      uint64_t xcr0_in, uint64_t xss_in,
                                      uint32_t *eax_out, uint32_t *ebx_out,
                                      uint32_t *ecx_out, uint32_t *edx_out)
{
    bool failed = false;
    uint32_t ebx_check = 0;
    uint32_t ebx_vmpl_sup = 0;

    if (eax_in != 0x8000001F || ecx_in != 0x0)
    {
        return ERR_INVALID_PARAMS;
    }

    /* FN8000001F_EAX - Bitmask */
    if ((*eax_out & FN8000001F_EAX_DEFAULT) != *eax_out)
    {
        *eax_out = *eax_out & FN8000001F_EAX_DEFAULT;
        failed = true;
    }

    /* FN8000001F_EAX_RESERVED - Zeros mask */
    if ((~(*eax_out) & FN8000001F_EAX_RESERVED) != FN8000001F_EAX_RESERVED)
    {
        failed = true;
        *eax_out = *eax_out & ~(FN8000001F_EAX_RESERVED);
    }

    /* FN8000001F_EBX exact, ignore the unchecked part [11:6] */
    ebx_check = (*ebx_out & ~FN8000001F_EBX_UNCHECKED_MASK) & ~FN8000001F_EBX_VMPL_SUP_MASK;
    if (ebx_check != FN8000001F_EBX_DEFAULT)
    {
        /* Clear and OR the strict part */
        *ebx_out &= ~FN8000001F_EBX_UNCHECKED_MASK;
        *ebx_out |= FN8000001F_EBX_DEFAULT;
        failed = true;
    }

    /* FN8000001F_EBX_VMPL_SUP - less than */
    ebx_vmpl_sup = (*ebx_out & FN8000001F_EBX_VMPL_SUP_MASK) >> FN8000001F_EBX_VMPL_SUP_SHIFT;
    if ((ebx_vmpl_sup > FN8000001F_EBX_VMPL_SUP_MAX))
    {
        /* Clear and OR the less than part */
        *ebx_out &= ~FN8000001F_EBX_VMPL_SUP_MASK;
        *ebx_out |= (FN8000001F_EBX_VMPL_SUP_MAX << FN8000001F_EBX_VMPL_SUP_SHIFT);
        failed = true;
    }

    /* FN8000001F_EBX_RESERVED - Zeros mask */
    if ((~(*ebx_out) & FN8000001F_EBX_RESERVED) != FN8000001F_EBX_RESERVED)
    {
        failed = true;
        *ebx_out = *ebx_out & ~(FN8000001F_EBX_RESERVED);
    }

    /* FN8000001F_ECX - unchecked */

    /* FN8000001F_ECX_RESERVED - Zeros mask */
    if ((~(*ecx_out) & FN8000001F_ECX_RESERVED) != FN8000001F_ECX_RESERVED)
    {
        failed = true;
        *ecx_out = *ecx_out & ~(FN8000001F_ECX_RESERVED);
    }

    /* FN8000001F_EDX - unchecked */

    /* FN8000001F_EDX_RESERVED - Zeros mask */
    if ((~(*edx_out) & FN8000001F_EDX_RESERVED) != FN8000001F_EDX_RESERVED)
    {
        failed = true;
        *edx_out = *edx_out & ~(FN8000001F_EDX_RESERVED);
    }

    if (failed)
        return SEV_STATUS_INVALID_PARAM;
    else
        return SEV_STATUS_SUCCESS;
}

/**
 * FN00000001  from PPR
 *
 * CPUID_Fn000001_EAX - LessThan Rule
 *
 * CPUID_Fn000001_EBX - CLFlush - strict, Others Unchecked
 *
 * CPUID_Fn000001_ECX - OSXSave Unchecked, rest Bitmask (included in the mask)
 *
 * CPUID_Fn000001_EDX - Bitmask
 */
static sev_status_t FN80000022_CUSTOM(uint32_t eax_in, uint32_t ecx_in,
                                             uint64_t xcr0_in, uint64_t xss_in,
                                             uint32_t *eax_out, uint32_t *ebx_out,
                                             uint32_t *ecx_out, uint32_t *edx_out)
{
    bool failed = false;
    uint32_t num_per_ctr_cores = 0;
    uint32_t libv2stacksz = 0;

    if (eax_in != 0x80000022 || ecx_in != 0)
    {
      return ERR_INVALID_PARAMS;
    }

    /* FN80000022 EAX is bitmask */
    if ((*eax_out & FN80000022_EAX_DEFAULT) != *eax_out)
    {
        failed = true;
        *eax_out = *eax_out & FN80000022_EAX_DEFAULT;
    }

    /* FN80000022_EAX_RESERVED */
    if ((~(*eax_out) & FN80000022_EAX_RESERVED) != FN80000022_EAX_RESERVED)
    {
      failed = true;
      *eax_out = *eax_out & ~(FN80000022_EAX_RESERVED);
    }

    /**
     * These two must be less than or equal to the size in the PPR.
     *  6 for NumPerfCtrCore value
     *  0x10 for LIBRV2STACKSIZE
     *  The rest of the field is unchecked
     */
    num_per_ctr_cores = (*ebx_out & FN80000022_EBX_NUM_PERF_CORE_MASK) >> FN80000022_EBX_NUM_PERF_CORE_SHIFT;
    libv2stacksz = (*ebx_out & FN80000022_EBX_LIBRV2STACKSZ_MASK) >> FN80000022_EBX_LIBRV2STACKSZ_SHIFT;
    if (num_per_ctr_cores > FN80000022_EBX_NUM_PERF_CORE_VALUE)
    {
        failed = true;
        *ebx_out &= ~FN80000022_EBX_NUM_PERF_CORE_MASK;
        *ebx_out |= (FN80000022_EBX_NUM_PERF_CORE_VALUE << FN80000022_EBX_NUM_PERF_CORE_SHIFT);
    }

    if (libv2stacksz > FN80000022_EBX_LIBRV2STACKSZ_VALUE)
    {
        failed = true;
        *ebx_out &= ~FN80000022_EBX_LIBRV2STACKSZ_MASK;
        *ebx_out |= (FN80000022_EBX_LIBRV2STACKSZ_VALUE << FN80000022_EBX_LIBRV2STACKSZ_SHIFT);
    }

    /* ECX is unchecked! */

    /* EDX is strict */
    if (*edx_out != FN80000022_EDX_DEFAULT)
    {
        failed = true;
        *edx_out = FN80000022_EDX_DEFAULT;
    }

    if (failed)
      return SEV_STATUS_INVALID_PARAM;
    else
      return SEV_STATUS_SUCCESS;
}

/* Order listed is based on PPR documentation */
static cpuid_lookup lookup_table[] =
{
    /* Functional Register CPUID_Fn00000000 */
    {
        /* EAX */            0x00000000,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN00000000_EAX_DEFAULT,
        /* EBX_OUT */        FN00000000_EBX_DEFAULT,
        /* ECX_OUT */        FN00000000_ECX_DEFAULT,
        /* EDX_OUT */        FN00000000_EDX_DEFAULT,
        /* EAX_RESERVED */   FN00000000_EAX_RESERVED,
        /* EBX_RESERVED */   FN00000000_EBX_RESERVED,
        /* ECX_RESERVED */   FN00000000_ECX_RESERVED,
        /* EDX_RESERVED */   FN00000000_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_LESSTHAN,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn00000001 */
    {
        /* EAX */            0x00000001,
        /* ECX */            0x00000000,
        /* CUSTOM */         FN00000001_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn00000002 */
    {
        /* EAX */            0x00000002,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EBX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EBX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* ECX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn00000004 */
    {
        /* EAX */            0x00000004,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EBX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EBX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* ECX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn00000005 */
    {
        /* EAX */            0x00000005,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN00000005_EAX_DEFAULT,
        /* EBX_OUT */        FN00000005_EBX_DEFAULT,
        /* ECX_OUT */        FN00000005_ECX_DEFAULT,
        /* EDX_OUT */        FN00000005_EDX_DEFAULT,
        /* EAX_RESERVED */   FN00000005_EAX_RESERVED,
        /* EBX_RESERVED */   FN00000005_EBX_RESERVED,
        /* ECX_RESERVED */   FN00000005_ECX_RESERVED,
        /* EDX_RESERVED */   FN00000005_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn00000006 */
    {
        /* EAX */            0x00000006,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN00000006_EAX_DEFAULT,
        /* EBX_OUT */        FN00000006_EBX_DEFAULT,
        /* ECX_OUT */        FN00000006_ECX_DEFAULT,
        /* EDX_OUT */        FN00000006_EDX_DEFAULT,
        /* EAX_RESERVED */   FN00000006_EAX_RESERVED,
        /* EBX_RESERVED */   FN00000006_EBX_RESERVED,
        /* ECX_RESERVED */   FN00000006_ECX_RESERVED,
        /* EDX_RESERVED */   FN00000006_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_MASK,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_MASK,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn00000007_x00 */
    {
        /* EAX */            0x00000007,
        /* ECX */            0x00000000,   /* x00 */
        /* CUSTOM */         FN00000007_x00_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn00000007_x01 */
    {
        /* EAX */            0x00000007,
        /* ECX */            0x00000001,   /* x01 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN00000007_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN00000007_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN00000007_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN00000007_x01_EDX_DEFAULT,
        /* EAX_RESERVED */   FN00000007_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN00000007_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN00000007_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN00000007_x01_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_MASK,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000B_x00 */
    {
        /* EAX */            0x0000000B,
        /* ECX */            0x00000000,   /* x00 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000B_x00_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000B_x00_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000B_x00_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000B_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000B_x00_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000B_x00_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000B_x00_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000B_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn0000000B_x01 */
    {
        /* EAX */            0x0000000B,
        /* ECX */            0x00000001,   /* x01 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000B_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000B_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000B_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000B_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000B_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000B_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000B_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000B_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn0000000B_x02 */
    {
        /* EAX */            0x0000000B,
        /* ECX */            0x00000002,   /* x02 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000B_x02_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000B_x02_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000B_x02_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000B_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000B_x02_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000B_x02_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000B_x02_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000B_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x00 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000000,   /* x00 */
        /* XCR0 */           FN0000000D_X00_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */ /* x01 */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x01 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000001,   /* x01 */
        /* CUSTOM */         FN0000000D_X01_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x02 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000002,   /* x02 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x02_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x02_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x02_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x02_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x02_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x02_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x02_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x02_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x05 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000005,   /* x05 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x05_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x05_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x05_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x05_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x05_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x05_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x05_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x05_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_MASK,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x06 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000006,   /* x06 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x06_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x06_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x06_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x06_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x06_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x06_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x06_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x06_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_MASK,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x06 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000007,   /* x07 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x07_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x07_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x07_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x07_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x07_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x07_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x07_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x07_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_MASK,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x09 */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x00000009,   /* x09 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x09_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x09_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x09_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x09_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x09_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x09_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x09_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x09_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x0B */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x0000000B,   /* x0B */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x0B_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x0B_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x0B_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x0B_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x0B_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x0B_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x0B_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x0B_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000D_x0C */
    {
        /* EAX */            0x0000000D,
        /* ECX */            0x0000000C,   /* x0C */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000D_x0C_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000D_x0C_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000D_x0C_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000D_x0C_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000D_x0C_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000D_x0C_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000D_x0C_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000D_x0C_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn0000000F_x00 */
    {
        /* EAX */            0x0000000F,
        /* ECX */            0x00000000,   /* x00 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000F_x00_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000F_x00_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000F_x00_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000F_x00_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000F_x00_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000F_x00_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000F_x00_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000F_x00_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn0000000F_x01 */
    {
        /* EAX */            0x0000000F,
        /* ECX */            0x00000001,   /* x01 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN0000000F_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN0000000F_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN0000000F_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN0000000F_x01_EDX_DEFAULT,
        /* EAX_RESERVED */   FN0000000F_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN0000000F_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN0000000F_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN0000000F_x01_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn00000010_x00 */
    {
        /* EAX */            0x00000010,
        /* ECX */            0x00000000,   /* x00 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN00000010_x00_EAX_DEFAULT,
        /* EBX_OUT */        FN00000010_x00_EBX_DEFAULT,
        /* ECX_OUT */        FN00000010_x00_ECX_DEFAULT,
        /* EDX_OUT */        FN00000010_x00_EDX_DEFAULT,
        /* EAX_RESERVED */   FN00000010_x00_EAX_RESERVED,
        /* EBX_RESERVED */   FN00000010_x00_EBX_RESERVED,
        /* ECX_RESERVED */   FN00000010_x00_ECX_RESERVED,
        /* EDX_RESERVED */   FN00000010_x00_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn00000010_x01 */
    {
        /* EAX */            0x00000010,
        /* ECX */            0x00000001,   /* x01 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN00000010_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN00000010_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN00000010_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN00000010_x01_EDX_DEFAULT,
        /* EAX_RESERVED */   FN00000010_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN00000010_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN00000010_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN00000010_x01_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000000 */
    {
        /* EAX */            0x80000000,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000000_EAX_DEFAULT,
        /* EBX_OUT */        FN80000000_EBX_DEFAULT,
        /* ECX_OUT */        FN80000000_ECX_DEFAULT,
        /* EDX_OUT */        FN80000000_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000000_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000000_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000000_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000000_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_LESSTHAN,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000001 */
    {
        /* EAX */            0x80000001,
        /* ECX */            0x00000000,
        /* CUSTOM */         FN80000001_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn80000002 */
    {
        /* EAX */            0x80000002,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000002_DEFAULT,
        /* EBX_OUT */        FN80000002_DEFAULT,
        /* ECX_OUT */        FN80000002_DEFAULT,
        /* EDX_OUT */        FN80000002_DEFAULT,
        /* EAX_RESERVED */   FN80000002_RESERVED,
        /* EBX_RESERVED */   FN80000002_RESERVED,
        /* ECX_RESERVED */   FN80000002_RESERVED,
        /* EDX_RESERVED */   FN80000002_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000003 */
    {
        /* EAX */            0x80000003,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000003_DEFAULT,
        /* EBX_OUT */        FN80000003_DEFAULT,
        /* ECX_OUT */        FN80000003_DEFAULT,
        /* EDX_OUT */        FN80000003_DEFAULT,
        /* EAX_RESERVED */   FN80000003_RESERVED,
        /* EBX_RESERVED */   FN80000003_RESERVED,
        /* ECX_RESERVED */   FN80000003_RESERVED,
        /* EDX_RESERVED */   FN80000003_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000004 */
    {
        /* EAX */            0x80000004,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000004_DEFAULT,
        /* EBX_OUT */        FN80000004_DEFAULT,
        /* ECX_OUT */        FN80000004_DEFAULT,
        /* EDX_OUT */        FN80000004_DEFAULT,
        /* EAX_RESERVED */   FN80000004_RESERVED,
        /* EBX_RESERVED */   FN80000004_RESERVED,
        /* ECX_RESERVED */   FN80000004_RESERVED,
        /* EDX_RESERVED */   FN80000004_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000005 */
    {
        /* EAX */            0x80000005,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000005_EAX_DEFAULT,
        /* EBX_OUT */        FN80000005_EBX_DEFAULT,
        /* ECX_OUT */        FN80000005_ECX_DEFAULT,
        /* EDX_OUT */        FN80000005_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000005_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000005_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000005_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000005_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000006 */
    {
        /* EAX */            0x80000006,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000006_EAX_DEFAULT,
        /* EBX_OUT */        FN80000006_EBX_DEFAULT,
        /* ECX_OUT */        FN80000006_ECX_DEFAULT,
        /* EDX_OUT */        FN80000006_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000006_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000006_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000006_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000006_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000007 */
    {
        /* EAX */            0x80000007,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000007_EAX_DEFAULT,
        /* EBX_OUT */        FN80000007_EBX_DEFAULT,
        /* ECX_OUT */        FN80000007_ECX_DEFAULT,
        /* EDX_OUT */        FN80000007_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000007_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000007_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000007_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000007_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_MASK,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_MASK,
        },
    },

    /* Functional Register CPUID_Fn80000008 */
    {
        /* EAX */            0x80000008,
        /* ECX */            0x00000000,
        /* CUSTOM */         FN80000008_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn8000000A */
    {
        /* EAX */            0x8000000A,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000000A_EAX_DEFAULT,
        /* EBX_OUT */        FN8000000A_EBX_DEFAULT,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FN8000000A_EDX_DEFAULT,
        /* EAX_RESERVED */   FN8000000A_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000000A_EBX_RESERVED,
        /* ECX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FN8000000A_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_MASK,
        },
    },

    /* Functional Register CPUID_Fn80000019 */
    {
        /* EAX */            0x80000019,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000019_EAX_DEFAULT,
        /* EBX_OUT */        FN80000019_EBX_DEFAULT,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FN80000019_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000019_EBX_RESERVED,
        /* ECX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn8000001A */
    {
        /* EAX */            0x8000001A,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001A_EAX_DEFAULT,
        /* EBX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FN8000001A_EAX_RESERVED,
        /* EBX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* ECX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn8000001B */
    {
        /* EAX */            0x8000001B,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001B_EAX_DEFAULT,
        /* EBX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FN8000001B_EAX_RESERVED,
        /* EBX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* ECX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_MASK,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn8000001D_x00 */
    {
        /* EAX */            0x8000001D,
        /* ECX */            0x00000000, /* x00*/
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001D_x00_EAX_DEFAULT,
        /* EBX_OUT */        FN8000001D_x00_EBX_DEFAULT,
        /* ECX_OUT */        FN8000001D_x00_ECX_DEFAULT,
        /* EDX_OUT */        FN8000001D_x00_EDX_DEFAULT,
        /* EAX_RESERVED */   FN8000001D_x00_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000001D_x00_EBX_RESERVED,
        /* ECX_RESERVED */   FN8000001D_x00_ECX_RESERVED,
        /* EDX_RESERVED */   FN8000001D_x00_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn8000001D_x01 */
    {
        /* EAX */            0x8000001D,
        /* ECX */            0x00000001, /* x01*/
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001D_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN8000001D_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN8000001D_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN8000001D_x01_EDX_DEFAULT,
        /* EAX_RESERVED */   FN8000001D_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000001D_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN8000001D_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN8000001D_x01_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn8000001D_x02 */
    {
        /* EAX */            0x8000001D,
        /* ECX */            0x00000002, /* x02*/
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001D_x02_EAX_DEFAULT,
        /* EBX_OUT */        FN8000001D_x02_EBX_DEFAULT,
        /* ECX_OUT */        FN8000001D_x02_ECX_DEFAULT,
        /* EDX_OUT */        FN8000001D_x02_EDX_DEFAULT,
        /* EAX_RESERVED */   FN8000001D_x02_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000001D_x02_EBX_RESERVED,
        /* ECX_RESERVED */   FN8000001D_x02_ECX_RESERVED,
        /* EDX_RESERVED */   FN8000001D_x02_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn8000001D_x03 */
    {
        /* EAX */            0x8000001D,
        /* ECX */            0x00000003, /* x03*/
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001D_x03_EAX_DEFAULT,
        /* EBX_OUT */        FN8000001D_x03_EBX_DEFAULT,
        /* ECX_OUT */        FN8000001D_x03_ECX_DEFAULT,
        /* EDX_OUT */        FN8000001D_x03_EDX_DEFAULT,
        /* EAX_RESERVED */   FN8000001D_x03_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000001D_x03_EBX_RESERVED,
        /* ECX_RESERVED */   FN8000001D_x03_ECX_RESERVED,
        /* EDX_RESERVED */   FN8000001D_x03_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn8000001D_x04 */
    {
        /* EAX */            0x8000001D,
        /* ECX */            0x00000004, /* x04*/
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001D_x04_EAX_DEFAULT,
        /* EBX_OUT */        FN8000001D_x04_EBX_DEFAULT,
        /* ECX_OUT */        FN8000001D_x04_ECX_DEFAULT,
        /* EDX_OUT */        FN8000001D_x04_EDX_DEFAULT,
        /* EAX_RESERVED */   FN8000001D_x04_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000001D_x04_EBX_RESERVED,
        /* ECX_RESERVED */   FN8000001D_x04_ECX_RESERVED,
        /* EDX_RESERVED */   FN8000001D_x04_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn8000001E */
    {
        /* EAX */            0x8000001E,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN8000001E_EAX_DEFAULT,
        /* EBX_OUT */        FN8000001E_EBX_DEFAULT,
        /* ECX_OUT */        FN8000001E_ECX_DEFAULT,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FN8000001E_EAX_RESERVED,
        /* EBX_RESERVED */   FN8000001E_EBX_RESERVED,
        /* ECX_RESERVED */   FN8000001E_ECX_RESERVED,
        /* EDX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn8000001F */
    {
        /* EAX */            0x8000001F,
        /* ECX */            0x00000000,
        /* CUSTOM */         FN8000001F_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn80000020 x00 */
    {
        /* EAX */            0x80000020,
        /* ECX */            0x00000000, /* x00 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000020_x00_EAX_DEFAULT,
        /* EBX_OUT */        FN80000020_x00_EBX_DEFAULT,
        /* ECX_OUT */        FN80000020_x00_ECX_DEFAULT,
        /* EDX_OUT */        FN80000020_x00_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000020_x00_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000020_x00_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000020_x00_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000020_x00_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn80000020 x01 */
    {
        /* EAX */            0x80000020,
        /* ECX */            0x00000001, /* x01 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000020_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN80000020_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN80000020_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN80000020_x01_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000020_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000020_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000020_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000020_x01_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000020 x02 */
    {
        /* EAX */            0x80000020,
        /* ECX */            0x00000002, /* x02 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000020_x02_EAX_DEFAULT,
        /* EBX_OUT */        FN80000020_x02_EBX_DEFAULT,
        /* ECX_OUT */        FN80000020_x02_ECX_DEFAULT,
        /* EDX_OUT */        FN80000020_x02_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000020_x02_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000020_x02_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000020_x02_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000020_x02_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000020 x03 */
    {
        /* EAX */            0x80000020,
        /* ECX */            0x00000003, /* x03 */
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000020_x03_EAX_DEFAULT,
        /* EBX_OUT */        FN80000020_x03_EBX_DEFAULT,
        /* ECX_OUT */        FN80000020_x03_ECX_DEFAULT,
        /* EDX_OUT */        FN80000020_x03_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000020_x03_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000020_x03_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000020_x03_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000020_x03_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_EXACT,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_MASK,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn80000021 */
    {
        /* EAX */            0x80000021,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000021_EAX_DEFAULT,
        /* EBX_OUT */        FN80000021_EBX_DEFAULT,
        /* ECX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EDX_OUT */        FNXXXXXXXX_CPUID_DOES_NOT_EXIST,
        /* EAX_RESERVED */   FN80000021_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000021_EBX_RESERVED,
        /* ECX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* EDX_RESERVED */   FNXXXXXXXX_RESERVED_DOES_NOT_EXIST,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_MASK,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn80000022 */
    {
        /* EAX */            0x80000022,
        /* ECX */            0x00000000,
        /* CUSTOM */         FN80000022_CUSTOM,
        /* EAX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EBX_OUT */        FNXXXXXXXX_CUSTOM,
        /* ECX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EDX_OUT */        FNXXXXXXXX_CUSTOM,
        /* EAX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EBX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* ECX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* EDX_RESERVED */   FNXXXXXXXX_CUSTOM,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_CUSTOM,
            /* EBX Rules */  CPUID_RULE_CUSTOM,
            /* ECX Rules */  CPUID_RULE_CUSTOM,
            /* EDX Rules */  CPUID_RULE_CUSTOM,
        },
    },

    /* Functional Register CPUID_Fn80000023 */
    {
        /* EAX */            0x80000023,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000023_EAX_DEFAULT,
        /* EBX_OUT */        FN80000023_EBX_DEFAULT,
        /* ECX_OUT */        FN80000023_ECX_DEFAULT,
        /* EDX_OUT */        FN80000023_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000023_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000023_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000023_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000023_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_MASK,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn80000024x00 - Used for FEATURE_INFO for HV */
    {
        /* EAX */            0x80000024,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000024_x00_EAX_DEFAULT,
        /* EBX_OUT */        FN80000024_x00_EBX_DEFAULT,
        /* ECX_OUT */        FN80000024_x00_ECX_DEFAULT,
        /* EDX_OUT */        FN80000024_x00_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000024_x00_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000024_x00_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000024_x00_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000024_x00_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_LESSTHAN,
            /* EBX Rules */  CPUID_RULE_MASK,
            /* ECX Rules */  CPUID_RULE_MASK,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },

    /* Functional Register CPUID_Fn80000024x01 - Used for FEATURE_INFO for guests*/
    {
        /* EAX */            0x80000024,
        /* ECX */            0x00000001,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000024_x01_EAX_DEFAULT,
        /* EBX_OUT */        FN80000024_x01_EBX_DEFAULT,
        /* ECX_OUT */        FN80000024_x01_ECX_DEFAULT,
        /* EDX_OUT */        FN80000024_x01_EDX_DEFAULT,
        /* EAX_RESERVED */   FN80000024_x01_EAX_RESERVED,
        /* EBX_RESERVED */   FN80000024_x01_EBX_RESERVED,
        /* ECX_RESERVED */   FN80000024_x01_ECX_RESERVED,
        /* EDX_RESERVED */   FN80000024_x01_EDX_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_MASK,
            /* EBX Rules */  CPUID_RULE_EXACT,
            /* ECX Rules */  CPUID_RULE_EXACT,
            /* EDX Rules */  CPUID_RULE_EXACT,
        },
    },


    /* Functional Register CPUID_Fn80000026 x00 */
    {
        /* EAX */            0x80000026,
        /* ECX */            0x00000000,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000026_DEFAULT,
        /* EBX_OUT */        FN80000026_DEFAULT,
        /* ECX_OUT */        FN80000026_DEFAULT,
        /* EDX_OUT */        FN80000026_DEFAULT,
        /* EAX_RESERVED */   FN80000026_RESERVED,
        /* EBX_RESERVED */   FN80000026_RESERVED,
        /* ECX_RESERVED */   FN80000026_RESERVED,
        /* EDX_RESERVED */   FN80000026_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000026 x01 */
    {
        /* EAX */            0x80000026,
        /* ECX */            0x00000001,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000026_DEFAULT,
        /* EBX_OUT */        FN80000026_DEFAULT,
        /* ECX_OUT */        FN80000026_DEFAULT,
        /* EDX_OUT */        FN80000026_DEFAULT,
        /* EAX_RESERVED */   FN80000026_RESERVED,
        /* EBX_RESERVED */   FN80000026_RESERVED,
        /* ECX_RESERVED */   FN80000026_RESERVED,
        /* EDX_RESERVED */   FN80000026_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000026 x02 */
    {
        /* EAX */            0x80000026,
        /* ECX */            0x00000002,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000026_DEFAULT,
        /* EBX_OUT */        FN80000026_DEFAULT,
        /* ECX_OUT */        FN80000026_DEFAULT,
        /* EDX_OUT */        FN80000026_DEFAULT,
        /* EAX_RESERVED */   FN80000026_RESERVED,
        /* EBX_RESERVED */   FN80000026_RESERVED,
        /* ECX_RESERVED */   FN80000026_RESERVED,
        /* EDX_RESERVED */   FN80000026_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

    /* Functional Register CPUID_Fn80000026 x03 */
    {
        /* EAX */            0x80000026,
        /* ECX */            0x00000003,
        /* CUSTOM */         NULL,
        /* EAX_OUT */        FN80000026_DEFAULT,
        /* EBX_OUT */        FN80000026_DEFAULT,
        /* ECX_OUT */        FN80000026_DEFAULT,
        /* EDX_OUT */        FN80000026_DEFAULT,
        /* EAX_RESERVED */   FN80000026_RESERVED,
        /* EBX_RESERVED */   FN80000026_RESERVED,
        /* ECX_RESERVED */   FN80000026_RESERVED,
        /* EDX_RESERVED */   FN80000026_RESERVED,
        /* Rules */
        {
            /* EAX Rules */  CPUID_RULE_UNCHECKED,
            /* EBX Rules */  CPUID_RULE_UNCHECKED,
            /* ECX Rules */  CPUID_RULE_UNCHECKED,
            /* EDX Rules */  CPUID_RULE_UNCHECKED,
        },
    },

};

#define MAX_CPUIDS (sizeof(lookup_table) / sizeof (cpuid_lookup))

static sev_status_t cpuid_entry_rule_check(uint8_t rule, uint32_t valmask, uint32_t reservedmask, uint32_t *reg)
{
    switch (rule)
    {
        case CPUID_RULE_MASK:
            if ((*reg & valmask) != *reg)
            {
                *reg = *reg & valmask;
                return SEV_STATUS_INVALID_CONFIG;
            }
            break;
        case CPUID_RULE_EXACT:
            if (*reg != valmask)
            {
                *reg = valmask;
                return SEV_STATUS_INVALID_CONFIG;
            }
            break;
        case CPUID_RULE_LESSTHAN:
            if (*reg > valmask)
            {
                *reg = valmask;
                return SEV_STATUS_INVALID_CONFIG;
            }
            break;
        case CPUID_RULE_UNCHECKED:
            break;
        default:
        case CPUID_RULE_DOES_NOT_EXIST:
            *reg = valmask;
            break;
    }

    /* Always check reserved bits */
    if ((~(*reg) & reservedmask) != reservedmask)
    {
        *reg = *reg & ~(reservedmask);
        return SEV_STATUS_INVALID_CONFIG;
    }

    return SEV_STATUS_SUCCESS;
}

sev_status_t sanitize_cpuid_entry(uint32_t *eax_in, uint32_t *ecx_in,
                                  uint64_t *xcr0_in, uint64_t *xss_in,
                                  uint32_t *eax_out, uint32_t *ebx_out,
                                  uint32_t *ecx_out, uint32_t *edx_out)
{
    uint32_t i = 0;
    sev_status_t status = SEV_STATUS_SUCCESS;
    bool found = false;
    bool error_detected = false;

    if (eax_in == NULL || ecx_in == NULL || xcr0_in == NULL || eax_out == NULL ||
        ebx_out == NULL || ecx_out == NULL || edx_out == NULL)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    for (i = 0; i < MAX_CPUIDS; i++)
    {
        if ((lookup_table[i].eax_in == *eax_in) && (lookup_table[i].ecx_in == *ecx_in))
        {
            /* Found a match */
            found = true;
            if (lookup_table[i].custom_func == NULL)
            {
                status = cpuid_entry_rule_check(lookup_table[i].rules.eax_rule, lookup_table[i].eax_out, lookup_table[i].eax_reserved, eax_out);
                if (status != SEV_STATUS_SUCCESS)
                    error_detected = true;

                status = cpuid_entry_rule_check(lookup_table[i].rules.ebx_rule, lookup_table[i].ebx_out, lookup_table[i].ebx_reserved, ebx_out);
                if (status != SEV_STATUS_SUCCESS)
                    error_detected = true;

                status = cpuid_entry_rule_check(lookup_table[i].rules.ecx_rule, lookup_table[i].ecx_out, lookup_table[i].ecx_reserved, ecx_out);
                if (status != SEV_STATUS_SUCCESS)
                    error_detected = true;

                status = cpuid_entry_rule_check(lookup_table[i].rules.edx_rule, lookup_table[i].edx_out, lookup_table[i].edx_reserved, edx_out);
                if (status != SEV_STATUS_SUCCESS)
                    error_detected = true;
            }
            else
            {
                status = lookup_table[i].custom_func(*eax_in, *ecx_in, *xcr0_in, *xss_in, eax_out, ebx_out, ecx_out, edx_out);
                if (status != SEV_STATUS_SUCCESS)
                    error_detected = true;
            }
            break;
        }
    }

    /* Any architectural leaf not listed in the table must have all output values equal to 0 */
    if ((found == false) &&
        (*eax_out != 0 || *ebx_out != 0 || *ecx_out != 0 || *edx_out != 0))
    {
        *eax_out = 0;
        *ebx_out = 0;
        *ecx_out = 0;
        *edx_out = 0;
        error_detected = true;
    }

    if (error_detected)
        status = SEV_STATUS_INVALID_PARAM;

end:
    return status;
}

sev_status_t sanitize_cpuid_list(snp_cpuid_function_t *cpuid_function,
                                 uint32_t req_count, uint32_t *rsp_count)
{
    sev_status_t status = SEV_STATUS_SUCCESS;
    uint32_t i = 0;
    bool failed = false;

    if (!rsp_count)
    {
        status = ERR_INVALID_PARAMS;
        goto end;
    }

    *rsp_count = 0;

    for (i = 0; i < req_count; i++)
    {
        /*
         * If CPUID function is not in the standard range (Fn0000_0000 - Fn0000_FFFF)
         * or the extended range (Fn8000_0000 - Fn8000_FFFF), do not perform any
         * checks on the function output.
         */
        if (((int)cpuid_function[i].eax_in >= CPUID_STD_RANGE_MIN && cpuid_function[i].eax_in <= CPUID_STD_RANGE_MAX) ||
            (cpuid_function[i].eax_in >= CPUID_EXT_RANGE_MIN && cpuid_function[i].eax_in <= CPUID_EXT_RANGE_MAX))
        {
            if (cpuid_function[i].reserved != 0)
            {
                failed = true;
            }

            /* Validate architectural leaves */
            status = sanitize_cpuid_entry(&cpuid_function[i].eax_in,
                                          &cpuid_function[i].ecx_in,
                                          &cpuid_function[i].xcr0_in,
                                          &cpuid_function[i].xss_in,
                                          &cpuid_function[i].eax,
                                          &cpuid_function[i].ebx,
                                          &cpuid_function[i].ecx,
                                          &cpuid_function[i].edx);
            if (status != SEV_STATUS_SUCCESS)
            {
                failed = true;
            }

            /* Increment the count that has been validated */
            *rsp_count = *rsp_count + 1;
        }
    }

end:
    return (failed) ? SEV_STATUS_INVALID_PARAM : SEV_STATUS_SUCCESS;
}
