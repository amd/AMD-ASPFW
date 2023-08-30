// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_TRACE_H
#define SEV_TRACE_H

#include <stddef.h>
#include <stdint.h>

// TRACE switch for overall SEV_UAPP
// Turn ON by compile switch "SEV_UAPP_TRACE_ENABLE=1"
// Only work for master die, debug print cannot be enabled on slave Dies.
#ifdef SEV_UAPP_TRACE_ENABLE
#define SEV_MCMD_TRACE_EN               // TRACE switch for module: sev_mcmd
#define SEV_PLAT_TRACE_EN               // TRACE switch for module: sev_plat
#define SEV_GUEST_TRACE_EN              // TRACE switch for module: sev_guest
#define SEV_HAL_TRACE_EN                // TRACE switch for module: sev_hal
#endif


#ifdef SEV_UAPP_TRACE_ENABLE
    #define SEV_TRACE( str )                Svc_DebugPrint( str )
    #define SEV_TRACE_EX( ... )             Svc_DebugPrintEx ( __VA_ARGS__ )
#else
    #define SEV_TRACE( str )
    #define SEV_TRACE_EX( ... )
#endif

#ifdef SEV_MCMD_TRACE_EN
    #define SEV_MCMD_TRACE( str )           Svc_DebugPrint( str )
    #define SEV_MCMD_TRACE_EX( ... )        Svc_DebugPrintEx ( __VA_ARGS__ )
#else
    #define SEV_MCMD_TRACE( str )
    #define SEV_MCMD_TRACE_EX( ... )
#endif

#ifdef SEV_PLAT_TRACE_EN
    #define SEV_PLAT_TRACE( str )           Svc_DebugPrint( str )
    #define SEV_PLAT_TRACE_EX( ... )        Svc_DebugPrintEx ( __VA_ARGS__ )
#else
    #define SEV_PLAT_TRACE( str )
    #define SEV_PLAT_TRACE_EX( ... )
#endif

#ifdef SEV_GUEST_TRACE_EN
    #define SEV_GUEST_TRACE( str )          Svc_DebugPrint( str )
    #define SEV_GUEST_TRACE_EX( ... )       Svc_DebugPrintEx ( __VA_ARGS__ )
#else
    #define SEV_GUEST_TRACE( str )
    #define SEV_GUEST_TRACE_EX( ... )
#endif

#ifdef SEV_HAL_TRACE_EN
    #define SEV_HAL_TRACE( str )            Svc_DebugPrint( str )
    #define SEV_HAL_TRACE_EX( ... )         Svc_DebugPrintEx ( __VA_ARGS__ )
#else
    #define SEV_HAL_TRACE( str )
    #define SEV_HAL_TRACE_EX( ... )
#endif

#endif /* SEV_TRACE_H */
