// Copyright(C) 2023 Advanced Micro Devices, Inc. All rights reserved.

/* Extended error codes used throughout SEV FW.
 * Each error code is unique, but arbitrary.
 * These values need to be documented elsewhere.
 * All we do here in this file is track allocation.
 */

#include "sev_status.h"

extern uint64_t sev_error_stack;
extern sev_status_t sev_error(sev_status_t status, uint16_t error_id);
#define SEV_ERROR(status, error_id) sev_error(status, error_id)

#define EXT_ERR_001 1
#define EXT_ERR_002 2
#define EXT_ERR_003 3
#define EXT_ERR_004 4
#define EXT_ERR_005 5
#define EXT_ERR_006 6
#define EXT_ERR_007 7
#define EXT_ERR_008 8
#define EXT_ERR_009 9
#define EXT_ERR_010 10
#define EXT_ERR_011 11
#define EXT_ERR_012 12
#define EXT_ERR_013 13
#define EXT_ERR_014 14
#define EXT_ERR_015 15
#define EXT_ERR_016 16
#define EXT_ERR_017 17
#define EXT_ERR_018 18
#define EXT_ERR_019 19
#define EXT_ERR_020 20
#define EXT_ERR_021 21
#define EXT_ERR_022 22
#define EXT_ERR_023 23
#define EXT_ERR_024 24
#define EXT_ERR_025 25
#define EXT_ERR_026 26
#define EXT_ERR_027 27
#define EXT_ERR_028 28
#define EXT_ERR_029 29
#define EXT_ERR_030 30
#define EXT_ERR_031 31
#define EXT_ERR_032 32
#define EXT_ERR_033 33
#define EXT_ERR_034 34
#define EXT_ERR_035 35
#define EXT_ERR_036 36
#define EXT_ERR_037 37
#define EXT_ERR_038 38
#define EXT_ERR_039 39
#define EXT_ERR_040 40
#define EXT_ERR_041 41
#define EXT_ERR_042 42
#define EXT_ERR_043 43
#define EXT_ERR_044 44
#define EXT_ERR_045 45
#define EXT_ERR_046 46
#define EXT_ERR_047 47
#define EXT_ERR_048 48
#define EXT_ERR_049 49
#define EXT_ERR_050 50
#define EXT_ERR_051 51
#define EXT_ERR_052 52
#define EXT_ERR_053 53
#define EXT_ERR_054 54
#define EXT_ERR_055 55
#define EXT_ERR_056 56
#define EXT_ERR_057 57
#define EXT_ERR_058 58
#define EXT_ERR_059 59
#define EXT_ERR_060 60
#define EXT_ERR_061 61
#define EXT_ERR_062 62
#define EXT_ERR_063 63
#define EXT_ERR_064 64
#define EXT_ERR_065 65
#define EXT_ERR_066 66
#define EXT_ERR_067 67
#define EXT_ERR_068 68
#define EXT_ERR_069 69
#define EXT_ERR_070 70
#define EXT_ERR_071 71
#define EXT_ERR_072 72
#define EXT_ERR_073 73
#define EXT_ERR_074 74
#define EXT_ERR_075 75
#define EXT_ERR_076 76
#define EXT_ERR_077 77
#define EXT_ERR_078 78
#define EXT_ERR_079 79
#define EXT_ERR_080 80
#define EXT_ERR_081 81
#define EXT_ERR_082 82
#define EXT_ERR_083 83
#define EXT_ERR_084 84
#define EXT_ERR_085 85
#define EXT_ERR_086 86
#define EXT_ERR_087 87
#define EXT_ERR_088 88
#define EXT_ERR_089 89
#define EXT_ERR_090 90
#define EXT_ERR_091 91
#define EXT_ERR_092 92
#define EXT_ERR_093 93
#define EXT_ERR_094 94
#define EXT_ERR_095 95
#define EXT_ERR_096 96
#define EXT_ERR_097 97
#define EXT_ERR_098 98
#define EXT_ERR_099 99
#define EXT_ERR_100 100
