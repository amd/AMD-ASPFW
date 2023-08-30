// Copyright(C) 2016-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SEV_HAL_IOMMU_H
#define SEV_HAL_IOMMU_H

#include <stddef.h>
#include <stdint.h>

#include "sev_es.h"
#include "sev_rmp.h"
#include "sev_status.h"

/* Genoa has 2 physical NBIOs, but each has 2 IOHUBs.  So logically,
   it was "4 NBIOs" in the way SNP is addressing the registers */
#define MAX_NBIO                (2 * 2)
#define MAX_IOMMU_TABLE_STATES  (5*MAX_NBIO*MAX_SOCKET_NUM) /* 5 tables in set_iommu_table_state() */

sev_status_t enable_snp_iommu(void);
sev_status_t validate_snp_iommu(void);
sev_status_t disable_snp_iommu(void);
sev_status_t check_iommu_event_logs(void);
sev_status_t set_iommu_table_state(snp_page_state_t page_state);

#endif /* SEV_HAL_IOMMU_H */
