// Copyright(C) 2018-2020 Advanced Micro Devices, Inc. All rights reserved.

#ifndef APICID_H
#define APICID_H

#include <stddef.h>
#include <stdint.h>

#include "sev_plat.h"
#include "sev_status.h"

/* Apicid list count (numIDs) limit for apicid to ccx bitmask conversion. */
/* Each apicid entry is 4 bytes (32bits), and the maximum number of entries
   for a 4K page should be 1024 entries */
#define APIC_ID_LIST_MAX_CNT    (1024)  /* 4K memory - 1 page */

/**
 * Creates APIC ID look up table.
 */
sev_status_t create_apicid_table(sev_t *sev);

/**
 * Sync up APIC ID lookup table between master and slave
 */
sev_status_t sync_apicid_tables(sev_t *sev);

/**
 * Converts a list of APICIDs of uint32_t to the PHYSICAL ccx_bitmask
 */
sev_status_t apicid_to_ccx_bitmask(sev_t *sev, uint32_t *apicid_list,
                                   size_t listcnt, uint32_t *ccx_bitmask);

/**
 * Get the APIC ID (physical params)
 */
sev_status_t get_apic_id(uint32_t socket_id, uint32_t ccd, uint32_t ccx, uint32_t core, uint32_t thread_id, uint32_t *apicid);
/**
 * Get the APIC ID (logical params)
 */
uint32_t get_apic_id_logical(uint32_t socket_id, uint32_t ccd, uint32_t ccx, uint32_t core, uint32_t thread_id);

/**
 * Helper function to get bits needed to represent given number of instances.
 */
uint32_t get_field_width(uint32_t num_instances);

uint32_t get_num_cores_per_complex(void);

uint32_t get_ccds_per_socket(void);

uint32_t get_ccxs_per_ccd(void);

uint32_t get_max_ccds(void);

uint32_t get_physical_ccxs_per_ccd(void);

#endif /* APICID_H */
