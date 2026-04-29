/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report operating systems.
 *
 * Non-SQL report operating systems code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_OPERATING_SYSTEMS_H
#define _GVM_MANAGE_REPORT_OPERATING_SYSTEMS_H

#include "manage_resources.h"

#include <glib.h>

struct report_os {
 gchar *best_os_name;
 gchar *os_cpe;
 int hosts_count;
};
typedef struct report_os *report_os_t;

report_os_t
report_os_new (void);

void
report_os_free (report_os_t);

GPtrArray *
report_os_list_new (void);

void
report_os_list_free (GPtrArray *);

int
get_report_operating_systems (report_t,
                              const get_data_t *,
                              GPtrArray **);
int
report_operating_systems_count (report_t);

int
fill_filtered_report_host_ids (GHashTable **,
                               const get_data_t *,
                               report_t ,
                               iterator_t *);

#endif //_GVM_MANAGE_REPORT_OPERATING_SYSTEMS_H
