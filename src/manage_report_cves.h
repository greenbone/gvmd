/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report CVEs.
 *
 * Non-SQL report CVEs code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_CVES_H
#define _GVM_MANAGE_REPORT_CVES_H

#include "manage_resources.h"

#include <glib.h>

struct report_cve {
  gchar *nvt_name;
  gchar *nvt_oid;
  int hosts_count;
  int occurrences;
  double severity_double;
  GPtrArray *nvt_cves;
};
typedef struct report_cve *report_cve_t;

report_cve_t
report_cve_new(void);

void
report_cve_free(report_cve_t);

GPtrArray *
report_cve_list_new (void);

void
report_cve_list_free (GPtrArray *);

int
get_report_cves (report_t,
                 const get_data_t *,
                 GPtrArray **);

int
report_cves_count (report_t, const get_data_t *);

#endif //_GVM_MANAGE_REPORT_CVES_H
