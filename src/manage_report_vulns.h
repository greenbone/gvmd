/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report Vulnerabilities.
 *
 * Non-SQL report Vulnerabilities code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_VULNS_H
#define _GVM_MANAGE_REPORT_VULNS_H

#include "manage_resources.h"

#include <glib.h>

struct report_vuln {
  gchar *nvt_name;
  gchar *nvt_oid;
  int hosts_count;
  int occurrences;
  double severity_double;
  GPtrArray *nvt_cves;
};
typedef struct report_vuln *report_vuln_t;

report_vuln_t
report_vuln_new(void);

void
report_vuln_free(report_vuln_t);

GPtrArray *
report_vuln_list_new (void);

void
report_vuln_list_free (GPtrArray *);

int
get_report_vulns (report_t,
                 const get_data_t *,
                 GPtrArray **);

int
report_vulns_count (report_t, const get_data_t *);

#endif //_GVM_MANAGE_REPORT_VULNS_H
