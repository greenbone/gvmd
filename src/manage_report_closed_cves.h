/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report closed cves.
 *
 * Non-SQL report closed cves code for the GVM management layer.
 */

#ifndef _GVM_MANAGE_REPORT_CLOSED_CVES_H
#define _GVM_MANAGE_REPORT_CLOSED_CVES_H

#include "manage_resources.h"

#include <glib.h>

struct report_closed_cve {
  gchar *host;
  gchar *cve;
  gchar *oid;
  gchar *nvt_name;
  double severity_double;
};
typedef struct report_closed_cve *report_closed_cve_t;

report_closed_cve_t
report_closed_cve_new(void);

void
report_closed_cve_free(report_closed_cve_t);

GPtrArray *
report_closed_cve_list_new (void);

void
report_closed_cve_list_free (GPtrArray *);

int
get_report_closed_cves (report_t, GPtrArray **);

int
report_closed_cve_count (report_t);

#endif //_GVM_MANAGE_REPORT_CLOSED_CVES_H
