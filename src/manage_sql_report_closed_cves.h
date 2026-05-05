/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report closed cves.
 *
 * Headers for SQL handlers for report closed cve XML.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_CLOSED_CVES_H
#define _GVM_MANAGE_SQL_REPORT_CLOSED_CVES_H

#include "manage_report_closed_cves.h"

void
init_report_closed_cve_iterator (iterator_t *, report_t);

int
report_closed_cve_count (report_t);

const gchar *
report_closed_cve_iterator_host (iterator_t *);

const gchar *
report_closed_cve_iterator_cve (iterator_t *);

const gchar *
report_closed_cve_iterator_oid (iterator_t *);

const gchar *
report_closed_cve_iterator_nvt_name (iterator_t *);

double
report_closed_cve_iterator_severity_double (iterator_t *);

#endif //_GVM_MANAGE_SQL_REPORT_CLOSED_CVES_H
