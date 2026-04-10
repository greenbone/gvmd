/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report errors.
 *
 * Headers for SQL handlers for report error XML.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_ERRORS_H
#define _GVM_MANAGE_SQL_REPORT_ERRORS_H

#include "manage_sql.h"

void
init_report_errors_iterator (iterator_t *, report_t);

const char *
report_errors_iterator_host (iterator_t *);

const char *
report_errors_iterator_severity (iterator_t *);

const char *
report_errors_iterator_scan_nvt_version (iterator_t *);

const char *
report_errors_iterator_port (iterator_t *);

const char *
report_errors_iterator_nvt_oid (iterator_t *);

const char *
report_errors_iterator_desc (iterator_t *);

const char *
report_errors_iterator_nvt_name (iterator_t *);

const char *
report_errors_iterator_nvt_cvss (iterator_t *);

const char *
report_errors_iterator_scan_nvt_version (iterator_t *);

const char *
report_errors_iterator_severity (iterator_t *);

int
report_error_count (report_t);

int
print_report_errors_xml (report_t, FILE *);

int
print_report_errors_xml_summary_or_details (report_t, FILE *, int);

#endif //_GVM_MANAGE_SQL_REPORT_ERRORS_H
