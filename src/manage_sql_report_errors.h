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

int
print_report_errors_xml (report_t, FILE *);

int
print_report_errors_xml_summary_or_details (report_t, FILE *, int);

#endif //_GVM_MANAGE_SQL_REPORT_ERRORS_H
