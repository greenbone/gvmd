/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report ports.
 *
 * Headers for SQL handlers for report port XML.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_PORTS_H
#define _GVM_MANAGE_SQL_REPORT_PORTS_H

#include "manage_sql.h"

int
print_report_port_xml (print_report_context_t *, report_t, FILE *,
                       const get_data_t *, int, int, int, const char *,
                       iterator_t *);

int
print_report_port_xml_summary_or_details (print_report_context_t *, report_t,
                                          FILE *, const get_data_t *, int, int,
                                          int, int, const char *, iterator_t *);

#endif //_GVM_MANAGE_SQL_REPORT_PORTS_H
