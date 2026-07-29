/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Audit report hosts.
 *
 * Headers for SQL handlers for audit report hosts.
 */

#ifndef _GVM_MANAGE_SQL_AUDIT_REPORT_HOSTS_H
#define _GVM_MANAGE_SQL_AUDIT_REPORT_HOSTS_H

#include "manage_sql_report_hosts.h"

int
fill_filtered_audit_report_hosts (array_t **,
                                  const get_data_t *,
                                  report_t,
                                  iterator_t *,
                                  print_report_context_t *,
                                  const gchar *);

#endif /* _GVM_MANAGE_SQL_AUDIT_REPORT_HOSTS_H */
