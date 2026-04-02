/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report hosts.
 *
 * Headers for SQL handlers for report host XML.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_HOSTS_H
#define _GVM_MANAGE_SQL_REPORT_HOSTS_H

#include "manage_report_hosts.h"
#include "manage_sql.h"

int
print_report_hosts_xml (print_report_context_t *,
                        FILE *,
                        report_t,
                        const get_data_t *,
                        const gchar *,
                        int lean,
                        gboolean,
                        gboolean,
                        array_t *,
                        GString *);

int
fill_filtered_result_hosts (array_t **,
                            const get_data_t *,
                            report_t,
                            iterator_t *,
                            gboolean);

#endif /* _GVM_MANAGE_SQL_REPORT_HOSTS_H */
