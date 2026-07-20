/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured scan report summary loading.
 */

#ifndef _GVMD_MANAGE_SQL_SCAN_REPORT_H
#define _GVMD_MANAGE_SQL_SCAN_REPORT_H

#include "manage_scan_report.h"

int
manage_sql_fill_report_summary (report_t,
                                const get_data_t *,
                                const gchar *,
                                report_summary_t);
int
report_scan_run_status (report_t, task_status_t*);

int
report_vuln_count (report_t);

char*
scan_end_time (report_t report);

char*
scan_start_time (report_t report);

#endif /* _GVMD_MANAGE_SQL_SCAN_REPORT_H */
