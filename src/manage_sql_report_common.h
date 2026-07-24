/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured common report summary loading.
 */
#ifndef _GVM_MANAGE_SQL_REPORT_COMMON_H
#define _GVM_MANAGE_SQL_REPORT_COMMON_H

#include "manage_report_common.h"

int
report_scan_run_status (report_t, task_status_t*);

int
report_vuln_count (report_t);

char*
scan_end_time (report_t report);

char*
scan_start_time (report_t report);

int
fill_report_base (report_t, report_summary_base_t);

int
fill_report_scan_information (report_t, report_summary_base_t);

int
fill_report_resource_summary (report_t, const get_data_t *,
                              report_resource_summary_t);

int
fill_report_task (report_t, report_task_reference_t);

int
fill_report_target (task_t, report_target_reference_t);

int
fill_report_timezone (report_summary_base_t, const gchar *);

#endif //_GVM_MANAGE_SQL_REPORT_COMMON_H
