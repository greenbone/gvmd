/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Scan report summary and operations.
 */

#ifndef _GVMD_MANAGE_SCAN_REPORT_H
#define _GVMD_MANAGE_SCAN_REPORT_H

#include "manage.h"
#include "manage_report_common.h"

/**
 * @brief Result summary for a normal vulnerability report.
 *
 * Legacy report generation names are mapped as follows:
 *
 * holes    -> high
 * warnings -> medium
 * infos    -> low
 */
typedef struct
{
 report_count_t total;
 report_count_t critical;
 report_count_t high;
 report_count_t medium;
 report_count_t low;
 report_count_t log;
 report_count_t false_positive;

 report_severity_t severity;
} report_result_summary_t;

/**
 * @brief Structured model of a normal report.
 *
 * This model intentionally excludes:
 *
 * - delta report data
 * - audit and compliance data
 * - detailed results
 * - detailed hosts
 * - report export and report format data
 * - temporary report-rendering state
 */
struct scan_report_summary
{
 report_summary_base_t base;

 report_task_reference_t task;

 report_resource_summary_t resources;

 report_result_summary_t results;
};

typedef struct scan_report_summary* scan_report_summary_t;

/**
 * @brief Result of loading a structured report model.
 */
typedef enum
{
 MANAGE_GET_SCAN_REPORT_ERROR = -1,
 MANAGE_GET_SCAN_REPORT_SUCCESS = 0,
 MANAGE_GET_SCAN_REPORT_NOT_FOUND = 1,
 MANAGE_GET_SCAN_REPORT_FILTER_NOT_FOUND = 2,
 MANAGE_GET_SCAN_REPORT_UNSUPPORTED_TYPE = 3
} manage_get_scan_report_response_t;

scan_report_summary_t
scan_report_summary_new (void);

void
scan_report_summary_free (scan_report_summary_t);

manage_get_scan_report_response_t
manage_get_scan_report_summary (const get_data_t *,
                                scan_report_summary_t *);

#endif /* _GVMD_MANAGE_SCAN_REPORT_H */
