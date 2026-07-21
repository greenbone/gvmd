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

/**
 * @brief Full and filtered values for a report count.
 */
typedef struct
{
 int full;
 int filtered;
} report_count_t;

/**
 * @brief Full and filtered report severity.
 */
typedef struct
{
 double full;
 double filtered;
} report_severity_t;

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
 * @brief Resource counts belonging to a report.
 */
struct report_resource_summary
{
 int hosts;
 int ports;
 int applications;
 int operating_systems;
 int vulnerabilities;
 int cves;
 int closed_cves;
 int tls_certificates;
 int errors;
};

typedef struct report_resource_summary* report_resource_summary_t;

/**
 * @brief Type of resource scanned by the report task.
 */
typedef enum
{
 REPORT_TARGET_TYPE_NONE = 0,
 REPORT_TARGET_TYPE_TARGET,
 REPORT_TARGET_TYPE_OCI_IMAGE,
 REPORT_TARGET_TYPE_WEB_APPLICATION,
 REPORT_TARGET_TYPE_AGENT_GROUP,
 REPORT_TARGET_TYPE_IMPORT
} report_target_type_t;

/**
 * @brief Reference to the resource scanned by a report task.
 */
struct report_target_reference
{
 report_target_type_t type;

 resource_t id;
 gchar* uuid;
 gchar* name;
 gchar* comment;

 int in_trash;
};

typedef struct report_target_reference* report_target_reference_t;

/**
 * @brief Reference to the task associated with a report.
 */
struct report_task_reference
{
 task_t id;
 gchar* uuid;
 gchar* name;
 gchar* comment;
 gchar* usage_type;
 int progress;

 report_target_reference_t target;
};

typedef struct report_task_reference* report_task_reference_t;

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
struct report_summary
{
 report_t report;
 user_t owner;

 gchar* id;
 gchar* name;
 gchar* comment;
 gchar* owner_name;

 time_t creation_time;
 time_t modification_time;

 gchar* timestamp;
 gchar* scan_start;
 gchar* scan_end;
 task_status_t scan_run_status;
 gchar* scan_run_status_str;

 gchar* timezone;
 gchar* timezone_abbrev;

 report_task_reference_t task;

 report_resource_summary_t resources;
 report_result_summary_t results;
};

typedef struct report_summary* report_summary_t;

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

report_summary_t
report_summary_new (void);

void
report_summary_free (report_summary_t);

manage_get_scan_report_response_t
manage_get_scan_report_summary (const gchar *, const get_data_t *,
                                report_summary_t *);

const gchar *
report_target_type_to_string (report_target_type_t);

#endif /* _GVMD_MANAGE_SCAN_REPORT_H */
