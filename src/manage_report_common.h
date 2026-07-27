/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report common operations.
 */


#ifndef _GVM_MANAGE_REPORT_COMMON_H
#define _GVM_MANAGE_REPORT_COMMON_H

#include "manage.h"

/**
 * @brief Controls derived from GET data for GET_%s_REPORT.
 */
typedef struct
{
 gchar *zone;
} get_report_controls_t;

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
 * @brief Common metadata shared by scan and audit report summaries.
 */
struct report_summary_base
{
 report_t report;
 user_t owner;

 gchar *id;
 gchar *name;
 gchar *comment;
 gchar *owner_name;

 time_t creation_time;
 time_t modification_time;

 gchar *timestamp;
 gchar *scan_start;
 gchar *scan_end;

 task_status_t scan_run_status;
 gchar *scan_run_status_str;

 gchar *timezone;
 gchar *timezone_abbrev;
};

/**
* @brief Usage type of a report,
*        used to validate the report type for GET_%s_REPORT.
*/
typedef enum
{
 REPORT_USAGE_TYPE_SCAN = 0,
 REPORT_USAGE_TYPE_AUDIT = 1
} report_usage_type_t;

typedef struct report_summary_base *report_summary_base_t;

report_summary_base_t
report_summary_base_new (void);

void
report_summary_base_free (report_summary_base_t);

report_task_reference_t
report_task_reference_new (void);

void
report_task_reference_free (report_task_reference_t);

report_resource_summary_t
report_resource_summary_new (void);

void
report_resource_summary_free (report_resource_summary_t);

void
get_report_controls_cleanup (get_report_controls_t *);

const gchar *
report_target_type_to_string (report_target_type_t);

int
validate_get_report_usage_type (report_t, report_usage_type_t);

int
resolve_get_report_controls (const get_data_t *,
                             get_report_controls_t *);

#endif //_GVM_MANAGE_REPORT_COMMON_H
