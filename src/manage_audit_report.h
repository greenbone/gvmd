/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Audit report summary and operations.
 */

#ifndef _GVMD_MANAGE_AUDIT_REPORT_H
#define _GVMD_MANAGE_AUDIT_REPORT_H

#include "manage_report_common.h"

/**
 * @brief Full and filtered compliance values for an audit report.
 */
typedef struct
{
  gchar *full;
  gchar *filtered;
} audit_report_compliance_t;

/**
 * @brief Result summary for an audit report.
 */
typedef struct
{
  report_count_t total;
  report_count_t yes;
  report_count_t no;
  report_count_t incomplete;
  report_count_t undefined;

  audit_report_compliance_t compliance;
} audit_report_result_summary_t;

/**
 * @brief Structured summary of an audit report.
 */
struct audit_report_summary
{
  report_summary_base_t base;
  report_task_reference_t task;
  report_resource_summary_t resources;

  audit_report_result_summary_t results;
};

typedef struct audit_report_summary *audit_report_summary_t;

/**
 * @brief Result of loading an audit report summary.
 */
typedef enum
{
  MANAGE_GET_AUDIT_REPORT_ERROR = -1,
  MANAGE_GET_AUDIT_REPORT_SUCCESS = 0,
  MANAGE_GET_AUDIT_REPORT_NOT_FOUND = 1,
  MANAGE_GET_AUDIT_REPORT_FILTER_NOT_FOUND = 2,
  MANAGE_GET_AUDIT_REPORT_UNSUPPORTED_TYPE = 3
} manage_get_audit_report_response_t;

audit_report_summary_t
audit_report_summary_new (void);

void
audit_report_summary_free (audit_report_summary_t);

manage_get_audit_report_response_t
manage_get_audit_report_summary (const get_data_t *,
                                 audit_report_summary_t *);

#endif /* _GVMD_MANAGE_AUDIT_REPORT_H */
