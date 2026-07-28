/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Audit Report summary and operations.
 */

#include "manage_audit_report.h"

#include "manage_settings.h"
#include "manage_sql_audit_report.h"
#include "manage_sql_scan_report.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize an audit report summary.
 *
 * Allocates the scan report summary and initializes its shared base,
 * task reference, target reference, and resource summary structures.
 *
 * @return Newly allocated audit report summary.
 */
audit_report_summary_t
audit_report_summary_new (void)
{
  audit_report_summary_t summary;

  summary = g_malloc0 (sizeof (struct audit_report_summary));

  summary->base = report_summary_base_new ();

  summary->task = report_task_reference_new ();

  summary->resources = report_resource_summary_new ();

  return summary;
}

/**
 * @brief Free an audit report summary.
 *
 * @param[in] summary  Audit report summary to free.
 */
void
audit_report_summary_free (audit_report_summary_t summary)
{
  if (summary == NULL)
    return;

  report_summary_base_free (summary->base);
  report_task_reference_free (summary->task);
  report_resource_summary_free (summary->resources);

  g_free (summary->results.compliance.full);
  g_free (summary->results.compliance.filtered);

  g_free (summary);
}

/**
 * @brief Load a structured audit report summary.
 *
 * @param[in]  get          GET command data.
 * @param[out] summary      Loaded report summary.
 *
 * @return Status describing the result of the operation.
 */
manage_get_audit_report_response_t
manage_get_audit_report_summary (const get_data_t *get,
                                 audit_report_summary_t *summary)
{
  get_report_controls_t controls = {0};
  audit_report_summary_t loaded_summary = NULL;
  report_t report = 0;
  int ret;

  if (get == NULL
      || summary == NULL
      || get->id == NULL)
    return MANAGE_GET_AUDIT_REPORT_ERROR;

  *summary = NULL;

  ret = find_report_with_permission (get->id,
                                     &report,
                                     "get_reports");
  if (ret)
    return MANAGE_GET_AUDIT_REPORT_ERROR;

  if (report == 0)
    return MANAGE_GET_AUDIT_REPORT_NOT_FOUND;

  ret = validate_get_report_usage_type (report,
                                        REPORT_USAGE_TYPE_AUDIT);
  if (ret < 0)
    return MANAGE_GET_AUDIT_REPORT_ERROR;

  if (ret > 0)
    return MANAGE_GET_AUDIT_REPORT_UNSUPPORTED_TYPE;

  ret = resolve_get_report_controls (get, &controls);
  if (ret < 0)
    return MANAGE_GET_AUDIT_REPORT_ERROR;

  if (ret > 0)
    return MANAGE_GET_AUDIT_REPORT_FILTER_NOT_FOUND;

  loaded_summary = audit_report_summary_new ();

  ret = manage_sql_fill_audit_report_summary (report,
                                              get,
                                              controls.zone,
                                              loaded_summary);

  get_report_controls_cleanup (&controls);

  if (ret)
    {
      g_warning ("%s: Failed to load audit report summary for report %lld",
                 __func__, report);
      audit_report_summary_free (loaded_summary);
      return MANAGE_GET_AUDIT_REPORT_ERROR;
    }

  *summary = loaded_summary;

  return MANAGE_GET_AUDIT_REPORT_SUCCESS;
}
