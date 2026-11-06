/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured audit report summary loading.
 *
 * SQL-backed functions for filling a structured audit report summary.
 */

#include "manage_sql_audit_report.h"

#include "manage_sql_report_common.h"
#include "manage_sql_report_ports.h"
#include "manage_sql_settings.h"
#include "manage_sql_targets.h"
#include "manage_targets.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Fill full and filtered compliance counts.
 *
 * Compliance states are mapped directly to the legacy GMP response:
 *
 * - yes
 * - no
 * - incomplete
 * - undefined
 *
 * @param[in]     report             Report to inspect.
 * @param[in]     get                Result filtering information.
 * @param[in,out] summary            Audit report summary to fill.
 *
 * @return 0 on success, -1 on Error.
 */
static int
fill_audit_report_result_summary (
  report_t report,
  const get_data_t *get,
  audit_report_summary_t summary)
{
  int yes;
  int no;
  int incomplete;
  int undefined;

  int filtered_yes;
  int filtered_no;
  int filtered_incomplete;
  int filtered_undefined;
  int res;

  const gchar *levels;

  if (report == 0 || get == NULL || summary == NULL)
    return -1;

  levels = "yniu";

  yes = 0;
  no = 0;
  incomplete = 0;
  undefined = 0;

  filtered_yes = 0;
  filtered_no = 0;
  filtered_incomplete = 0;
  filtered_undefined = 0;
  res = -1;

  res = report_compliance_counts (
    report,
    get,
    &yes,
    &no,
    &incomplete,
    &undefined);

  if (res != 0)
    {
      g_warning ("%s: Failed to get compliance counts for report %lld",
                 __func__, report);
      return res;
    }

  res = report_compliance_f_counts (
    report,
    get,
    &filtered_yes,
    &filtered_no,
    &filtered_incomplete,
    &filtered_undefined);

  if (res != 0)
    {
      g_warning ("%s: Failed to get filtered compliance counts for report %lld",
                 __func__, report);
      return res;
    }

  summary->results.yes.full = yes;
  summary->results.yes.filtered =
    strchr (levels, 'y') ? filtered_yes : 0;

  summary->results.no.full = no;
  summary->results.no.filtered =
    strchr (levels, 'n') ? filtered_no : 0;

  summary->results.incomplete.full = incomplete;
  summary->results.incomplete.filtered =
    strchr (levels, 'i') ? filtered_incomplete : 0;

  summary->results.undefined.full = undefined;
  summary->results.undefined.filtered =
    strchr (levels, 'u') ? filtered_undefined : 0;

  summary->results.total.full =
    summary->results.yes.full
    + summary->results.no.full
    + summary->results.incomplete.full
    + summary->results.undefined.full;

  summary->results.total.filtered =
    summary->results.yes.filtered
    + summary->results.no.filtered
    + summary->results.incomplete.filtered
    + summary->results.undefined.filtered;

  g_free (summary->results.compliance.full);
  g_free (summary->results.compliance.filtered);

  summary->results.compliance.full =
    g_strdup (
      report_compliance_from_counts (
        &yes,
        &no,
        &incomplete,
        &undefined));

  summary->results.compliance.filtered =
    g_strdup (
      report_compliance_from_counts (
        &summary->results.yes.filtered,
        &summary->results.no.filtered,
        &summary->results.incomplete.filtered,
        &summary->results.undefined.filtered));

  return 0;
}

/**
 * @brief Fill a structured audit report summary.
 *
 * Loads report metadata, scan status, task information, target information,
 * resource counts, compliance counts and timezone data.
 *
 * @param[in]     report             Internal report resource.
 * @param[in]     get                Result filtering controls.
 * @param[in]     zone               Resolved request timezone, or NULL.
 * @param[in,out] summary            Allocated audit report summary to populate.
 *
 * @return 0 on success, or -1 on error.
 */
int
manage_sql_fill_audit_report_summary (
  report_t report,
  const get_data_t *get,
  const gchar *zone,
  audit_report_summary_t summary)
{
  int ret;

  if (report == 0 || get == NULL || summary == NULL)
    return -1;

  ret = fill_report_base (report, summary->base);
  if (ret)
    return ret;

  ret = fill_report_scan_information (report, summary->base);
  if (ret)
    return ret;

  ret = fill_report_task (report, summary->task);
  if (ret)
    return ret;

  ret = fill_report_target (
    summary->task ? summary->task->id : 0,
    summary->task ? summary->task->target : NULL);
  if (ret)
    return ret;

  ret = fill_report_resource_summary (
    report,
    get,
    summary->resources);
  if (ret)
    return ret;

  ret = fill_audit_report_result_summary (
    report,
    get,
    summary);
  if (ret)
    return ret;

  ret = fill_report_timezone (
    summary->base,
    zone);
  if (ret)
    return ret;

  return 0;
}
