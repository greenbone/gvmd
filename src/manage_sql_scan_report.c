/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured report summary loading.
 *
 * SQL-backed functions for filling a structured scan report summary.
 *
 * This module intentionally excludes:
 *
 * - delta report data
 * - audit and compliance data
 * - detailed results
 * - detailed hosts
 * - report export data
 */

#include "manage_sql_scan_report.h"

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
 * @brief Fill full and filtered result counts and severity.
 *
 * Legacy internal names are mapped as follows:
 *
 * - holes to high
 * - warnings to medium
 * - infos to low
 *
 * @param[in]     report  Report to inspect.
 * @param[in]     get     Result filtering information.
 * @param[in,out] summary   Report summary to fill.
 *
 * @return 0 on success, -1 on invalid input.
 */
static int
fill_report_result_summary (report_t report,
                            const get_data_t *get,
                            scan_report_summary_t summary)
{
  int criticals;
  int holes;
  int infos;
  int logs;
  int warnings;
  int false_positives;

  int filtered_criticals;
  int filtered_holes;
  int filtered_infos;
  int filtered_logs;
  int filtered_warnings;
  int filtered_false_positives;

  double full_severity;
  double filtered_severity;

  if (report == 0 || get == NULL || summary == NULL)
    return -1;

  criticals = 0;
  holes = 0;
  infos = 0;
  logs = 0;
  warnings = 0;
  false_positives = 0;

  filtered_criticals = 0;
  filtered_holes = 0;
  filtered_infos = 0;
  filtered_logs = 0;
  filtered_warnings = 0;
  filtered_false_positives = 0;

  full_severity = 0.0;
  filtered_severity = 0.0;

  /*
   * Verify the exact declaration of report_counts_id_full() in your branch.
   * This call follows the argument ordering used by print_report_xml_start().
   */
  report_counts_id_full (
    report,
    &criticals,
    &holes,
    &infos,
    &logs,
    &warnings,
    &false_positives,
    &full_severity,
    get,
    NULL,
    &filtered_criticals,
    &filtered_holes,
    &filtered_infos,
    &filtered_logs,
    &filtered_warnings,
    &filtered_false_positives,
    &filtered_severity);

  summary->results.critical.full = criticals;
  summary->results.critical.filtered = filtered_criticals;

  summary->results.high.full = holes;
  summary->results.high.filtered = filtered_holes;

  summary->results.medium.full = warnings;
  summary->results.medium.filtered = filtered_warnings;

  summary->results.low.full = infos;
  summary->results.low.filtered = filtered_infos;

  summary->results.log.full = logs;
  summary->results.log.filtered = filtered_logs;

  summary->results.false_positive.full = false_positives;
  summary->results.false_positive.filtered = filtered_false_positives;

  summary->results.total.full =
    criticals
    + holes
    + warnings
    + infos
    + logs
    + false_positives;

  summary->results.total.filtered =
    filtered_criticals
    + filtered_holes
    + filtered_warnings
    + filtered_infos
    + filtered_logs
    + filtered_false_positives;

  summary->results.severity.full = full_severity;
  summary->results.severity.filtered = filtered_severity;

  return 0;
}

/**
 * @brief Fill a structured normal report summary.
 *
 * Loads report metadata, scan status, task information, target information,
 * resource counts, result counts, severity and timezone data.
 *
 * @param[in]     report  Internal report resource.
 * @param[in]     get     Result filtering controls.
 * @param[in]     zone    Resolved request timezone, or NULL.
 * @param[in,out] summary   Allocated report summary to populate.
 *
 * @return 0 on success, or -1 on error.
 */
int
manage_sql_fill_report_summary (report_t report,
                                const get_data_t *get,
                                const gchar *zone,
                                scan_report_summary_t summary)
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

  ret = fill_report_resource_summary (report, get, summary->resources);
  if (ret)
    return ret;

  ret = fill_report_result_summary (report, get, summary);
  if (ret)
    return ret;

  ret = fill_report_timezone (summary->base, zone);
  if (ret)
    return ret;

  return 0;
}
