/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Scan Report summary and operations.
 */

#include "manage_scan_report.h"

#include "manage_filters.h"
#include "manage_settings.h"
#include "manage_sql_scan_report.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize a scan report summary.
 *
 * Allocates the scan report summary and initializes its shared base,
 * task reference, target reference, and resource summary structures.
 *
 * @return Newly allocated scan report summary.
 */
scan_report_summary_t
scan_report_summary_new (void)
{
  scan_report_summary_t summary;

  summary = g_malloc0 (sizeof (struct scan_report_summary));

  summary->base = report_summary_base_new ();

  summary->task = report_task_reference_new ();

  summary->resources = report_resource_summary_new ();

  return summary;
}

/**
 * @brief Free a report summary.
 *
 * @param[in] summary  Report summary to free.
 */
void
scan_report_summary_free (scan_report_summary_t summary)
{
  if (summary == NULL)
    return;

  report_summary_base_free (summary->base);
  report_task_reference_free (summary->task);
  report_resource_summary_free (summary->resources);

  g_free (summary);
}

/**
 * @brief Check whether a report is supported by GET_REPORT.
 *
 * GET_REPORT currently supports vulnerability reports only.
 * Audit reports are handled by a separate command.
 *
 * @param[in] report  Report resource.
 *
 * @return 0 if supported, 1 if unsupported, or -1 on error.
 */
static int
validate_get_report_usage_type (report_t report)
{
  task_t task = 0;
  gchar *usage_type = NULL;
  int ret;

  if (report == 0)
    return -1;

  ret = report_task (report, &task);
  if (ret)
    return -1;

  /*
   * A report without an associated task has no usage type to validate.
   */
  if (task == 0)
    return 0;

  ret = task_usage_type (task, &usage_type);
  if (ret)
    return -1;

  if (usage_type && strcmp (usage_type, "audit") == 0)
    {
      g_free (usage_type);
      return 1;
    }

  g_free (usage_type);

  return 0;
}


/**
 * @brief Validate and resolve controls needed by GET_REPORT.
 *
 * @param[in]  get       GET command data.
 * @param[out] controls  Resolved controls required by the report summary.
 *
 * @return 0 on success, 2 if the filter cannot be resolved, or -1 on error.
 */
static int
resolve_get_report_controls (const get_data_t *get,
                             get_report_controls_t *controls)
{
  gchar *term = NULL;
  gchar *sort_field = NULL;
  gchar *min_qod = NULL;
  gchar *levels = NULL;
  gchar *compliance_levels = NULL;
  gchar *delta_states = NULL;
  gchar *search_phrase = NULL;
  int first_result = 0;
  int max_results = 0;
  int sort_order = 0;
  int result_hosts_only = 0;
  int search_phrase_exact = 0;
  int notes = 0;
  int overrides = 0;
  int apply_overrides = 0;
  int ret;

  if (get == NULL || controls == NULL)
    return -1;

  controls->zone = NULL;

  ret = manage_report_filter_controls_from_get (
    get,
    &term,
    &first_result,
    &max_results,
    &sort_field,
    &sort_order,
    &result_hosts_only,
    NULL,
    &min_qod,
    &levels,
    &compliance_levels,
    &delta_states,
    &search_phrase,
    &search_phrase_exact,
    &notes,
    &overrides,
    &apply_overrides,
    &controls->zone);

  g_free (term);
  g_free (sort_field);
  g_free (min_qod);
  g_free (levels);
  g_free (compliance_levels);
  g_free (delta_states);
  g_free (search_phrase);

  return ret;
}

/**
 * @brief Load a structured vulnerability report summary.
 *
 * @param[in]  get          GET command data.
 * @param[out] summary      Loaded report summary.
 *
 * @return Status describing the result of the operation.
 */
manage_get_scan_report_response_t
manage_get_scan_report_summary (const get_data_t *get,
                                scan_report_summary_t *summary)
{
  get_report_controls_t controls = {0};
  scan_report_summary_t loaded_model = NULL;
  report_t report = 0;
  int ret;

  if (get == NULL
      || summary == NULL
      || get->id == NULL)
    return MANAGE_GET_SCAN_REPORT_ERROR;

  *summary = NULL;

  ret = find_report_with_permission (get->id,
                                     &report,
                                     "get_reports");

  if (ret)
    return MANAGE_GET_SCAN_REPORT_ERROR;

  if (report == 0)
    return MANAGE_GET_SCAN_REPORT_NOT_FOUND;

  ret = validate_get_report_usage_type (report);
  if (ret < 0)
    return MANAGE_GET_SCAN_REPORT_ERROR;

  if (ret > 0)
    return MANAGE_GET_SCAN_REPORT_UNSUPPORTED_TYPE;

  ret = resolve_get_report_controls (get, &controls);

  if (ret)
    {
      get_report_controls_cleanup (&controls);

      if (ret == 2)
        return MANAGE_GET_SCAN_REPORT_FILTER_NOT_FOUND;

      return MANAGE_GET_SCAN_REPORT_ERROR;
    }

  loaded_model = scan_report_summary_new ();

  ret = manage_sql_fill_report_summary (report,
                                        get,
                                        controls.zone,
                                        loaded_model);

  get_report_controls_cleanup (&controls);

  if (ret)
    {
      scan_report_summary_free (loaded_model);
      return MANAGE_GET_SCAN_REPORT_ERROR;
    }

  *summary = loaded_model;

  return MANAGE_GET_SCAN_REPORT_SUCCESS;
}
