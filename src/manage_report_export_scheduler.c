/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_report_export_scheduler.h"

#include "gvmd_config.h"
#include "manage_report_exports.h"
#include "sql.h"

#include <math.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


static int retry_base_delay = 10;
static int retry_multiplier = 2;
static int retry_max_delay = 600;

/**
 * @brief  Load configuration values from gvmd config
 */
void
init_report_export_scheduler_from_config ()
{
  GKeyFile *kf = get_gvmd_config ();
  if (kf == NULL)
    {
      return;
    }

  gboolean has_base_delay = FALSE;
  int base_delay = 0;

  gboolean has_multiplier = FALSE;
  int multiplier = 0;

  gboolean has_max_delay = FALSE;
  int max_delay = 0;

  gvmd_config_get_int (kf, "security_intelligence_export", "retry_base_delay",
                       &has_base_delay, &base_delay);

  gvmd_config_get_int (kf, "security_intelligence_export", "retry_multiplier",
                       &has_multiplier, &multiplier);

  gvmd_config_get_int (kf, "security_intelligence_export", "retry_max_delay",
                       &has_max_delay, &max_delay);

  if (has_base_delay)
    {
      retry_base_delay = base_delay;
      g_debug ("set retry_base_delay from config: %d", retry_base_delay);
    }

  if (has_multiplier)
    {
      retry_multiplier = multiplier;
      g_debug ("set retry_multiplier from config: %d", retry_multiplier);
    }

  if (has_max_delay)
    {
      retry_max_delay = max_delay;
      g_debug ("set retry_max_delay from config: %d", retry_max_delay);
    }
}

/**
 * @brief  Calculates the timestamp for next_retry_time
 *
 * @param  retry_count  The amount of retry attempts so far (can be 0)
 *
 * @return The timestamp for when the next export attempt should be run
 */
static time_t
calculate_next_retry_time (const int retry_count)
{
  int base_delay = 0;
  int multiplier = 0;
  int max_delay = 0;

  gvmd_config_resolve_int ("GVMD_REPORT_EXPORT_RETRY_BASE_DELAY", TRUE,
                           retry_base_delay, &base_delay);
  gvmd_config_resolve_int ("GVMD_REPORT_EXPORT_RETRY_MULTIPLIER", TRUE,
                           retry_multiplier, &multiplier);
  gvmd_config_resolve_int ("GVMD_REPORT_EXPORT_RETRY_MAX_DELAY", TRUE,
                           retry_max_delay, &max_delay);

  return time (NULL)
         + MIN (base_delay * (long) pow (multiplier, retry_count), max_delay);
}

/**
 * @brief  Process a single report, which is due for export.
 *         Used to separate iterating over all reports from the handling
 *         of the export.
 *
 * @param  report       The report ID
 * @param  retry_count  The current retry count for the given report
 */
static void
process_report_export (report_t report, int retry_count)
{
  set_report_export_status_and_reason (report, REPORT_EXPORT_STATUS_STARTED,
                                       NULL);

  /* Run the export */
  export_report_result_t result = export_report (report);
  gchar *reason = NULL;

  sql_begin_immediate ();

  switch (result)
    {
    case EXPORT_REPORT_RESULT_SUCCESS:
      set_report_export_status_and_reason (report,
                                           REPORT_EXPORT_STATUS_FINISHED, NULL);

      g_debug ("%s: report export finished, report: %lld", __func__, report);

      break;
    case EXPORT_REPORT_RESULT_TIMEOUT:
      reason = g_strdup ("The request has timed out");
    case EXPORT_REPORT_RESULT_FAILURE:
      set_report_export_status_and_reason (report, REPORT_EXPORT_STATUS_FAILED,
                                           reason);
      set_report_export_next_retry_time (
        report, calculate_next_retry_time (retry_count));
      set_report_export_retry_count (report, retry_count + 1);

      g_debug ("%s: report export failed, report: %lld, reason: %s", __func__,
               report, reason);
      break;
    }

  if (reason)
    {
      g_free (reason);
      reason = NULL;
    }

  sql_commit ();
}

/**
 * @brief  Run report export scheduler, which fetches all due exports
 *         and tries to export them accordingly
 *
 * @return 0 on success, -1 on failure
 */
int
manage_report_export_scheduler ()
{
  iterator_t report_exports;

  init_report_exports_from_config ();
  init_report_export_scheduler_from_config ();

  g_debug ("%s: iterating over due exports", __func__);
  init_report_export_iterator_due_exports (&report_exports);

  while (next (&report_exports))
    {
      process_report_export (
        report_export_iterator_report_id (&report_exports),
        report_export_iterator_retry_count (&report_exports));
    }

  cleanup_iterator (&report_exports);
  return 0;
}

/**
 * @brief  Export a single report to security intelligence
 *
 * @param  report  The report to export
 *
 * @return EXPORT_REPORT_RESULT_SUCCESS on success
 *         EXPORT_REPORT_RESULT_TIMEOUT when the request has timed out
 *         EXPORT_REPORT_RESULT_FAILURE on failure
 */
export_report_result_t
export_report (report_t report)
{
  (void) report;
  g_debug ("%s: exporting report %lld", __func__, report);

  return EXPORT_REPORT_RESULT_FAILURE;
}
