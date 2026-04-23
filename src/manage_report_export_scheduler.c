/* Copyright (C) 2025 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_report_export_scheduler.h"

#include "gvmd_config.h"
#include "manage_report_exports.h"

#include <math.h>


static int retry_base_delay = 10;
static int retry_multiplier = 2;
static int retry_max_delay = 600;


/**
 * @brief Load configuration values from gvmd config
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
 * @brief  Run report export scheduler, which fetches all due exports
 *         and tries to export them accordingly
 *
 * @return 0 on success, -1 on failure
 */
int
manage_report_export_scheduler ()
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


  iterator_t it;

  g_debug ("%s: iterating over due exports", __func__);
  init_report_export_iterator_due_exports (&it);

  while (next (&it))
    {
      report_t report = report_export_iterator_report_id (&it);
      set_report_export_status_and_reason (report, REPORT_EXPORT_STATUS_STARTED,
                                           NULL);

      g_debug ("%s: exporting report %lld", __func__, report);
      export_report_result_t result = export_report (report, 0, NULL);
      int retry_count = 0, delay = 0;

      switch (result)
        {
        case EXPORT_REPORT_RESULT_SUCCESS:
          set_report_export_status_and_reason (
            report, REPORT_EXPORT_STATUS_FINISHED, NULL);

          g_debug ("%s: report export finished, report: %lld", __func__,
                   report);

          continue;
        case EXPORT_REPORT_RESULT_FAILURE:
          retry_count = report_export_iterator_retry_count (&it);
          delay = MIN (base_delay * powl (multiplier, retry_count), max_delay);

          set_report_export_status_and_reason (
            report, REPORT_EXPORT_STATUS_FAILED, NULL);
          set_report_export_next_retry_time (report, time (NULL) + delay);
          set_report_export_retry_count (report, retry_count + 1);

          g_debug ("%s: report export failed, report: %lld, retry_count: %d, "
                   "delay: %d",
                   __func__, report, retry_count, delay);

          continue;
        }
    }

  cleanup_iterator (&it);

  return 0;
}

/**
 * @brief  Export a single report to security intelligence
 *
 * @param report  The report to export
 *
 * @return EXPORT_REPORT_RESULT_SUCCESS on success
 *         EXPORT_REPORT_RESULT_FAILURE on failure
 */
export_report_result_t
export_report (report_t report, int TODO, const char* MORE_TODO)
{
  (void)report;
  (void)TODO;
  (void)MORE_TODO;

  return rand () % 2 == 0 ? EXPORT_REPORT_RESULT_SUCCESS
                          : EXPORT_REPORT_RESULT_FAILURE;
}
