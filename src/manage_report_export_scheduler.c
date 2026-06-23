/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_report_export_scheduler.h"

#include "gvmd_config.h"
#include "manage_integration_configs.h"
#include "manage_report_exports.h"
#include "sql.h"

#include <math.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


static int export_max_retries = 10; /* in seconds */
static int retry_base_delay = 10;   /* in seconds */
static int retry_multiplier = 2;    /* in seconds */
static int retry_max_delay = 600;   /* in seconds */
static int export_stale_threshold = 720;  /* in minutes */


/**
 * @brief  Load configuration values from gvmd config
 */
static void
init_report_export_from_config ()
{
  GKeyFile *kf = get_gvmd_config ();
  if (kf == NULL)
    {
      return;
    }

  gboolean has_max_retries = FALSE;
  int max_retries = 0;

  gboolean has_base_delay = FALSE;
  int base_delay = 0;

  gboolean has_multiplier = FALSE;
  int multiplier = 0;

  gboolean has_max_delay = FALSE;
  int max_delay = 0;

  gboolean has_stale_threshold = FALSE;
  int stale_threshold = 0;

  gvmd_config_get_int (kf, "security_intelligence_export", "max_retries",
                       &has_max_retries, &max_retries);
  gvmd_config_get_int (kf, "security_intelligence_export", "retry_base_delay",
                       &has_base_delay, &base_delay);
  gvmd_config_get_int (kf, "security_intelligence_export", "retry_multiplier",
                       &has_multiplier, &multiplier);
  gvmd_config_get_int (kf, "security_intelligence_export", "retry_max_delay",
                       &has_max_delay, &max_delay);
  gvmd_config_get_int (kf, "security_intelligence_export", "stale_threshold",
                       &has_stale_threshold, &stale_threshold);

  if (has_max_retries)
    {
      export_max_retries = max_retries;
      g_debug ("set export_max_retries from config: %d",
               export_max_retries);
    }

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

  if (has_stale_threshold)
    {
      export_stale_threshold = stale_threshold;
      g_debug ("set export_stale_threshold from config: %d",
               export_stale_threshold);
    }
}

static integration_config_data_t
read_report_export_integration_config ()
{
  iterator_t config_it;
  init_integration_config_iterator_one (
    &config_it, INTEGRATION_CONFIG_SECURITY_INTELLIGENCE_UUID);

  integration_config_data_t config = integration_config_data_new ();

  if (!next (&config_it))
    {
      g_debug ("%s: failed to find integration config '%s'", __func__,
               INTEGRATION_CONFIG_SECURITY_INTELLIGENCE_UUID);

      cleanup_iterator (&config_it);
      return NULL;
    }

  config->row_id = get_iterator_resource (&config_it);
  config->uuid = g_strdup (get_iterator_uuid (&config_it));
  config->owner = get_iterator_owner (&config_it);
  config->name = g_strdup (get_iterator_name (&config_it));
  config->comment = g_strdup (get_iterator_comment (&config_it));
  config->service_url =
    g_strdup (integration_config_iterator_service_url (&config_it));
  config->service_cacert =
    g_strdup (integration_config_iterator_service_cacert (&config_it));
  config->oidc_url =
    g_strdup (integration_config_iterator_oidc_url (&config_it));
  config->oidc_client_id =
    g_strdup (integration_config_iterator_oidc_client_id (&config_it));
  config->oidc_client_secret = g_strdup (
    integration_config_iterator_encrypted_oidc_client_secret (&config_it));
  config->creation_time = get_iterator_creation_time (&config_it);
  config->modification_time = get_iterator_modification_time (&config_it);

  cleanup_iterator (&config_it);
  return config;
}

/**
 * @brief  Finds stale exports, and sets their status to 'failed'.
 */
static void
reset_stale_report_exports ()
{
  int stale_threshold = 0;
  gvmd_config_resolve_int ("GVMD_REPORT_EXPORT_STALE_THRESHOLD", TRUE,
                           export_stale_threshold, &stale_threshold);

  const time_t threshold_timestamp = time (NULL) - (stale_threshold * 60);

  iterator_t report_exports;
  init_report_export_iterator_stale_exports (&report_exports,
                                             threshold_timestamp);

  sql_begin_immediate ();

  while (next (&report_exports))
    {
      report_t id = report_export_iterator_report_id (&report_exports);
      set_report_export_status_and_reason (id, REPORT_EXPORT_STATUS_FAILED,
                                           "Stale threshold has been exceeded");

      g_debug ("%s: found stale report export, report_id: %lld", __func__, id);
    }

  sql_commit ();

  cleanup_iterator (&report_exports);
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
 * @param  config       Integration config for OpenVAS Security Intelligence
 *                      export
 */
static void
process_report_export (report_t report, int retry_count,
                       integration_config_data_t config)
{
  set_report_export_status_and_reason (report, REPORT_EXPORT_STATUS_STARTED,
                                       NULL);

  export_report_result_t result = EXPORT_REPORT_RESULT_SUCCESS;
# if ENABLE_SECURITY_INTELLIGENCE_EXPORT
  /* Run the export */
  result =
    export_report_security_intelligence (report, config);
#endif
  gchar *reason = NULL;

  sql_begin_immediate ();

  if (result == EXPORT_REPORT_RESULT_SUCCESS)
    {
      set_report_export_status_and_reason (report,
                                           REPORT_EXPORT_STATUS_FINISHED, NULL);

      g_debug ("%s: report export finished, report: %lld", __func__, report);
    }
  else
    {
      if (result == EXPORT_REPORT_RESULT_TIMEOUT)
          reason = g_strdup ("The request has timed out");
      else if (result == EXPORT_REPORT_RESULT_TOKEN_GENERATION_FAILED)
        reason = g_strdup ("Could not generate access_token");

      set_report_export_status_and_reason (report, REPORT_EXPORT_STATUS_FAILED,
                                           reason);
      set_report_export_next_retry_time (
        report, calculate_next_retry_time (retry_count));
      set_report_export_retry_count (report, retry_count + 1);

      g_debug ("%s: report export failed, report: %lld, reason: %s", __func__,
               report, reason);
    }

  if (reason)
    {
      g_free (reason);
      reason = NULL;
    }

  sql_commit ();
}

/**
 * @brief  Iterates over due exports and calls process_report_export ()
 *         for each of them
 */
static void
run_due_exports ()
{
  int max_retry_count = 0;
  gvmd_config_resolve_int ("GVMD_REPORT_EXPORT_MAX_RETRIES", TRUE,
                           export_max_retries, &max_retry_count);

  integration_config_data_t integration_config =
    read_report_export_integration_config ();
  if (!integration_config)
    {
      g_warning (
        "%s: aborting exports, since integration config could not be read",
        __func__);
      return;
    }


  g_debug ("%s: iterating over due exports", __func__);

  iterator_t report_exports;
  init_report_export_iterator_due_exports (&report_exports, max_retry_count);
  while (next (&report_exports))
    {
      process_report_export (
        report_export_iterator_report_id (&report_exports),
        report_export_iterator_retry_count (&report_exports),
        integration_config);
    }

  cleanup_iterator (&report_exports);
  integration_config_data_free (integration_config);
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
  init_report_export_from_config ();

  reset_stale_report_exports ();

  run_due_exports ();

  return 0;
}
