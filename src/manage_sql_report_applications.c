/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report applications.
 *
 * SQL handlers for report application XML.
 */

#include "manage_sql_report_applications.h"

#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get the application name from a report app iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The application name of the report host detail. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_app_iterator_application_name, 0);

/**
 * @brief Get the host counts from a report app iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host counts of the report app. Caller must use only
 *         before calling cleanup_iterator.
 */
int
report_app_iterator_host_count (iterator_t *iterator)
{
  return iterator_int (iterator, 1);
}

/**
 * @brief Get the occurrences from a report app iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The occurrences of the report app. Caller must use only
 *         before calling cleanup_iterator.
 */
int
report_app_iterator_occurrences (iterator_t *iterator)
{
  return iterator_int (iterator, 2);
}

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 */
void
init_report_app_iterator (iterator_t *iterator, report_t report)
{
  init_ps_iterator (iterator,
                    "SELECT value AS app, count(*) AS hosts,"
                    " (SELECT  count(*) FROM report_host_details r"
                    " WHERE r.name = app_details.value AND r.report_host IN"
                    " (SELECT id FROM report_hosts WHERE report = $1)) AS occurrences"
                    " FROM report_host_details app_details"
                    " WHERE report_host IN"
                    " (SELECT id FROM report_hosts WHERE report = $1)"
                    " AND name = 'App'  GROUP BY value;",
                    SQL_RESOURCE_PARAM (report),
                    NULL);
}

/**
 * @brief Collect maximum severities for detected applications in a report.
 *
 * Builds a hash table that maps each detected application CPE to the maximum
 * severity found across all matching report results.
 *
 * @param[in]  get              Get request data.
 * @param[in]  report           Report to inspect.
 * @param[out] results          Result iterator.
 * @param[out] apps_severities  Hash table of CPE string to double* severity.
 *
* @return 0 on success, 1 failed to find result, 2 failed to find filter (filt_id),
 *         -1 error.
 */
int
fill_report_applications_severities (const get_data_t *get,
                                     report_t report,
                                     iterator_t *results,
                                     GHashTable **apps_severities)
{
  int ret;
  const char *port;
  char *detect_oid, *detect_ref, *detect_cpe, *detect_loc, *detect_name;
  result_t result;

  if (apps_severities == NULL)
    return -1;

  *apps_severities = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                            g_free);

  ret = init_result_get_iterator (results, get, report, NULL, NULL);
  if (ret)
    return ret;

  while (next (results))
    {
      double severity;
      double *stored_severity;
      char *key_copy;

      detect_oid = detect_ref = detect_cpe = detect_loc = detect_name = NULL;

      port = result_iterator_port (results);
      result = result_iterator_result (results);

      if (result_detection_reference (result,
                                      report,
                                      result_iterator_host (results),
                                      port,
                                      NULL,
                                      &detect_oid,
                                      &detect_ref,
                                      &detect_cpe,
                                      &detect_loc,
                                      &detect_name) == 0)
        {
          if (detect_cpe != NULL)
            {
              severity = result_iterator_severity_double (results);

              stored_severity = g_hash_table_lookup (*apps_severities,
                detect_cpe);

              if (stored_severity)
                {
                  if (severity > *stored_severity)
                    *stored_severity = severity;
                }
              else
                {
                  key_copy = g_strdup (detect_cpe);
                  double *new_severity = g_malloc (sizeof (double));
                  *new_severity = severity;
                  g_hash_table_insert (*apps_severities, key_copy,
                                       new_severity);
                }
            }
        }

      g_free (detect_oid);
      g_free (detect_ref);
      g_free (detect_cpe);
      g_free (detect_loc);
      g_free (detect_name);
    }

  return 0;
}
