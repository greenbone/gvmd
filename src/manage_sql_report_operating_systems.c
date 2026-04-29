/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report operating systems.
 *
 * SQL handlers for report operating system XML.
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

#include "manage_sql_report_operating_systems.h"

#include "manage.h"
#include "sql.h"

/**
 * @brief Get the report host matching result host information.
 *
 * @param[in]  report    Report containing the result.
 * @param[in]  host      Host value from the result.
 * @param[in]  hostname  Hostname value from the result.
 *
 * @return Related report host on success, or 0 if not found.
 */
static report_host_t
result_report_host (report_t report, const char *host, const char *hostname)
{
  if (report == 0)
    return 0;

  if (host && *host)
    {
      return sql_int_ps (
        "SELECT id"
        " FROM report_hosts"
        " WHERE report = $1"
        "   AND host = $2"
        " LIMIT 1;",
        SQL_RESOURCE_PARAM (report),
        SQL_STR_PARAM (host),
        NULL);
    }

  if (hostname && *hostname)
    {
      return sql_int_ps (
        "SELECT id"
        " FROM report_hosts"
        " WHERE report = $1"
        "   AND hostname = $2"
        " LIMIT 1;",
        SQL_RESOURCE_PARAM (report),
        SQL_STR_PARAM (hostname),
        NULL);
    }

  return 0;
}

/**
 * @brief Get the cpe from a report os iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The cpe value of the report os. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_os_iterator_cpe, 1);

/**
 * @brief Get the best_os_txt from a report os iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The best_os_txt value of the report os. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_os_iterator_os_name, 2);

/**
 * @brief Get the report_host_id per OS from a report os iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host counts per OS of the report os. Caller must use only
 *         before calling cleanup_iterator.
 */
report_host_t
report_os_iterator_report_host_id (iterator_t *iterator)
{
  return iterator_int (iterator, 0);
}

void
init_report_os_iterator (iterator_t *iterator, report_t report)
{
  init_ps_iterator (
    iterator,
    "SELECT rh.id AS report_host_id, "
    "       (SELECT value FROM report_host_details "
    "         WHERE report_host = rh.id AND name = 'best_os_cpe'"
    "         LIMIT 1) AS cpe, "
    "       (SELECT value FROM report_host_details"
    "         WHERE report_host = rh.id AND name = 'best_os_txt'"
    "         LIMIT 1) AS os_name"
    " FROM report_hosts rh"
    " WHERE rh.report = $1;",
    SQL_RESOURCE_PARAM (report),
    NULL);
}

/**
 * @brief Get the number of distinct operating systems in a report.
 *
 * Counts distinct OS CPE values across all hosts in the report.
 *
 * @param[in]  report  Report whose operating systems to count.
 *
 * @return Number of distinct operating systems on success, or -1 on error.
 */
int
report_operating_systems_count (report_t report)
{
  return sql_int_ps (
    "SELECT count(DISTINCT value)"
    " FROM report_host_details"
    " WHERE report_host IN (SELECT id FROM report_hosts WHERE report = $1)"
    "   AND name = 'best_os_cpe';",
    SQL_RESOURCE_PARAM (report),
    NULL);
}

/**
 * @brief Initialize the result iterator and collect distinct report host IDs.
 *
 * @param[out] report_host_ids  Hash table used as a set of report host IDs.
 * @param[in]  get              Request data used for iterator initialization.
 * @param[in]  report           Report identifier.
 * @param[in,out] results       Result iterator to use.
 *
 * @return 0 on success, non-zero on failure.
 */
int
fill_filtered_report_host_ids (GHashTable **report_host_ids,
                               const get_data_t *get,
                               report_t report,
                               iterator_t *results)
{
  int ret;

  if (report_host_ids == NULL)
    return -1;

  *report_host_ids = g_hash_table_new (g_direct_hash, g_direct_equal);

  ret = init_result_get_iterator (results, get, report, NULL, NULL);
  if (ret)
    {
      g_hash_table_destroy (*report_host_ids);
      *report_host_ids = NULL;
      return ret;
    }

  while (next (results))
    {
      report_host_t report_host;
      report_host = result_report_host (report,
                                        result_iterator_host (results),
                                        result_iterator_hostname (results));

      if (report_host)
        g_hash_table_add (*report_host_ids, GSIZE_TO_POINTER (report_host));
    }

  return 0;
}
