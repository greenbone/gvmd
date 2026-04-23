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

#include "sql.h"

/**
 * @brief Get the cpe from a report os iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The cpe value of the report os. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_os_iterator_cpe, 0);

/**
 * @brief Get the best_os_txt from a report os iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The best_os_txt value of the report os. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_os_iterator_os_name, 1);

/**
 * @brief Get the host counts per OS from a report os iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host counts per OS of the report os. Caller must use only
 *         before calling cleanup_iterator.
 */
int
report_os_iterator_host_count (iterator_t *iterator)
{
  return iterator_int (iterator, 1);
}

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 */
void
init_report_os_iterator (iterator_t *iterator, report_t report)
{
  init_ps_iterator (
    iterator,
    "SELECT cpe.value AS cpe, txt.value AS os_name,"
    "       COUNT(DISTINCT rh.id) AS hosts"
    " FROM report_hosts rh"
    " LEFT JOIN report_host_details cpe"
    "  ON cpe.report_host = rh.id AND cpe.name = 'best_os_cpe'"
    " LEFT JOIN report_host_details txt"
    "  ON txt.report_host = rh.id AND txt.name = 'best_os_txt'"
    " WHERE rh.report = $1"
    " GROUP BY cpe.value, txt.value"
    " ORDER BY hosts DESC, os_name ASC;",
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
