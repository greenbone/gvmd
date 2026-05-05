/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report closed CVEs.
 *
 * SQL handlers for report closed CVE XML.
 */

#include "manage_sql_report_closed_cves.h"

#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get the host from a report closed CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The host of the report host detail. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_closed_cve_iterator_host, 0);

/**
 * @brief Get the cve from a report closed CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The cve of the nvts table. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_closed_cve_iterator_cve, 1);

/**
 * @brief Get the oid from a report closed CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The oid of the nvts table. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_closed_cve_iterator_oid, 2);

/**
 * @brief Get the nvt name from a report closed CVE iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The nvt name of the nvts table. Caller must use only
 *         before calling cleanup_iterator.
 */
DEF_ACCESS (report_closed_cve_iterator_nvt_name, 3);

/**
 * @brief Get the severity from report closed CVE iterator as double.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The severity of the closed CVE.  Caller must only use before calling
 *         cleanup_iterator.
 */
double
report_closed_cve_iterator_severity_double (iterator_t *iterator)
{
  if (iterator->done)
    return 0.0;

  return iterator_double (iterator, 4);
}

/**
 * @brief Initialise a report closed CVEs iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose closed CVEs the iterator loops over.
 */
void
init_report_closed_cve_iterator (iterator_t *iterator, report_t report)
{
  init_ps_iterator (iterator,
                    "SELECT DISTINCT rh.host,"
                    "       trim(split_cve) AS cve,"
                    "       nvts.oid,"
                    "       nvts.name,"
                    "       nvts.cvss_base"
                    " FROM report_hosts rh"
                    " JOIN report_host_details rhd"
                    "   ON rhd.report_host = rh.id"
                    " JOIN nvts"
                    "   ON nvts.oid = rhd.source_name"
                    " CROSS JOIN LATERAL regexp_split_to_table(nvts.cve, ',')"
                    " AS split_cve"
                    " WHERE rh.report = $1"
                    "   AND rhd.name = 'EXIT_CODE'"
                    "   AND rhd.value = 'EXIT_NOTVULN'"
                    "   AND nvts.cve != ''"
                    "   AND nvts.family IN (" LSC_FAMILY_LIST ")",
                    SQL_RESOURCE_PARAM (report),
                    NULL);
}

/**
 * @brief Count a report's total number of closed CVEs.
 *
 * @param[in]  report  Report.
 *
 * @return Closed CVE count.
 */
int
report_closed_cve_count (report_t report)
{
  return sql_int_ps (
    "SELECT COUNT(*)"
    " FROM ("
    "   SELECT DISTINCT rh.host, trim(split_cve) AS cve"
    "   FROM report_hosts rh"
    "   JOIN report_host_details rhd"
    "     ON rhd.report_host = rh.id"
    "   JOIN nvts n"
    "     ON n.oid = rhd.source_name"
    "   CROSS JOIN LATERAL regexp_split_to_table(n.cve, ',')"
    "   AS split_cve"
    "   WHERE rh.report = $1"
    "     AND rhd.name = 'EXIT_CODE'"
    "     AND rhd.value = 'EXIT_NOTVULN'"
    "     AND n.cve != ''"
    "     AND n.family IN (" LSC_FAMILY_LIST ")"
    " );",
    SQL_RESOURCE_PARAM (report),
    NULL);
}
