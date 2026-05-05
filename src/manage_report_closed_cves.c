/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report closed CVEs.
 *
 * Non-SQL report closed CVEs code for the GVM management layer.
 */

#include "manage_report_closed_cves.h"
#include "manage_sql_report_closed_cves.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize a new report closed CVE.
 *
 * @return Newly allocated report closed CVE.
 */
report_closed_cve_t
report_closed_cve_new (void)
{
  return (report_closed_cve_t) g_malloc0 (sizeof (struct report_closed_cve));
}

/**
 * @brief Free a report closed CVE.
 *
 * @param[in] closed_cve  Report closed CVE to free.
 */
void
report_closed_cve_free (report_closed_cve_t closed_cve)
{
  if (closed_cve == NULL)
    return;

  g_free (closed_cve->host);
  g_free (closed_cve->cve);
  g_free (closed_cve->oid);
  g_free (closed_cve->nvt_name);
  g_free (closed_cve);
}

/**
 * @brief Create a new report closed CVE list.
 *
 * @return Newly allocated closed CVE list.
 */
GPtrArray *
report_closed_cve_list_new (void)
{
  return g_ptr_array_new_with_free_func (
    (GDestroyNotify) report_closed_cve_free);
}

/**
 * @brief Free a report closed CVE list.
 *
 * @param[in] closed_cves  Closed CVE list to free.
 */
void
report_closed_cve_list_free (GPtrArray *closed_cves)
{
  if (closed_cves == NULL)
    return;

  g_ptr_array_free (closed_cves, TRUE);
}

/**
 * @brief Get closed CVEs for a report.
 *
 * @param[in]  report           Report to process.
 * @param[out] closed_cve_list  Closed CVE list to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
get_report_closed_cves (report_t report,
                        GPtrArray **closed_cve_list)
{
  iterator_t closed_cves;

  if (closed_cve_list == NULL)
    return -1;

  *closed_cve_list = report_closed_cve_list_new ();

  init_report_closed_cve_iterator (&closed_cves, report);

  while (next (&closed_cves))
    {
      report_closed_cve_t closed_cve;

      closed_cve = report_closed_cve_new ();

      closed_cve->host = g_strdup (
        report_closed_cve_iterator_host (&closed_cves));
      closed_cve->cve = g_strdup (
        report_closed_cve_iterator_cve (&closed_cves));
      closed_cve->oid = g_strdup (
        report_closed_cve_iterator_oid (&closed_cves));
      closed_cve->nvt_name = g_strdup (
        report_closed_cve_iterator_nvt_name (&closed_cves));
      closed_cve->severity_double = report_closed_cve_iterator_severity_double (
        &closed_cves);

      g_ptr_array_add (*closed_cve_list, closed_cve);
    }

  cleanup_iterator (&closed_cves);
  return 0;
}
