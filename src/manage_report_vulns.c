/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report Vulnerabilities.
 *
 * Non-SQL report Vulnerabilities code for the GVM management layer.
 */

#include "manage_report_vulns.h"

#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create a new report Vulnerability object.
 *
 * @return Newly allocated report Vulnerability object.
 */
report_vuln_t
report_vuln_new (void)
{
  report_vuln_t cve;

  cve = g_malloc0 (sizeof (struct report_vuln));

  cve->nvt_cves = g_ptr_array_new_with_free_func (g_free);

  return cve;
}

/**
 * @brief Free a report Vulnerability object.
 *
 * @param[in] vuln Report Vulnerability object to free.
 */
void
report_vuln_free (report_vuln_t vuln)
{
  if (vuln == NULL)
    return;

  g_free (vuln->nvt_name);
  g_free (vuln->nvt_oid);

  if (vuln->nvt_cves)
    g_ptr_array_free (vuln->nvt_cves, TRUE);

  g_free (vuln);
}

/**
 * @brief Create a new report Vulnerability list.
 *
 * @return Newly allocated report Vulnerability list.
 */
GPtrArray *
report_vuln_list_new (void)
{
  return g_ptr_array_new_with_free_func ((GDestroyNotify) report_vuln_free);
}

/**
 * @brief Free a report Vulnerability list.
 *
 * @param[in] vulns Report Vulnerability list to free.
 */
void
report_vuln_list_free (GPtrArray *vulns)
{
  if (vulns == NULL)
    return;

  g_ptr_array_free (vulns, TRUE);
}

/**
 * @brief Check whether a VT reference is a CVE reference.
 *
 * @param[in] ref VT reference to check.
 *
 * @return TRUE if the reference type is "cve", FALSE otherwise.
 */
static gboolean
vtref_is_cve (vtref_t *ref)
{
  return g_strcmp0 (vtref_type (ref), "cve") == 0;
}

/**
 * @brief Add all CVE references from an NVT to a report Vulnerability object.
 *
 * @param[in,out] vuln   Report Vulnerability object to update.
 * @param[in]     nvti  NVT information containing VT references.
 */
static void
report_vuln_add_nvt_cves (report_vuln_t vuln, nvti_t *nvti)
{
  int i;

  if (vuln == NULL || nvti == NULL)
    return;

  for (i = 0; i < nvti_vtref_len (nvti); i++)
    {
      vtref_t *ref;
      const gchar *id;

      ref = nvti_vtref (nvti, i);

      if (!vtref_is_cve (ref))
        continue;

      id = vtref_id (ref);
      if (id == NULL)
        id = "";

      g_ptr_array_add (vuln->nvt_cves, g_strdup (id));
    }
}

/**
 * @brief Create a report Vulnerability object from the current result.
 *
 * @param[in] results Result iterator positioned at the current result.
 * @param[in] nvti    NVT information for the current result.
 *
 * @return Newly allocated report Vulnerability object.
 */
static report_vuln_t
report_vuln_from_result (iterator_t *results, nvti_t *nvti)
{
  report_vuln_t vuln;
  const char *oid;

  oid = result_iterator_nvt_oid (results);

  vuln = report_vuln_new ();
  vuln->nvt_name = g_strdup (result_iterator_nvt_name (results));
  vuln->nvt_oid = g_strdup (oid);
  vuln->severity_double = result_iterator_severity_double (results);

  report_cve_add_nvt_cves (vuln, nvti);

  return vuln;
}

/**
 * @brief Look up or create the host set for an NVT OID.
 *
 * @param[in,out] hosts_by_oid Hash table mapping NVT OIDs to host sets.
 * @param[in]     oid          NVT OID.
 *
 * @return Host set for the given NVT OID.
 */
static GHashTable *
lookup_or_create_host_set (GHashTable *hosts_by_oid, const char *oid)
{
  GHashTable *hosts;

  hosts = g_hash_table_lookup (hosts_by_oid, oid);

  if (hosts == NULL)
    {
      hosts = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
      g_hash_table_insert (hosts_by_oid, g_strdup (oid), hosts);
    }

  return hosts;
}

/**
 * @brief Add a host to a report Vulnerability object if it was not counted yet.
 *
 * @param[in,out] vuln          Report Vulnerability object to update.
 * @param[in,out] hosts_by_oid  Hash table mapping NVT OIDs to host sets.
 * @param[in]     oid           NVT OID.
 * @param[in]     host          Host identifier.
 */
static void
report_cve_add_host_once (report_vuln_t vuln,
                          GHashTable *hosts_by_oid,
                          const char *oid,
                          const char *host)
{
  GHashTable *hosts;

  if (vuln == NULL || hosts_by_oid == NULL || oid == NULL || host == NULL)
    return;

  hosts = lookup_or_create_host_set (hosts_by_oid, oid);

  if (!g_hash_table_contains (hosts, host))
    {
      g_hash_table_insert (hosts, g_strdup (host), GINT_TO_POINTER (1));
      vuln->hosts_count++;
    }
}

/**
 * @brief Look up or create a report Vulnerability object for the current result.
 *
 * @param[in,out] vulns_by_oid Hash table mapping NVT OIDs to report CVEs.
 * @param[in,out] report_vulns Report Vulnerability list to update.
 * @param[in]     results      Result iterator positioned at the current result.
 * @param[in]     nvti         NVT information for the current result.
 *
 * @return Report Vulnerability object for the current NVT OID.
 */
static report_vuln_t
lookup_or_create_report_vuln (GHashTable *vulns_by_oid,
                             GPtrArray *report_vulns,
                             iterator_t *results,
                             nvti_t *nvti)
{
  const gchar *oid;
  report_vuln_t cve;

  oid = result_iterator_nvt_oid (results);

  cve = g_hash_table_lookup (vulns_by_oid, oid);

  if (cve == NULL)
    {
      cve = report_cve_from_result (results, nvti);

      g_ptr_array_add (report_vulns, cve);

      /* Key is owned by vulnerability itself. */
      g_hash_table_insert (vulns_by_oid, cve->nvt_oid, cve);
    }

  return cve;
}

/**
 * @brief Get Vulnerabilities for a report with aggregated host and occurrence counts.
 *
 * @param[in]  report        Report to process.
 * @param[in]  get           Report filter and pagination data.
 * @param[out] report_vulns  Report Vulnerability list to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
get_report_vulns (report_t report,
                 const get_data_t *get,
                 GPtrArray **report_vulns)
{
  iterator_t results;
  GHashTable *vulns_by_oid;
  GHashTable *hosts_by_oid;

  if (report_vulns == NULL)
    return -1;

  *report_vulns = report_vuln_list_new ();

  vulns_by_oid = g_hash_table_new (g_str_hash, g_str_equal);

  hosts_by_oid = g_hash_table_new_full (
    g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_hash_table_destroy);

  init_result_get_iterator (&results, get, report, NULL, NULL);

  while (next (&results))
    {
      const gchar *oid;
      const gchar *host;
      nvti_t *nvti;
      report_vuln_t vuln;

      oid = result_iterator_nvt_oid (&results);
      if (oid == NULL)
        continue;

      nvti = lookup_nvti (oid);
      if (nvti == NULL)
        continue;

      vuln = lookup_or_create_report_cve (vulns_by_oid,
                                         *report_vulns,
                                         &results,
                                         nvti);

      vuln->occurrences++;

      host = result_iterator_host (&results);
      report_cve_add_host_once (vuln, hosts_by_oid, oid, host);
    }

  cleanup_iterator (&results);

  g_hash_table_destroy (hosts_by_oid);
  g_hash_table_destroy (vulns_by_oid);

  return 0;
}

/**
 * @brief Check whether an NVT has at least one CVE reference.
 *
 * @param[in] nvti NVT information to inspect.
 *
 * @return TRUE if the NVT has CVE references, FALSE otherwise.
 */
static gboolean
nvti_has_cve_refs (nvti_t *nvti)
{
  int i;

  if (nvti == NULL)
    return FALSE;

  for (i = 0; i < nvti_vtref_len (nvti); i++)
    {
      vtref_t *ref;

      ref = nvti_vtref (nvti, i);

      if (vtref_is_cve (ref))
        return TRUE;
    }

  return FALSE;
}

/**
 * @brief Count report Vulnerability rows from filtered report results.
 *
 * @param[in] report  Report to process.
 * @param[in] get     Report filter and pagination data.
 *
 * @return Number of unique report Vulnerability rows.
 */
int
report_vulns_count (report_t report, const get_data_t *get)
{
  iterator_t results;
  GHashTable *seen_oids;
  int count;

  count = 0;
  seen_oids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  init_result_get_iterator (&results, get, report, NULL, NULL);

  while (next (&results))
    {
      const char *oid;
      nvti_t *nvti;

      oid = result_iterator_nvt_oid (&results);
      if (oid == NULL)
        continue;

      if (g_hash_table_contains (seen_oids, oid))
        continue;

      nvti = lookup_nvti (oid);
      if (nvti == NULL)
        continue;

      if (!nvti_has_cve_refs (nvti))
        continue;

      g_hash_table_insert (seen_oids, g_strdup (oid), GINT_TO_POINTER (1));
      count++;
    }

  cleanup_iterator (&results);
  g_hash_table_destroy (seen_oids);

  return count;
}
