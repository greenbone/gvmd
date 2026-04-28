/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report CVEs.
 *
 * Non-SQL report CVEs code for the GVM management layer.
 */

#include "manage_report_cves.h"

#include "manage_sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Create a new report CVE object.
 *
 * @return Newly allocated report CVE object.
 */
report_cve_t
report_cve_new (void)
{
  report_cve_t cve;

  cve = g_malloc0 (sizeof (struct report_cve));

  cve->nvt_cves = g_ptr_array_new_with_free_func (g_free);

  return cve;
}

/**
 * @brief Free a report CVE object.
 *
 * @param[in] cve Report CVE object to free.
 */
void
report_cve_free (report_cve_t cve)
{
  if (cve == NULL)
    return;

  g_free (cve->nvt_name);
  g_free (cve->nvt_oid);

  if (cve->nvt_cves)
    g_ptr_array_free (cve->nvt_cves, TRUE);

  g_free (cve);
}

/**
 * @brief Create a new report CVE list.
 *
 * @return Newly allocated report CVE list.
 */
GPtrArray *
report_cve_list_new (void)
{
  return g_ptr_array_new_with_free_func ((GDestroyNotify) report_cve_free);
}

/**
 * @brief Free a report CVE list.
 *
 * @param[in] cves Report CVE list to free.
 */
void
report_cve_list_free (GPtrArray *cves)
{
  if (cves == NULL)
    return;

  g_ptr_array_free (cves, TRUE);
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
 * @brief Add all CVE references from an NVT to a report CVE object.
 *
 * @param[in,out] cve   Report CVE object to update.
 * @param[in]     nvti  NVT information containing VT references.
 */
static void
report_cve_add_nvt_cves (report_cve_t cve, nvti_t *nvti)
{
  int i;

  if (cve == NULL || nvti == NULL)
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

      g_ptr_array_add (cve->nvt_cves, g_strdup (id));
    }
}

/**
 * @brief Create a report CVE object from the current result.
 *
 * Adds basic NVT information, severity, and CVE references.
 *
 * @param[in] results Result iterator positioned at the current result.
 * @param[in] nvti    NVT information for the current result.
 *
 * @return Newly allocated report CVE object.
 */
static report_cve_t
report_cve_from_result (iterator_t *results, nvti_t *nvti)
{
  report_cve_t cve;
  const char *oid;

  oid = result_iterator_nvt_oid (results);

  cve = report_cve_new ();
  cve->nvt_name = g_strdup (result_iterator_nvt_name (results));
  cve->nvt_oid = g_strdup (oid);
  cve->severity_double = result_iterator_severity_double (results);

  report_cve_add_nvt_cves (cve, nvti);

  return cve;
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
 * @brief Add a host to a report CVE object if it was not counted yet.
 *
 * @param[in,out] cve          Report CVE object to update.
 * @param[in,out] hosts_by_oid Hash table mapping NVT OIDs to host sets.
 * @param[in]     oid          NVT OID.
 * @param[in]     host         Host identifier.
 */
static void
report_cve_add_host_once (report_cve_t cve,
                          GHashTable *hosts_by_oid,
                          const char *oid,
                          const char *host)
{
  GHashTable *hosts;

  if (cve == NULL || hosts_by_oid == NULL || oid == NULL || host == NULL)
    return;

  hosts = lookup_or_create_host_set (hosts_by_oid, oid);

  if (!g_hash_table_contains (hosts, host))
    {
      g_hash_table_insert (hosts, g_strdup (host), GINT_TO_POINTER (1));
      cve->hosts_count++;
    }
}

/**
 * @brief Look up or create a report CVE object for the current result.
 *
 * @param[in,out] cves_by_oid Hash table mapping NVT OIDs to report CVEs.
 * @param[in,out] report_cves Report CVE list to update.
 * @param[in]     results     Result iterator positioned at the current result.
 * @param[in]     nvti        NVT information for the current result.
 *
 * @return Report CVE object for the current NVT OID.
 */
static report_cve_t
lookup_or_create_report_cve (GHashTable *cves_by_oid,
                             GPtrArray *report_cves,
                             iterator_t *results,
                             nvti_t *nvti)
{
  const gchar *oid;
  report_cve_t cve;

  oid = result_iterator_nvt_oid (results);

  cve = g_hash_table_lookup (cves_by_oid, oid);

  if (cve == NULL)
    {
      cve = report_cve_from_result (results, nvti);

      g_ptr_array_add (report_cves, cve);

      /* Key is owned by cve itself. */
      g_hash_table_insert (cves_by_oid, cve->nvt_oid, cve);
    }

  return cve;
}

/**
 * @brief Get CVEs for a report with aggregated host and occurrence counts.
 *
 * @param[in]  report       Report to process.
 * @param[in]  get          Report filter and pagination data.
 * @param[out] report_cves  Report CVE list to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
get_report_cves (report_t report,
                 const get_data_t *get,
                 GPtrArray **report_cves)
{
  iterator_t results;
  GHashTable *cves_by_oid;
  GHashTable *hosts_by_oid;

  if (report_cves == NULL)
    return -1;

  *report_cves = report_cve_list_new ();

  cves_by_oid = g_hash_table_new (g_str_hash, g_str_equal);

  hosts_by_oid = g_hash_table_new_full (
    g_str_hash, g_str_equal, g_free, (GDestroyNotify) g_hash_table_destroy);

  init_result_get_iterator (&results, get, report, NULL, NULL);

  while (next (&results))
    {
      const gchar *oid;
      const gchar *host;
      nvti_t *nvti;
      report_cve_t cve;

      oid = result_iterator_nvt_oid (&results);
      if (oid == NULL)
        continue;

      nvti = lookup_nvti (oid);
      if (nvti == NULL)
        continue;

      cve = lookup_or_create_report_cve (cves_by_oid,
                                         *report_cves,
                                         &results,
                                         nvti);

      cve->occurrences++;

      host = result_iterator_host (&results);
      report_cve_add_host_once (cve, hosts_by_oid, oid, host);
    }

  cleanup_iterator (&results);

  g_hash_table_destroy (hosts_by_oid);
  g_hash_table_destroy (cves_by_oid);

  return 0;
}
