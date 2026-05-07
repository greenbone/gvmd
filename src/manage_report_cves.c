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
  return g_malloc0 (sizeof (struct report_cve));
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

  g_free (cve->host);
  g_free (cve->cve);
  g_free (cve->oid);
  g_free (cve->nvt_name);

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
  return ref != NULL && g_strcmp0 (vtref_type (ref), "cve") == 0;
}

/**
 * @brief Create a report CVE object from the current result and CVE ID.
 *
 * @param[in] results Result iterator positioned at the current result.
 * @param[in] cve_id  Single CVE ID.
 *
 * @return Newly allocated report CVE object.
 */
static report_cve_t
report_cve_from_result (iterator_t *results, const gchar *cve_id)
{
  report_cve_t cve;

  cve = report_cve_new ();

  cve->host = g_strdup (result_iterator_host (results));
  cve->cve = g_strdup (cve_id);
  cve->oid = g_strdup (result_iterator_nvt_oid (results));
  cve->nvt_name = g_strdup (result_iterator_nvt_name (results));
  cve->severity_double = result_iterator_severity_double (results);

  return cve;
}

/**
 * @brief Add one report CVE object for a single CVE ID.
 *
 * @param[in,out] report_cves Report CVE list to update.
 * @param[in]     results     Result iterator positioned at the current result.
 * @param[in]     cve_id      Single CVE ID.
 */
static void
report_cves_add_single_cve (GPtrArray *report_cves,
                            iterator_t *results,
                            const gchar *cve_id)
{
  report_cve_t cve;

  if (report_cves == NULL || results == NULL || str_blank (cve_id))
    return;

  cve = report_cve_from_result (results, cve_id);
  g_ptr_array_add (report_cves, cve);
}

/**
 * @brief Add report CVE objects from a CVE reference string.
 *
 * A CVE reference string can contain multiple CVE IDs separated by commas.
 * This function creates one report CVE object for each single CVE ID.
 *
 * @param[in,out] report_cves Report CVE list to update.
 * @param[in]     results     Result iterator positioned at the current result.
 * @param[in]     cve_ids     CVE reference string.
 */
static void
report_cves_add_from_vtref_id (GPtrArray *report_cves,
                               iterator_t *results,
                               const gchar *cve_ids)
{
  gchar **cve_array;
  int i;

  if (report_cves == NULL || results == NULL || str_blank (cve_ids))
    return;

  cve_array = g_strsplit (cve_ids, ",", -1);

  for (i = 0; cve_array[i] != NULL; i++)
    {
      gchar *cve_id;

      cve_id = g_strstrip (cve_array[i]);

      if (str_blank (cve_id))
        continue;

      report_cves_add_single_cve (report_cves, results, cve_id);
    }

  g_strfreev (cve_array);
}

/**
 * @brief Count single CVE IDs in a CVE reference string.
 *
 * A CVE reference string can contain multiple CVE IDs separated by commas.
 *
 * @param[in] cve_ids CVE reference string.
 *
 * @return Number of single CVE IDs.
 */
static int
report_cves_count_from_vtref_id (const gchar *cve_ids)
{
  gchar **cve_array;
  int count;
  int i;

  if (str_blank (cve_ids))
    return 0;

  count = 0;
  cve_array = g_strsplit (cve_ids, ",", -1);

  for (i = 0; cve_array[i] != NULL; i++)
    {
      gchar *cve_id;

      cve_id = g_strstrip (cve_array[i]);

      if (!str_blank (cve_id))
        count++;
    }

  g_strfreev (cve_array);

  return count;
}

/**
 * @brief Add CVE rows for all CVE references of an NVT.
 *
 * @param[in,out] report_cves Report CVE list to update.
 * @param[in]     results     Result iterator positioned at the current result.
 * @param[in]     nvti        NVT information containing VT references.
 */
static void
report_cves_add_from_nvti (GPtrArray *report_cves,
                           iterator_t *results,
                           nvti_t *nvti)
{
  int i;

  if (report_cves == NULL || results == NULL || nvti == NULL)
    return;

  for (i = 0; i < nvti_vtref_len (nvti); i++)
    {
      vtref_t *ref;

      ref = nvti_vtref (nvti, i);

      if (!vtref_is_cve (ref))
        continue;

      report_cves_add_from_vtref_id (report_cves, results, vtref_id (ref));
    }
}

/**
 * @brief Count CVE rows for all CVE references of an NVT.
 *
 * @param[in] nvti NVT information containing VT references.
 *
 * @return Number of CVE rows.
 */
static int
report_cves_count_from_nvti (nvti_t *nvti)
{
  int count;
  int i;

  if (nvti == NULL)
    return 0;

  count = 0;

  for (i = 0; i < nvti_vtref_len (nvti); i++)
    {
      vtref_t *ref;

      ref = nvti_vtref (nvti, i);

      if (!vtref_is_cve (ref))
        continue;

      count += report_cves_count_from_vtref_id (vtref_id (ref));
    }

  return count;
}

/**
 * @brief Get CVEs for a report.
 *
 * Creates one report CVE row for each CVE reference of each filtered result.
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

  if (report_cves == NULL)
    return -1;

  *report_cves = report_cve_list_new ();

  init_result_get_iterator (&results, get, report, NULL, NULL);

  while (next (&results))
    {
      const gchar *oid;
      nvti_t *nvti;

      oid = result_iterator_nvt_oid (&results);
      if (oid == NULL)
        continue;

      nvti = lookup_nvti (oid);
      if (nvti == NULL)
        continue;

      report_cves_add_from_nvti (*report_cves, &results, nvti);
    }

  cleanup_iterator (&results);

  return 0;
}

/**
 * @brief Count report CVE rows from filtered report results.
 *
 * Counts one row for each single CVE reference of each filtered result.
 *
 * @param[in] report Report to process.
 * @param[in] get    Report filter and pagination data.
 *
 * @return Number of report CVE rows.
 */
int
report_cves_count (report_t report, const get_data_t *get)
{
  iterator_t results;
  int count;

  count = 0;

  init_result_get_iterator (&results, get, report, NULL, NULL);

  while (next (&results))
    {
      const gchar *oid;
      nvti_t *nvti;

      oid = result_iterator_nvt_oid (&results);
      if (oid == NULL)
        continue;

      nvti = lookup_nvti (oid);
      if (nvti == NULL)
        continue;

      count += report_cves_count_from_nvti (nvti);
    }

  cleanup_iterator (&results);

  return count;
}
