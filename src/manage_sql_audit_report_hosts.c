/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Audit report hosts.
 *
 * SQL handlers for audit report host summaries.
 */

#include "manage_sql_audit_report_hosts.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Update filtered per-host compliance counts.
 *
 * @param[in,out] ctx       Report print context.
 * @param[in]     results   Result iterator positioned at the current result.
 * @param[in]     host_key  Host key used for aggregation.
 */
static void
update_filtered_host_compliance_counts (print_report_context_t *ctx,
                                        iterator_t *results,
                                        const gchar *host_key)
{
  GHashTable *host_counts;
  const gchar *compliance;
  int count;

  if (ctx == NULL || results == NULL || host_key == NULL)
    return;

  compliance = result_iterator_compliance (results);
  if (compliance == NULL)
    return;

  if (strcasecmp (compliance, "yes") == 0)
    host_counts = ctx->f_host_compliant;
  else if (strcasecmp (compliance, "no") == 0)
    host_counts = ctx->f_host_notcompliant;
  else if (strcasecmp (compliance, "incomplete") == 0)
    host_counts = ctx->f_host_incomplete;
  else if (strcasecmp (compliance, "undefined") == 0)
    host_counts = ctx->f_host_undefined;
  else
    host_counts = NULL;

  if (host_counts == NULL)
    return;

  count = GPOINTER_TO_INT (
    g_hash_table_lookup (host_counts, host_key));

  g_hash_table_replace (host_counts,
                        g_strdup (host_key),
                        GINT_TO_POINTER (count + 1));
}

/**
 * @brief Initialize the result iterator and collect filtered audit hosts.
 *
 * Populates per-host compliance counts in the report print context.
 *
 * @param[in,out] result_hosts  Array to fill with result host keys.
 * @param[in]     get           Request filter information.
 * @param[in]     report        Audit report.
 * @param[in,out] results       Result iterator.
 * @param[in,out] ctx           Report print context.
 * @param[in]     host_filter   Exact host filter, or NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int
fill_filtered_audit_report_hosts (array_t **result_hosts,
                                  const get_data_t *get,
                                  report_t report,
                                  iterator_t *results,
                                  print_report_context_t *ctx,
                                  const gchar *host_filter)
{
  int ret;

  if (result_hosts == NULL
      || get == NULL
      || results == NULL
      || ctx == NULL)
    return -1;

  *result_hosts = make_array ();

  ret = init_result_get_iterator (results,
                                  get,
                                  report,
                                  host_filter,
                                  NULL);
  if (ret)
    return ret;

  while (next (results))
    {
      const gchar *host;

      host = result_iterator_host (results);
      if (host == NULL)
        continue;

      array_add_new_string (*result_hosts, host);

      update_filtered_host_compliance_counts (ctx,
                                              results,
                                              host);
    }

  return 0;
}
