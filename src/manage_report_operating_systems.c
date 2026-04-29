/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report operating systems.
 *
 * Non-SQL report operating systems code for the GVM management layer.
 */
#include "manage_report_operating_systems.h"

#include "manage_filters.h"
#include "manage_sql_report_operating_systems.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize a new report os.
 *
 * @return Newly allocated report application.
 */
report_os_t
report_os_new (void)
{
  return (report_os_t) g_malloc0 (sizeof (struct report_os));
}

/**
 * @brief Free a report os.
 *
 * @param[in] os Report os to free.
 */
void
report_os_free (report_os_t os)
{
  if (os == NULL)
    return;

  g_free (os->best_os_name);
  g_free (os->os_cpe);
  g_free (os);
}

/**
 * @brief Create a new report os list.
 *
 * @return Newly allocated os list.
 */
GPtrArray *
report_os_list_new (void)
{
  return g_ptr_array_new_with_free_func (
    (GDestroyNotify) report_os_free);
}

/**
 * @brief Free a report os list.
 *
 * @param[in] list  os list to free.
 */
void
report_os_list_free (GPtrArray *list)
{
  if (list == NULL)
    return;

  g_ptr_array_free (list, TRUE);
}

/**
 * @brief Get operating systems  for a report with aggregated host.
 *
 * @param[in]  report               Report to process.
 * @param[out] report_os_list       Operating System list to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
get_report_operating_systems (report_t report,
                              const get_data_t *get,
                              GPtrArray **report_os_list)
{
  iterator_t report_os;
  iterator_t results;
  int result_hosts_only = 0;
  gchar *term = NULL;
  int ret;
  GHashTable *report_host_ids = NULL;
  GHashTable *os_by_cpe = NULL;

  if (report_os_list == NULL)
    return -1;

  if (get->filter)
    {
      ret = manage_report_filter_controls_from_get (get,
                                                    &term,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    &result_hosts_only,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL,
                                                    NULL);
      if (ret)
        return ret;
    }

  *report_os_list = report_os_list_new ();

  if (get->details && result_hosts_only)
    {
      ret = fill_filtered_report_host_ids (&report_host_ids,
                                           get,
                                           report,
                                           &results);
      if (ret)
        {
          g_free (term);
          report_os_list_free (*report_os_list);
          *report_os_list = NULL;
          return ret;
        }
    }

  os_by_cpe = g_hash_table_new (g_str_hash, g_str_equal);

  init_report_os_iterator (&report_os, report);

  while (next (&report_os))
    {
      report_host_t report_host_id;
      const char *cpe;
      const char *os_name;
      report_os_t os;
      gchar *key;

      report_host_id = report_os_iterator_report_host_id (&report_os);

      if (report_host_ids
          && g_hash_table_contains (report_host_ids,
                                    GSIZE_TO_POINTER (report_host_id)) == FALSE)
        continue;

      cpe = report_os_iterator_cpe (&report_os);
      os_name = report_os_iterator_os_name (&report_os);

      key = g_strdup (cpe ? cpe : "");

      os = g_hash_table_lookup (os_by_cpe, key);
      if (os == NULL)
        {
          os = report_os_new ();
          os->os_cpe = g_strdup (cpe);
          os->best_os_name = g_strdup (os_name);
          os->hosts_count = 1;

          g_ptr_array_add (*report_os_list, os);
          g_hash_table_insert (os_by_cpe, key, os);
        }
      else
        {
          os->hosts_count++;
          g_free (key);
        }
    }

  cleanup_iterator (&report_os);

  if (report_host_ids)
    {
      cleanup_iterator (&results);
      g_hash_table_destroy (report_host_ids);
    }

  g_hash_table_destroy (os_by_cpe);
  g_free (term);

  return 0;
}
