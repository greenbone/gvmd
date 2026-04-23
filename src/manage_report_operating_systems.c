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
                              GPtrArray **report_os_list)
{
  iterator_t report_os;

  if (report_os_list == NULL)
    return -1;

  *report_os_list = report_os_list_new ();

  init_report_os_iterator (&report_os, report);

  while (next (&report_os))
    {
      report_os_t os;

      os = report_os_new ();
      os->os_cpe = g_strdup (report_os_iterator_cpe (&report_os));
      os->best_os_name = g_strdup (report_os_iterator_os_name (&report_os));
      os->hosts_count = report_os_iterator_host_count (&report_os);

      g_ptr_array_add (*report_os_list, os);
    }

  cleanup_iterator (&report_os);

  return 0;
}
