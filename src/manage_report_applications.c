/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report applications.
 *
 * Non-SQL report applications code for the GVM management layer.
 */

#include "manage_report_applications.h"

#include "manage_sql_report_applications.h"
#include "utils.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Allocate and initialize a new report application.
 *
 * @return Newly allocated report application.
 */
report_application_t
report_application_new (void)
{
  return (report_application_t) g_malloc0 (sizeof (struct report_application));
}

/**
 * @brief Free a report application.
 *
 * @param[in] app  Report application to free.
 */
void
report_application_free (report_application_t app)
{
  if (app == NULL)
    return;

  g_free (app->application_name);
  g_free (app);
}

/**
 * @brief Create a new report application list.
 *
 * @return Newly allocated application list.
 */
GPtrArray *
report_application_list_new (void)
{
  return g_ptr_array_new_with_free_func (
    (GDestroyNotify) report_application_free);
}

/**
 * @brief Free a report application list.
 *
 * @param[in] apps  Application list to free.
 */
void
report_application_list_free (GPtrArray *apps)
{
  if (apps == NULL)
    return;

  g_ptr_array_free (apps, TRUE);
}

/**
 * @brief Get applications for a report with aggregated host, occurrence,
 *        and severity information.
 *
 * Initializes a list of report applications, fills it from the report
 * application iterator, and sets the maximum severity for each application
 * from the precomputed severity hash table.
 *
 * @param[in]  report               Report to process.
 * @param[in]  get                  Get request data.
 * @param[out] report_applications  Application list to fill.
 *
 * @return 0 on success, -1 on error.
 */
int
get_report_applications (report_t report,
                         const get_data_t *get,
                         GPtrArray **report_applications)
{
  GHashTable *app_severities;
  iterator_t results;
  iterator_t report_apps;

  if (report_applications == NULL)
    return -1;

  *report_applications = report_application_list_new ();

  fill_report_applications_severities (get, report, &results, &app_severities);

  init_report_app_iterator (&report_apps, report);

  while (next (&report_apps))
    {
      const gchar *application_name;
      double *severity_ptr;
      report_application_t app;

      application_name = report_app_iterator_application_name (&report_apps);
      if (str_blank (application_name))
        continue;

      app = report_application_new ();
      app->application_name = g_strdup (application_name);
      app->hosts_count = report_app_iterator_host_count (&report_apps);
      app->occurrences = report_app_iterator_occurrences (&report_apps);
      app->severity_double = 0.0;

      severity_ptr = g_hash_table_lookup (app_severities, application_name);
      if (severity_ptr)
        app->severity_double = *severity_ptr;

      g_ptr_array_add (*report_applications, app);
    }

  cleanup_iterator (&report_apps);
  cleanup_iterator (&results);
  g_hash_table_destroy (app_severities);

  return 0;
}
