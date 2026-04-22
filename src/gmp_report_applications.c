/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Integration Application
 *
 * This includes function and variable definitions for GMP handling
 *  of applications.
 */

#include "gmp_report_applications.h"

#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_applications command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_apps_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_report_apps_data_t get_report_apps_data;

/**
 * @brief Reset the internal state of the <get_report_applications> command.
 */
static void
get_report_applications_reset ()
{
  get_data_reset (&get_report_apps_data.get);
  g_free (get_report_apps_data.report_id);
  memset (&get_report_apps_data, 0, sizeof (get_report_apps_data));
}

/**
 * @brief Initialize the <get_report_applications> GMP command by parsing attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding
 *                             attribute values.
 */
void
get_report_applications_start (const gchar **attribute_names,
                               const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_apps_data.get,
                             "report_application",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_apps_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_apps_data.get, "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Execute the <get_report_applications> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_report_applications_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  int ret, filtered, count;
  GPtrArray *applications;
  guint index;

  count = 0;
  filtered = 0;
  applications = NULL;

  if (get_report_apps_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("get_report_applications",
          "Missing report_id attribute"));
      get_report_applications_reset ();
      return;
    }

  ret = init_get ("get_report_applications",
                  &get_report_apps_data.get,
                  "Report Applications",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("get_report_applications",
              "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_applications_reset ();
          return;
        }
      get_report_applications_reset ();
      return;
    }

  if (find_report_with_permission (get_report_apps_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_applications_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_applications",
                                     "report",
                                     get_report_apps_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);
      get_report_applications_reset ();
      return;
    }

  if (get_report_apps_data.get.details)
    {
      ret = get_report_applications (report,
                                     &get_report_apps_data.get,
                                     &applications);
      if (ret)
        {
          internal_error_send_to_client (error);
          get_report_applications_reset ();
          return;
        }

      count = applications ? applications->len : 0;
      filtered = get_report_apps_data.get.id ? (count ? 1 : 0) : count;
    }
  else
    {
      count = report_applications_count (report);
      if (count < 0)
        {
          internal_error_send_to_client (error);
          get_report_applications_reset ();
          return;
        }

      filtered = get_report_apps_data.get.id ? (count ? 1 : 0) : count;
    }

  SEND_GET_START ("report_application");

  SEND_TO_CLIENT_OR_FAIL ("<applications>");

  if (get_report_apps_data.get.details)
    {
      for (index = 0; index < applications->len; index++)
        {
          report_application_t app;

          app = g_ptr_array_index (applications, index);
          if (app == NULL)
            continue;

          SEND_TO_CLIENT_OR_FAIL ("<application>");

          SENDF_TO_CLIENT_OR_FAIL ("<name>%s</name>",
                                   app->application_name
                                   ? app->application_name
                                   : "");
          SENDF_TO_CLIENT_OR_FAIL ("<hosts_count>%d</hosts_count>",
                                   app->hosts_count);
          SENDF_TO_CLIENT_OR_FAIL ("<occurrences>%d</occurrences>",
                                   app->occurrences);
          SENDF_TO_CLIENT_OR_FAIL ("<severity>%1.1f</severity>",
                                   app->severity_double);
          SENDF_TO_CLIENT_OR_FAIL ("<threat>%s</threat>",
                                   severity_to_level (app->severity_double, 0));

          SEND_TO_CLIENT_OR_FAIL ("</application>");
        }
    }
  else
    {
      SENDF_TO_CLIENT_OR_FAIL ("<count>%i</count>", count);
    }

  SEND_TO_CLIENT_OR_FAIL ("</applications>");

  SEND_GET_END ("report_application",
                &get_report_apps_data.get,
                count,
                filtered);

  report_application_list_free (applications);
  get_report_applications_reset ();
}
