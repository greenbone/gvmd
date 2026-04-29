/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Integration Operating Systems
 *
 * This includes function and variable definitions for GMP handling
 *  of operating systems.
 */

#include "gmp_report_operating_systems.h"

#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_operating_systems command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_os_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_report_os_data_t get_report_os_data;

/**
 * @brief Reset the internal state of the <get_report_operating_systems> command.
 */
static void
get_report_operating_systems_reset ()
{
  get_data_reset (&get_report_os_data.get);
  g_free (get_report_os_data.report_id);
  memset (&get_report_os_data, 0, sizeof (get_report_os_data));
}

/**
 * @brief Initialize the <get_report_operating_systems> GMP command by parsing attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding
 *                             attribute values.
 */
void
get_report_operating_systems_start (const gchar **attribute_names,
                                    const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_os_data.get,
                             "report_operating_systems",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_os_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_os_data.get, "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Execute the <get_report_operating_systems> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_report_operating_systems_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  int ret, filtered, count;
  GPtrArray *o_systems;
  guint index;

  count = 0;
  filtered = 0;
  o_systems = NULL;

  if (get_report_os_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("get_report_operating_systems",
          "Missing report_id attribute"));
      get_report_operating_systems_reset ();
      return;
    }

  ret = init_get ("get_report_operating_systems",
                  &get_report_os_data.get,
                  "Report Operating Systems",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("get_report_operating_systems",
              "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_operating_systems_reset ();
          return;
        }
      get_report_operating_systems_reset ();
      return;
    }

  if (find_report_with_permission (get_report_os_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_operating_systems_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_operating_systems",
                                     "report",
                                     get_report_os_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);
      get_report_operating_systems_reset ();
      return;
    }

  if (get_report_os_data.get.details)
    {
      ret = get_report_operating_systems (report,
                                          &get_report_os_data.get,
                                          &o_systems);
      if (ret)
        {
          internal_error_send_to_client (error);
          get_report_operating_systems_reset ();
          return;
        }

      count = o_systems ? o_systems->len : 0;
      filtered = get_report_os_data.get.id ? (count ? 1 : 0) : count;
    }
  else
    {
      count = report_operating_systems_count (report);
      if (count < 0)
        {
          internal_error_send_to_client (error);
          get_report_operating_systems_reset ();
          return;
        }

      filtered = get_report_os_data.get.id ? (count ? 1 : 0) : count;
    }

  SEND_GET_START ("report_operating_system");

  SEND_TO_CLIENT_OR_FAIL ("<operating_systems>");

  if (get_report_os_data.get.details)
    {
      for (index = 0; index < o_systems->len; index++)
        {
          report_os_t os;

          os = g_ptr_array_index (o_systems, index);
          if (os == NULL)
            continue;

          SEND_TO_CLIENT_OR_FAIL ("<operating_system>");

          SENDF_TO_CLIENT_OR_FAIL ("<best_os_cpe>%s</best_os_cpe>",
                                   os->os_cpe
                                   ? os->os_cpe
                                   : "");

          SENDF_TO_CLIENT_OR_FAIL ("<best_os_txt>%s</best_os_txt>",
                                   os->best_os_name
                                   ? os->best_os_name
                                   : "");
          SENDF_TO_CLIENT_OR_FAIL ("<hosts_count>%d</hosts_count>",
                                   os->hosts_count);

          SEND_TO_CLIENT_OR_FAIL ("</operating_system>");
        }
    }
  else
    {
      SENDF_TO_CLIENT_OR_FAIL ("<count>%i</count>", count);
    }

  SEND_TO_CLIENT_OR_FAIL ("</operating_systems>");

  SEND_GET_END ("report_operating_system",
                &get_report_os_data.get,
                count,
                filtered);

  report_os_list_free (o_systems);
  get_report_operating_systems_reset ();
}
