/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_report_ports.h"

#include "gmp_get.h"
#include "manage.h"
#include "manage_acl.h"
#include "manage_report_ports.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_ports command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_ports_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_report_ports_data_t get_report_ports_data;

/**
 * @brief Reset the internal state of the <get_report_ports> command.
 */
static void
get_report_ports_reset ()
{
  get_data_reset (&get_report_ports_data.get);
  g_free (get_report_ports_data.report_id);
  memset (&get_report_ports_data, 0, sizeof (get_report_ports_data));
}

/**
 * @brief Initialize the <get_report_ports> GMP command by parsing attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding
 *                             attribute values.
 */
void
get_report_ports_start (const gchar **attribute_names,
                        const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_ports_data.get,
                             "report_port",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_ports_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_ports_data.get, "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Execute the <get_report_ports> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_report_ports_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  task_t task;
  gchar *usage_type;
  int ret, filtered, count;

  count = 0;
  // int ret;
  usage_type = NULL;

  if (get_report_ports_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
      (XML_ERROR_SYNTAX ("get_report_ports",
                         "Missing report_id attribute"));
      get_report_ports_reset ();
      return;
    }

  ret = init_get ("get_report_ports",
                  &get_report_ports_data.get,
                  "Report Ports",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL
          (XML_ERROR_SYNTAX ("get_report_ports",
                             "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_ports_reset ();
          return;
        }
      get_report_ports_reset ();
      return;
    }

  if (find_report_with_permission (get_report_ports_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_ports_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_ports",
                                     "report",
                                     get_report_ports_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);
      get_report_ports_reset ();
      return;
    }

  if (report_task (report, &task))
    {
      internal_error_send_to_client (error);
      get_report_ports_reset ();
      return;
    }

  task_usage_type (task, &usage_type);
  if (usage_type == NULL)
    usage_type = g_strdup ("");

  SEND_GET_START ("report_port");

  ret = manage_send_report_ports (
    report,
    &get_report_ports_data.get,
    usage_type,
    send_to_client,
    gmp_parser->client_writer,
    gmp_parser->client_writer_data,
    &filtered);

  g_free (usage_type);

  if (ret)
    {
      switch (ret)
        {
        case 2:
          if (send_find_error_to_client ("get_report_ports",
                                         "filter",
                                         get_report_ports_data.get.filt_id,
                                         gmp_parser))
            error_send_to_client (error);
          break;
        default:
          internal_error_send_to_client (error);
          break;
        }
      get_report_ports_reset ();
      return;
    }

  filtered = get_report_ports_data.get.id
               ? 1
               : filtered;
  SEND_GET_END ("report_port", &get_report_ports_data.get, count, filtered);

  get_report_ports_reset ();
}