/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_report_errors.h"

#include "gmp_get.h"
#include "manage.h"
#include "manage_report_errors.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_errors command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_errors_data_t;

/**
 * @brief Parser callback data.
 */
static get_report_errors_data_t get_report_errors_data;

/**
 * @brief Reset the internal state of the <get_report_errors> command.
 */
static void
get_report_errors_reset ()
{
  get_data_reset (&get_report_errors_data.get);
  g_free (get_report_errors_data.report_id);
  memset (&get_report_errors_data, 0, sizeof (get_report_errors_data));
}

/**
 * @brief Initialize the <get_report_errors> GMP command by parsing
 *        attributes.
 *
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of corresponding
 *                              attribute values.
 */
void
get_report_errors_start (const gchar **attribute_names,
                         const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_errors_data.get,
                             "error",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_errors_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_errors_data.get,
                          "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Execute the <get_report_errors> GMP command.
 *
 * @param[in] gmp_parser  Pointer to the GMP parser handling the current
 *                        session.
 * @param[in] error       Location to store error information, if any occurs.
 */
void
get_report_errors_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  int ret, filtered, count;

  count = 0;

  if (get_report_errors_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL
        (XML_ERROR_SYNTAX ("get_report_errors",
                           "Missing report_id attribute"));
      get_report_errors_reset ();
      return;
    }

  ret = init_get ("get_report_errors",
                  &get_report_errors_data.get,
                  "Report Errors",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL
            (XML_ERROR_SYNTAX ("get_report_errors",
                               "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_errors_reset ();
          return;
        }
      get_report_errors_reset ();
      return;
    }

  if (find_report_with_permission (get_report_errors_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_errors_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_errors",
                                     "report",
                                     get_report_errors_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);
      get_report_errors_reset ();
      return;
    }

  SEND_GET_START ("report_error");

  ret = manage_send_report_errors (
    report,
    &get_report_errors_data.get,
    send_to_client,
    gmp_parser->client_writer,
    gmp_parser->client_writer_data);

  if (ret)
    {
      switch (ret)
        {
        case 2:
          if (send_find_error_to_client ("get_report_errors",
                                         "filter",
                                         get_report_errors_data.get.filt_id,
                                         gmp_parser))
            error_send_to_client (error);
          break;
        default:
          internal_error_send_to_client (error);
          break;
        }
      get_report_errors_reset ();
      return;
    }

  filtered = get_report_errors_data.get.id
               ? 1
               : report_error_count (report);
  SEND_GET_END ("report_error",
                &get_report_errors_data.get,
                count,
                filtered);

  get_report_errors_reset ();
}
