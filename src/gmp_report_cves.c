/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report CVEs.
 *
 * This includes function and variable definitions for GMP handling
 * of report CVEs.
 */

#include "gmp_report_cves.h"

#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_cves command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_cves_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_report_cves_data_t get_report_cves_data;

/**
 * @brief Reset the internal state of the <get_report_cves> command.
 */
static void
get_report_cves_reset ()
{
  get_data_reset (&get_report_cves_data.get);
  g_free (get_report_cves_data.report_id);
  memset (&get_report_cves_data, 0, sizeof (get_report_cves_data));
}

/**
 * @brief Initialize the <get_report_cves> GMP command by parsing attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding
 *                             attribute values.
 */
void
get_report_cves_start (const gchar **attribute_names,
                       const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_cves_data.get,
                             "report_cves",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_cves_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_cves_data.get, "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Send one report CVE as XML.
 *
 * @param[in] cve Report CVE to send.
 */
static void
send_report_cve_xml (gmp_parser_t *gmp_parser, GError **error, report_cve_t cve)
{
  guint index;

  if (cve == NULL)
    return;

  SEND_TO_CLIENT_OR_FAIL ("<cve_result>");

  SENDF_TO_CLIENT_OR_FAIL ("<nvt_name>%s</nvt_name>",
                           cve->nvt_name ? cve->nvt_name : "");

  SENDF_TO_CLIENT_OR_FAIL ("<nvt_oid>%s</nvt_oid>",
                           cve->nvt_oid ? cve->nvt_oid : "");

  SEND_TO_CLIENT_OR_FAIL ("<cves>");

  if (cve->nvt_cves)
    {
      for (index = 0; index < cve->nvt_cves->len; index++)
        {
          const gchar *nvt_cve;

          nvt_cve = g_ptr_array_index (cve->nvt_cves, index);

          SENDF_TO_CLIENT_OR_FAIL ("<cve>%s</cve>",
                                   nvt_cve ? nvt_cve : "");
        }
    }

  SEND_TO_CLIENT_OR_FAIL ("</cves>");

  SENDF_TO_CLIENT_OR_FAIL ("<hosts_count>%d</hosts_count>",
                           cve->hosts_count);

  SENDF_TO_CLIENT_OR_FAIL ("<occurrences>%d</occurrences>",
                           cve->occurrences);

  SENDF_TO_CLIENT_OR_FAIL ("<severity>%.1f</severity>",
                           cve->severity_double);

  SENDF_TO_CLIENT_OR_FAIL ("<threat>%s</threat>",
                           severity_to_level (cve->severity_double, 0));

  SEND_TO_CLIENT_OR_FAIL ("</cve_result>");
}

/**
 * @brief Execute the <get_report_cves> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_report_cves_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  int ret, filtered, count;
  GPtrArray *cves;
  guint index;

  count = 0;
  filtered = 0;
  cves = NULL;

  if (get_report_cves_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("get_report_cves",
          "Missing report_id attribute"));
      get_report_cves_reset ();
      return;
    }

  ret = init_get ("get_report_cves",
                  &get_report_cves_data.get,
                  "Report CVEs",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("get_report_cves", "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_cves_reset ();
          return;
        }

      get_report_cves_reset ();
      return;
    }

  if (find_report_with_permission (get_report_cves_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_cves_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_cves",
                                     "report",
                                     get_report_cves_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);

      get_report_cves_reset ();
      return;
    }

  if (get_report_cves_data.get.details)
    {
      ret = get_report_cves (report, &get_report_cves_data.get, &cves);
      if (ret)
        {
          internal_error_send_to_client (error);
          get_report_cves_reset ();
          return;
        }

      count = cves ? cves->len : 0;
      filtered = get_report_cves_data.get.id ? (count ? 1 : 0) : count;
    }
  else
    {
      count = report_cves_count (report, &get_report_cves_data.get);
      if (count < 0)
        {
          internal_error_send_to_client (error);
          get_report_cves_reset ();
          return;
        }

      filtered = get_report_cves_data.get.id ? (count ? 1 : 0) : count;
    }

  SEND_GET_START ("report_cve");

  SEND_TO_CLIENT_OR_FAIL ("<cve_results>");

  if (get_report_cves_data.get.details)
    {
      for (index = 0; index < cves->len; index++)
        {
          report_cve_t cve;

          cve = g_ptr_array_index (cves, index);
          send_report_cve_xml (gmp_parser, error, cve);
        }
    }
  else
    {
      SENDF_TO_CLIENT_OR_FAIL ("<count>%i</count>", count);
    }

  SEND_TO_CLIENT_OR_FAIL ("</cve_results>");

  SEND_GET_END ("report_cve",
                &get_report_cves_data.get,
                count,
                filtered);

  report_cve_list_free (cves);
  get_report_cves_reset ();
}
