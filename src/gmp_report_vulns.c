/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report Vulnerabilities.
 *
 * This includes function and variable definitions for GMP handling
 * of report Vulnerabilities.
 */

#include "gmp_report_vulns.h"

#include "gmp_get.h"
#include "manage.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_vulns command.
 */
typedef struct
{
  get_data_t get;  ///< Get args with filtering.
  char *report_id; ///< ID of single report to get.
} get_report_vulns_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially 0 because it's a global variable.
 */
static get_report_vulns_data_t get_report_vulns_data;

/**
 * @brief Reset the internal state of the <get_report_vulns> command.
 */
static void
get_report_vulns_reset ()
{
  get_data_reset (&get_report_vulns_data.get);
  g_free (get_report_vulns_data.report_id);
  memset (&get_report_vulns_data, 0, sizeof (get_report_vulns_data));
}

/**
 * @brief Initialize the <get_report_vulns> GMP command by parsing attributes.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding
 *                             attribute values.
 */
void
get_report_vulns_start (const gchar **attribute_names,
                        const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_report_vulns_data.get,
                             "report_vulns",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names, attribute_values,
                      "report_id", &attribute))
    {
      get_report_vulns_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_report_vulns_data.get, "report_id",
                          g_strdup (attribute));
    }
}

/**
 * @brief Send one report Vulnerability as XML.
 *
 * @param[in] vuln Report Vulnerability to send.
 */
static void
send_report_vuln_xml (gmp_parser_t *gmp_parser, GError **error,
                      report_vuln_t vuln)
{
  guint index;

  if (vuln == NULL)
    return;

  SEND_TO_CLIENT_OR_FAIL ("<vuln>");

  SENDF_TO_CLIENT_OR_FAIL ("<nvt oid=\"%s\">",
                           vuln->nvt_oid ? vuln->nvt_oid : "");

  SENDF_TO_CLIENT_OR_FAIL ("<name>%s</name>",
                           vuln->nvt_name ? vuln->nvt_name : "");

  SEND_TO_CLIENT_OR_FAIL ("</nvt>");

  SEND_TO_CLIENT_OR_FAIL ("<cves>");

  if (vuln->nvt_cves)
    {
      for (index = 0; index < vuln->nvt_cves->len; index++)
        {
          const gchar *nvt_cve;

          nvt_cve = g_ptr_array_index (vuln->nvt_cves, index);

          SENDF_TO_CLIENT_OR_FAIL ("<cve>%s</cve>",
                                   nvt_cve ? nvt_cve : "");
        }
    }

  SEND_TO_CLIENT_OR_FAIL ("</cves>");

  SENDF_TO_CLIENT_OR_FAIL ("<hosts_count>%d</hosts_count>",
                           vuln->hosts_count);

  SENDF_TO_CLIENT_OR_FAIL ("<occurrences>%d</occurrences>",
                           vuln->occurrences);

  SENDF_TO_CLIENT_OR_FAIL ("<severity>%.1f</severity>",
                           vuln->severity_double);

  SENDF_TO_CLIENT_OR_FAIL ("<threat>%s</threat>",
                           severity_to_level (vuln->severity_double, 0));

  SEND_TO_CLIENT_OR_FAIL ("</vuln>");
}

/**
 * @brief Execute the <get_report_vulns> GMP command.
 *
 * @param[in] gmp_parser Pointer to the GMP parser handling the current session.
 * @param[in] error      Location to store error information, if any occurs.
 */
void
get_report_vulns_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  int ret, filtered, count;
  GPtrArray *vulns;
  guint index;

  count = 0;
  filtered = 0;
  vulns = NULL;

  if (get_report_vulns_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("get_report_vulns",
          "Missing report_id attribute"));
      get_report_vulns_reset ();
      return;
    }

  ret = init_get ("get_report_vulns",
                  &get_report_vulns_data.get,
                  "Report Vulnerabilities",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("get_report_vulns", "Permission denied"));
          break;
        default:
          internal_error_send_to_client (error);
          get_report_vulns_reset ();
          return;
        }

      get_report_vulns_reset ();
      return;
    }

  if (find_report_with_permission (get_report_vulns_data.report_id,
                                   &report,
                                   "get_reports"))
    {
      internal_error_send_to_client (error);
      get_report_vulns_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client ("get_report_vulns",
                                     "report",
                                     get_report_vulns_data.report_id,
                                     gmp_parser))
        error_send_to_client (error);

      get_report_vulns_reset ();
      return;
    }

  if (get_report_vulns_data.get.details)
    {
      ret = get_report_vulns (report, &get_report_vulns_data.get, &vulns);
      if (ret)
        {
          internal_error_send_to_client (error);
          get_report_vulns_reset ();
          return;
        }

      count = vulns ? vulns->len : 0;
      filtered = get_report_vulns_data.get.id ? (count ? 1 : 0) : count;
    }
  else
    {
      count = report_vulns_count (report, &get_report_vulns_data.get);
      if (count < 0)
        {
          internal_error_send_to_client (error);
          get_report_vulns_reset ();
          return;
        }

      filtered = get_report_vulns_data.get.id ? (count ? 1 : 0) : count;
    }

  SEND_GET_START ("report_vuln");

  SEND_TO_CLIENT_OR_FAIL ("<vulns>");

  if (get_report_vulns_data.get.details)
    {
      for (index = 0; index < vulns->len; index++)
        {
          report_vuln_t cve;

          cve = g_ptr_array_index (vulns, index);
          send_report_vuln_xml (gmp_parser, error, cve);
        }
    }
  else
    {
      SENDF_TO_CLIENT_OR_FAIL ("<count>%i</count>", count);
    }

  SEND_TO_CLIENT_OR_FAIL ("</vulns>");

  SEND_GET_END ("report_vuln",
                &get_report_vulns_data.get,
                count,
                filtered);

  report_vuln_list_free (vulns);
  get_report_vulns_reset ();
}
