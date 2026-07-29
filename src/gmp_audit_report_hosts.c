/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GMP handlers for audit report hosts.
 */

#include "gmp_audit_report_hosts.h"

#include "gmp_get.h"
#include "manage.h"
#include "manage_audit_report_hosts.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_audit_report_hosts command.
 */
typedef struct
{
  get_data_t get;   ///< GET arguments with host/result filtering.
  gchar *report_id; ///< ID of the audit report.
  int lean;         ///< Whether to return lean host data.
} get_audit_report_hosts_data_t;

/**
 * @brief Parser callback data.
 *
 * This is initially zero because it is a global variable.
 */
static get_audit_report_hosts_data_t get_audit_report_hosts_data;

/**
 * @brief Reset the internal state of the get_audit_report_hosts command.
 */
static void
get_audit_report_hosts_reset (void)
{
  get_data_reset (&get_audit_report_hosts_data.get);
  g_free (get_audit_report_hosts_data.report_id);

  memset (&get_audit_report_hosts_data,
          0,
          sizeof (get_audit_report_hosts_data));
}

/**
 * @brief Initialize the get_audit_report_hosts GMP command.
 *
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
get_audit_report_hosts_start (const gchar **attribute_names,
                              const gchar **attribute_values)
{
  const gchar *attribute;

  get_data_parse_attributes (&get_audit_report_hosts_data.get,
                             "audit_report_host",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names,
                      attribute_values,
                      "report_id",
                      &attribute))
    {
      get_audit_report_hosts_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_audit_report_hosts_data.get,
                          "report_id",
                          attribute);
    }

  if (find_attribute (attribute_names,
                      attribute_values,
                      "lean",
                      &attribute))
    get_audit_report_hosts_data.lean = strcmp (attribute, "0");
  else
    get_audit_report_hosts_data.lean = 0;
}

/**
 * @brief Execute the get_audit_report_hosts GMP command.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] error       Location to store error information.
 */
void
get_audit_report_hosts_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_t report;
  int ret;
  int filtered;
  int count;

  count = 0;

  if (get_audit_report_hosts_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_audit_report_hosts",
          "Missing report_id attribute"));

      get_audit_report_hosts_reset ();
      return;
    }

  ret = init_get ("get_audit_report_hosts",
                  &get_audit_report_hosts_data.get,
                  "Audit Report Hosts",
                  NULL);
  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX (
              "get_audit_report_hosts",
              "Permission denied"));
          break;

        default:
          internal_error_send_to_client (error);
          get_audit_report_hosts_reset ();
          return;
        }

      get_audit_report_hosts_reset ();
      return;
    }

  if (find_report_with_permission (
    get_audit_report_hosts_data.report_id,
    &report,
    "get_reports"))
    {
      internal_error_send_to_client (error);
      get_audit_report_hosts_reset ();
      return;
    }

  if (report == 0)
    {
      if (send_find_error_to_client (
        "get_audit_report_hosts",
        "report",
        get_audit_report_hosts_data.report_id,
        gmp_parser))
        error_send_to_client (error);

      get_audit_report_hosts_reset ();
      return;
    }

  SEND_GET_START ("audit_report_host");

  /*
   * Use the underlying report resource type in the management and SQL
   * layers.
   */
  g_free (get_audit_report_hosts_data.get.subtype);
  get_audit_report_hosts_data.get.subtype = g_strdup ("report_host");

  ret = manage_send_audit_report_hosts (
    report,
    &get_audit_report_hosts_data.get,
    get_audit_report_hosts_data.lean,
    send_to_client,
    gmp_parser->client_writer,
    gmp_parser->client_writer_data);

  if (ret)
    {
      switch (ret)
        {
        case 2:
          if (send_find_error_to_client (
            "get_audit_report_hosts",
            "filter",
            get_audit_report_hosts_data.get.filt_id,
            gmp_parser))
            error_send_to_client (error);
          break;

        case 3:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX (
              "get_audit_report_hosts",
              "Report is not an audit report"));
          break;

        default:
          internal_error_send_to_client (error);
          break;
        }

      get_audit_report_hosts_reset ();
      return;
    }

  filtered = get_audit_report_hosts_data.get.id
               ? 1
               : report_host_count (report);

  SEND_GET_END ("audit_report_host",
                &get_audit_report_hosts_data.get,
                count,
                filtered);

  get_audit_report_hosts_reset ();
}
