/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Structured audit report retrieval.
 *
 * Implements GMP handling for the get_audit_report command.
 */

#include "gmp_audit_report.h"

#include "gmp_get.h"
#include "gmp_report_common.h"
#include "manage_audit_report.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_audit_report command.
 */
typedef struct
{
  get_data_t get;
} get_audit_report_data_t;

/**
 * @brief Parser callback data.
 */
static get_audit_report_data_t get_audit_report_data;

/**
 * @brief Reset the internal state of the get_audit_report command.
 */
static void
get_audit_report_reset (void)
{
  get_data_reset (&get_audit_report_data.get);

  memset (&get_audit_report_data,
          0,
          sizeof (get_audit_report_data));
}

/**
 * @brief Send audit report compliance counts.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary     Audit report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_audit_report_compliance_count (
  gmp_parser_t *gmp_parser,
  audit_report_summary_t summary)
{
  const audit_report_result_summary_t *results;

  if (gmp_parser == NULL || summary == NULL)
    return TRUE;

  results = &summary->results;

  if (send_report_xml (
        gmp_parser,
        "<compliance_count>%d",
        results->total.full))
    return TRUE;

  if (send_report_xml (
        gmp_parser,
        "<full>%d</full>"
        "<filtered>%d</filtered>",
        results->total.full,
        results->total.filtered))
    return TRUE;

  if (send_report_xml (
        gmp_parser,
        "<yes>"
        "<full>%d</full>"
        "<filtered>%d</filtered>"
        "</yes>",
        results->yes.full,
        results->yes.filtered))
    return TRUE;

  if (send_report_xml (
        gmp_parser,
        "<no>"
        "<full>%d</full>"
        "<filtered>%d</filtered>"
        "</no>",
        results->no.full,
        results->no.filtered))
    return TRUE;

  if (send_report_xml (
        gmp_parser,
        "<incomplete>"
        "<full>%d</full>"
        "<filtered>%d</filtered>"
        "</incomplete>",
        results->incomplete.full,
        results->incomplete.filtered))
    return TRUE;

  if (send_report_xml (
        gmp_parser,
        "<undefined>"
        "<full>%d</full>"
        "<filtered>%d</filtered>"
        "</undefined>",
        results->undefined.full,
        results->undefined.filtered))
    return TRUE;

  return send_report_xml (gmp_parser, "</compliance_count>");
}

/**
 * @brief Send full and filtered audit compliance values.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary     Audit report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_audit_report_compliance (
  gmp_parser_t *gmp_parser,
  audit_report_summary_t summary)
{
  const audit_report_compliance_t *compliance;

  if (gmp_parser == NULL || summary == NULL)
    return TRUE;

  compliance = &summary->results.compliance;

  return send_report_xml (
    gmp_parser,
    "<compliance>"
    "<full>%s</full>"
    "<filtered>%s</filtered>"
    "</compliance>",
    compliance->full ? compliance->full : "",
    compliance->filtered ? compliance->filtered : "");
}

/**
 * @brief Send the complete structured audit report.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary     Audit report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_audit_report_summary (gmp_parser_t *gmp_parser,
                           audit_report_summary_t summary)
{
  if (gmp_parser == NULL
      || summary == NULL
      || summary->base == NULL)
    return TRUE;

  if (send_report_base_start (gmp_parser, summary->base))
    return TRUE;

  if (send_report_resource_counts (gmp_parser, summary->resources))
    return TRUE;

  if (send_report_task (gmp_parser, summary->task))
    return TRUE;

  if (send_report_scan_information (gmp_parser, summary->base))
    return TRUE;

  if (send_audit_report_compliance_count (gmp_parser, summary))
    return TRUE;

  if (send_audit_report_compliance (gmp_parser, summary))
    return TRUE;

  if (send_report_base_end (gmp_parser, summary->base))
    return TRUE;

  return FALSE;
}

/**
 * @brief Initialize the get_audit_report command by parsing attributes.
 *
 * @param[in] attribute_names   Null-terminated attribute names.
 * @param[in] attribute_values  Null-terminated attribute values.
 */
void
get_audit_report_start (const gchar **attribute_names,
                        const gchar **attribute_values)
{
  get_data_parse_attributes (&get_audit_report_data.get,
                             "audit_report",
                             attribute_names,
                             attribute_values);
}

/**
 * @brief Execute the get_audit_report GMP command.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] error       Location for error information.
 */
void
get_audit_report_run (gmp_parser_t *gmp_parser,
                      GError **error)
{
  manage_get_audit_report_response_t response;
  audit_report_summary_t summary = NULL;
  int ret;

  if (get_audit_report_data.get.id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_audit_report",
          "Missing audit_report_id attribute"));

      get_audit_report_reset ();
      return;
    }

  ret = init_get ("get_audit_report",
                  &get_audit_report_data.get,
                  "Audit Reports",
                  NULL);

  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX (
              "get_audit_report",
              "Permission denied"));
          break;

        default:
          internal_error_send_to_client (error);
          break;
        }

      get_audit_report_reset ();
      return;
    }

  /*
   * Use the underlying report resource type in the management and SQL
   * layers.
   */
  g_free (get_audit_report_data.get.subtype);
  get_audit_report_data.get.subtype = g_strdup ("report");

  response = manage_get_audit_report_summary (
    &get_audit_report_data.get,
    &summary);

  switch (response)
    {
    case MANAGE_GET_AUDIT_REPORT_SUCCESS:
      break;

    case MANAGE_GET_AUDIT_REPORT_NOT_FOUND:
      if (send_find_error_to_client (
            "get_audit_report",
            "report",
            get_audit_report_data.get.id,
            gmp_parser))
        error_send_to_client (error);

      get_audit_report_reset ();
      return;

    case MANAGE_GET_AUDIT_REPORT_FILTER_NOT_FOUND:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_audit_report",
          "Failed to find filter"));

      get_audit_report_reset ();
      return;

    case MANAGE_GET_AUDIT_REPORT_UNSUPPORTED_TYPE:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_audit_report",
          "Report type is not supported"));

      get_audit_report_reset ();
      return;

    case MANAGE_GET_AUDIT_REPORT_ERROR:
    default:
      internal_error_send_to_client (error);
      get_audit_report_reset ();
      return;
    }

  SEND_GET_START_SINGULAR ("audit_report");

  if (send_audit_report_summary (gmp_parser, summary))
    goto send_error;

  SEND_GET_END_SINGULAR ("audit_report",
                         &get_audit_report_data.get,
                         1,
                         1);

  audit_report_summary_free (summary);
  get_audit_report_reset ();

  return;

send_error:
  error_send_to_client (error);
  audit_report_summary_free (summary);
  get_audit_report_reset ();
}
