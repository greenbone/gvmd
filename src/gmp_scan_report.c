/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Structured scan report retrieval.
 *
 * Implements GMP handling for the get_scan_report command.
 */

#include "gmp_scan_report.h"

#include "gmp_get.h"
#include "gmp_report_common.h"
#include "manage_scan_report.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_scan_report command.
 */
typedef struct
{
  get_data_t get;
} get_scan_report_data_t;

/**
 * @brief Parser callback data.
 */
static get_scan_report_data_t get_scan_report_data;

/**
 * @brief Reset the internal state of the get_scan_report command.
 */
static void
get_scan_report_reset (void)
{
  get_data_reset (&get_scan_report_data.get);

  memset (&get_scan_report_data, 0, sizeof (get_scan_report_data));
}

/**
 * @brief Send scan report resource count elements.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary     Scan report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_resource_counts (gmp_parser_t *gmp_parser,
                                  scan_report_summary_t summary)
{
  report_resource_summary_t resources;

  if (summary == NULL || summary->resources == NULL)
    return TRUE;

  resources = summary->resources;

  if (send_report_xml (
    gmp_parser,
    "<hosts><count>%d</count></hosts>",
    resources->hosts))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<closed_cves><count>%d</count></closed_cves>",
    resources->closed_cves))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<cves><count>%d</count></cves>",
    resources->cves))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<vulns><count>%d</count></vulns>",
    resources->vulnerabilities))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<os><count>%d</count></os>",
    resources->operating_systems))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<apps><count>%d</count></apps>",
    resources->applications))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<ssl_certs><count>%d</count></ssl_certs>",
    resources->tls_certificates))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<ports><count>%d</count></ports>",
    resources->ports))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<errors><count>%d</count></errors>",
    resources->errors))
    return TRUE;

  return FALSE;
}

/**
 * @brief Send the result count summary.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary     Scan report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_result_count (gmp_parser_t *gmp_parser,
                               scan_report_summary_t summary)
{
  const report_result_summary_t *results;

  if (summary == NULL)
    return TRUE;

  results = &summary->results;

  if (send_report_xml (
    gmp_parser,
    "<result_count>%d",
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
    "<critical>"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</critical>",
    results->critical.full,
    results->critical.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<hole deprecated=\"1\">"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</hole>",
    results->high.full,
    results->high.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<high>"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</high>",
    results->high.full,
    results->high.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<info deprecated=\"1\">"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</info>",
    results->low.full,
    results->low.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<low>"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</low>",
    results->low.full,
    results->low.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<log>"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</log>",
    results->log.full,
    results->log.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<warning deprecated=\"1\">"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</warning>",
    results->medium.full,
    results->medium.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<medium>"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</medium>",
    results->medium.full,
    results->medium.filtered))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<false_positive>"
    "<full>%d</full>"
    "<filtered>%d</filtered>"
    "</false_positive>",
    results->false_positive.full,
    results->false_positive.filtered))
    return TRUE;

  if (send_report_xml (gmp_parser, "</result_count>"))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<severity>"
    "<full>%.1f</full>"
    "<filtered>%.1f</filtered>"
    "</severity>",
    results->severity.full,
    results->severity.filtered))
    return TRUE;

  return FALSE;
}

/**
 * @brief Send the complete structured scan report.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary     Scan report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_summary (gmp_parser_t *gmp_parser,
                          scan_report_summary_t summary)
{
  if (gmp_parser == NULL
      || summary == NULL
      || summary->base == NULL)
    return TRUE;

  if (send_report_base_start (gmp_parser, summary->base))
    return TRUE;

  if (send_scan_report_resource_counts (gmp_parser, summary))
    return TRUE;

  if (send_report_task (gmp_parser, summary->task))
    return TRUE;

  if (send_report_scan_information (gmp_parser, summary->base))
    return TRUE;

  if (send_scan_report_result_count (gmp_parser, summary))
    return TRUE;

  if (send_report_base_end (gmp_parser, summary->base))
    return TRUE;

  return FALSE;
}

/**
 * @brief Initialize the get_scan_report command by parsing attributes.
 *
 * @param[in] attribute_names   Null-terminated attribute names.
 * @param[in] attribute_values  Null-terminated attribute values.
 */
void
get_scan_report_start (const gchar **attribute_names,
                       const gchar **attribute_values)
{
  get_data_parse_attributes (&get_scan_report_data.get,
                             "scan_report",
                             attribute_names,
                             attribute_values);
}

/**
 * @brief Execute the get_scan_report GMP command.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] error       Location for error information.
 */
void
get_scan_report_run (gmp_parser_t *gmp_parser,
                     GError **error)
{
  manage_get_scan_report_response_t response;
  scan_report_summary_t summary = NULL;
  int ret;

  if (get_scan_report_data.get.id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_scan_report",
          "Missing scan_report_id attribute"));

      get_scan_report_reset ();
      return;
    }

  ret = init_get ("get_scan_report",
                  &get_scan_report_data.get,
                  "Scan Reports",
                  NULL);

  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX (
              "get_scan_report",
              "Permission denied"));
          break;

        default:
          internal_error_send_to_client (error);
          break;
        }

      get_scan_report_reset ();
      return;
    }

  /*
   * Override the subtype with the underlying report resource type used by
   * the management and SQL layers.
   */
  g_free (get_scan_report_data.get.subtype);
  get_scan_report_data.get.subtype = g_strdup ("report");

  response = manage_get_scan_report_summary (
    &get_scan_report_data.get,
    &summary);

  switch (response)
    {
    case MANAGE_GET_SCAN_REPORT_SUCCESS:
      break;

    case MANAGE_GET_SCAN_REPORT_NOT_FOUND:
      if (send_find_error_to_client (
        "get_scan_report",
        "report",
        get_scan_report_data.get.id,
        gmp_parser))
        error_send_to_client (error);

      get_scan_report_reset ();
      return;

    case MANAGE_GET_SCAN_REPORT_FILTER_NOT_FOUND:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_scan_report",
          "Failed to find filter"));

      get_scan_report_reset ();
      return;

    case MANAGE_GET_SCAN_REPORT_UNSUPPORTED_TYPE:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_scan_report",
          "Report type is not supported"));

      get_scan_report_reset ();
      return;

    case MANAGE_GET_SCAN_REPORT_ERROR:
    default:
      internal_error_send_to_client (error);
      get_scan_report_reset ();
      return;
    }

  SEND_GET_START_SINGULAR ("scan_report");

  if (send_scan_report_summary (gmp_parser, summary))
    goto send_error;

  SEND_GET_END_SINGULAR ("scan_report",
                         &get_scan_report_data.get,
                         1,
                         1);

  scan_report_summary_free (summary);
  get_scan_report_reset ();

  return;

send_error:
  error_send_to_client (error);
  scan_report_summary_free (summary);
  get_scan_report_reset ();
}
