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
#include "manage_scan_report.h"

#include <stdarg.h>

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
  gchar *report_id;
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
  g_free (get_scan_report_data.report_id);

  memset (&get_scan_report_data, 0, sizeof (get_scan_report_data));
}

/**
 * @brief Send escaped XML content to the GMP client.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] format      printf-style format string.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_report_xml (gmp_parser_t *gmp_parser,
                 const gchar *format,
                 ...)
{
  va_list arguments;
  gchar *message;
  gboolean failed;

  if (gmp_parser == NULL || format == NULL)
    return TRUE;

  va_start (arguments, format);
  message = g_markup_vprintf_escaped (format, arguments);
  va_end (arguments);

  if (message == NULL)
    return TRUE;

  failed = send_to_client (message,
                           gmp_parser->client_writer,
                           gmp_parser->client_writer_data);

  g_free (message);

  return failed;
}

/**
 * @brief Send scan report resource count elements.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary       Report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_resource_counts (gmp_parser_t *gmp_parser,
                                  report_summary_t summary)
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
 * @brief Send the detailed task and target information.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary       Report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_task (gmp_parser_t *gmp_parser,
                       report_summary_t summary)
{
  report_task_reference_t task;
  report_target_reference_t target;

  if (summary == NULL)
    return TRUE;

  if (summary->task == NULL || summary->task->id == 0)
    return send_report_xml (gmp_parser, "<task/>");

  task = summary->task;

  if (send_report_xml (
    gmp_parser,
    "<task id=\"%s\">",
    task->uuid ? task->uuid : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<name>%s</name>",
    task->name ? task->name : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<comment>%s</comment>",
    task->comment ? task->comment : ""))
    return TRUE;

  target = task->target;

  if (target
      && target->type != REPORT_TARGET_TYPE_NONE
      && target->type != REPORT_TARGET_TYPE_IMPORT)
    {
      if (send_report_xml (
        gmp_parser,
        "<target id=\"%s\">",
        target->uuid ? target->uuid : ""))
        return TRUE;

      if (send_report_xml (
        gmp_parser,
        "<trash>%d</trash>",
        target->in_trash ? 1 : 0))
        return TRUE;

      if (send_report_xml (
        gmp_parser,
        "<name>%s</name>",
        target->name ? target->name : ""))
        return TRUE;

      if (send_report_xml (
        gmp_parser,
        "<comment>%s</comment>",
        target->comment ? target->comment : ""))
        return TRUE;

      if (send_report_xml (
        gmp_parser,
        "<target_type>%s</target_type>",
        report_target_type_to_string (target->type)))
        return TRUE;

      if (send_report_xml (gmp_parser, "</target>"))
        return TRUE;
    }
  else
    {
      if (send_report_xml (gmp_parser, "<target/>"))
        return TRUE;
    }

  if (send_report_xml (gmp_parser, "<progress>%d</progress>", task->progress))
    return TRUE;

  if (send_report_xml (gmp_parser, "</task>"))
    return TRUE;

  return FALSE;
}

/**
 * @brief Send the result count summary.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] summary       Report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_result_count (gmp_parser_t *gmp_parser,
                               report_summary_t summary)
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
 * @param[in] summary       Report summary.
 *
 * @return FALSE on success, TRUE on failure.
 */
static gboolean
send_scan_report_summary (gmp_parser_t *gmp_parser,
                          report_summary_t summary)
{
  gchar *creation_time = NULL;
  gchar *modification_time = NULL;

  if (summary == NULL)
    return TRUE;

  creation_time = g_strdup (iso_if_time (summary->creation_time));
  modification_time = g_strdup (iso_if_time (summary->modification_time));

  if (send_report_xml (
    gmp_parser,
    "<report id=\"%s\">",
    summary->id ? summary->id : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<owner>"
    "<name>%s</name>"
    "</owner>",
    summary->owner_name ? summary->owner_name : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<name>%s</name>",
    summary->name ? summary->name : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<comment>%s</comment>",
    summary->comment ? summary->comment : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<creation_time>%s</creation_time>",
    creation_time ? creation_time : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<modification_time>%s</modification_time>",
    modification_time ? modification_time : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<writable>0</writable>"))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<in_use>0</in_use>"))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<scan_run_status>%s</scan_run_status>",
    summary->scan_run_status_str
      ? summary->scan_run_status_str
      : ""))
    goto fail;

  if (send_scan_report_resource_counts (gmp_parser, summary))
    goto fail;

  if (send_scan_report_task (gmp_parser, summary))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<timestamp>%s</timestamp>",
    summary->timestamp ? summary->timestamp : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<scan_start>%s</scan_start>",
    summary->scan_start ? summary->scan_start : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<timezone>%s</timezone>",
    summary->timezone ? summary->timezone : ""))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<timezone_abbrev>%s</timezone_abbrev>",
    summary->timezone_abbrev
      ? summary->timezone_abbrev
      : ""))
    goto fail;

  if (send_scan_report_result_count (gmp_parser, summary))
    goto fail;

  if (send_report_xml (
    gmp_parser,
    "<scan_end>%s</scan_end>",
    summary->scan_end ? summary->scan_end : ""))
    goto fail;

  if (send_report_xml (gmp_parser, "</report>"))
    goto fail;

  g_free (creation_time);
  g_free (modification_time);

  return FALSE;

fail:
  g_free (creation_time);
  g_free (modification_time);

  return TRUE;
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
  const gchar *attribute;

  get_data_parse_attributes (&get_scan_report_data.get,
                             "report",
                             attribute_names,
                             attribute_values);

  if (find_attribute (attribute_names,
                      attribute_values,
                      "report_id",
                      &attribute))
    {
      get_scan_report_data.report_id = g_strdup (attribute);

      get_data_set_extra (&get_scan_report_data.get,
                          "report_id",
                          attribute);
    }
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
  report_summary_t summary = NULL;
  int ret;

  if (get_scan_report_data.report_id == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "get_scan_report",
          "Missing report_id attribute"));

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

  // Override the subtype to "report"
  // to ensure correct handling in manage_get_scan_report_summary.
  g_free (get_scan_report_data.get.subtype);
  get_scan_report_data.get.subtype = g_strdup ("report");
  response = manage_get_scan_report_summary (
    get_scan_report_data.report_id,
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
        get_scan_report_data.report_id,
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

  report_summary_free (summary);
  get_scan_report_reset ();

  return;

send_error:
  error_send_to_client (error);
  report_summary_free (summary);
  get_scan_report_reset ();
}
