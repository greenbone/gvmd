/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Common structured report serialization.
 */

#include "gmp_report_common.h"

#include <stdarg.h>

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Send escaped XML content to the GMP client.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] format      printf-style format string.
 *
 * @return FALSE on success, TRUE on failure.
 */
gboolean
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
 * @brief Send the common opening section of a structured report.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] base        Common report summary data.
 *
 * @return FALSE on success, TRUE on failure.
 */
gboolean
send_report_base_start (gmp_parser_t *gmp_parser,
                        report_summary_base_t base)
{
  const gchar *creation_time;
  const gchar *modification_time;

  if (gmp_parser == NULL || base == NULL)
    return TRUE;

  creation_time = iso_if_time (base->creation_time);
  modification_time = iso_if_time (base->modification_time);

  if (send_report_xml (
    gmp_parser,
    "<report id=\"%s\">",
    base->id ? base->id : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<owner>"
    "<name>%s</name>"
    "</owner>",
    base->owner_name ? base->owner_name : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<name>%s</name>",
    base->name ? base->name : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<comment>%s</comment>",
    base->comment ? base->comment : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<creation_time>%s</creation_time>",
    creation_time ? creation_time : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<modification_time>%s</modification_time>",
    modification_time ? modification_time : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<writable>0</writable>"))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<in_use>0</in_use>"))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<scan_run_status>%s</scan_run_status>",
    base->scan_run_status_str
      ? base->scan_run_status_str
      : ""))
    return TRUE;

  return FALSE;
}

/**
 * @brief Send the task and target associated with a report.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] task        Report task reference.
 *
 * @return FALSE on success, TRUE on failure.
 */
gboolean
send_report_task (gmp_parser_t *gmp_parser,
                  report_task_reference_t task)
{
  report_target_reference_t target;

  if (gmp_parser == NULL)
    return TRUE;

  if (task == NULL || task->id == 0)
    return send_report_xml (gmp_parser, "<task/>");

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

  if (send_report_xml (
    gmp_parser,
    "<progress>%d</progress>",
    task->progress))
    return TRUE;

  if (send_report_xml (gmp_parser, "</task>"))
    return TRUE;

  return FALSE;
}

/**
 * @brief Send common scan timing and timezone information.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] base        Common report summary data.
 *
 * @return FALSE on success, TRUE on failure.
 */
gboolean
send_report_scan_information (gmp_parser_t *gmp_parser,
                              report_summary_base_t base)
{
  if (gmp_parser == NULL || base == NULL)
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<timestamp>%s</timestamp>",
    base->timestamp ? base->timestamp : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<scan_start>%s</scan_start>",
    base->scan_start ? base->scan_start : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<timezone>%s</timezone>",
    base->timezone ? base->timezone : ""))
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<timezone_abbrev>%s</timezone_abbrev>",
    base->timezone_abbrev
      ? base->timezone_abbrev
      : ""))
    return TRUE;

  return FALSE;
}

/**
 * @brief Send the closing section of a structured report.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] base        Common report summary data.
 *
 * @return FALSE on success, TRUE on failure.
 */
gboolean
send_report_base_end (gmp_parser_t *gmp_parser,
                      report_summary_base_t base)
{
  if (gmp_parser == NULL || base == NULL)
    return TRUE;

  if (send_report_xml (
    gmp_parser,
    "<scan_end>%s</scan_end>",
    base->scan_end ? base->scan_end : ""))
    return TRUE;

  return send_report_xml (gmp_parser, "</report>");
}
