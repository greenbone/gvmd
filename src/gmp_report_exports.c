/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report Exports
 *
 * GMP handling for report exports.
 */

#include "gmp_report_exports.h"

#include "gmp_get.h"
#include "manage.h"
#include "manage_report_configs.h"
#include "manage_report_exports.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for the get_report_exports command.
 */
typedef struct
{
  get_data_t get; ///< Get arguments.
} get_report_exports_data_t;

/**
 * @brief Parser callback data.
 *
 * Initially zero because it is a global variable.
 */
static get_report_exports_data_t get_report_exports_data;

/**
 * @brief Reset the internal state of the <get_report_exports> command.
 */
static void
get_report_exports_reset ()
{
  get_data_reset (&get_report_exports_data.get);
  memset (&get_report_exports_data, 0, sizeof (get_report_exports_data));
}

/**
 * @brief Initialize the <get_report_exports> GMP command.
 *
 * @param[in] attribute_names  Null-terminated array of attribute names.
 * @param[in] attribute_values Null-terminated array of corresponding
 *                             attribute values.
 */
void
get_report_exports_start (const gchar **attribute_names,
                          const gchar **attribute_values)
{
  get_data_parse_attributes (&get_report_exports_data.get,
                             "report_export",
                             attribute_names,
                             attribute_values);
}

/**
 * @brief Execute the <get_report_exports> GMP command.
 *
 * @param[in] gmp_parser GMP parser handling the current session.
 * @param[in] error      Location to store error information.
 */
void
get_report_exports_run (gmp_parser_t *gmp_parser, GError **error)
{
  iterator_t report_exports;
  int count, filtered, first, ret;

  count = 0;
  filtered = 0;

  ret = init_get ("get_report_exports",
                  &get_report_exports_data.get,
                  "Report Exports",
                  &first);

  if (ret)
    {
      switch (ret)
        {
        case 99:
          SEND_TO_CLIENT_OR_FAIL (
            XML_ERROR_SYNTAX ("get_report_exports",
              "Permission denied"));
          break;

        default:
          internal_error_send_to_client (error);
          break;
        }

      get_report_exports_reset ();
      return;
    }

  ret = init_report_export_iterator (&report_exports,
                                     &get_report_exports_data.get);

  if (ret)
    {
      internal_error_send_to_client (error);
      get_report_exports_reset ();
      return;
    }

  SEND_GET_START ("report_export");

  while (1)
    {
      report_export_type_t export_type;
      report_export_status_t status;
      report_export_progress_t progress;
      report_t report;
      report_t delta_report;
      report_format_t report_format;
      report_config_t report_config;
      gchar *report_uuid_value;
      gchar *delta_report_uuid_value;
      gchar *report_format_uuid_value;
      gchar *report_config_uuid_value;

      ret = get_next (&report_exports,
                      &get_report_exports_data.get,
                      &first,
                      &count,
                      init_report_export_iterator);

      if (ret == 1)
        break;

      if (ret == -1)
        {
          cleanup_iterator (&report_exports);
          internal_error_send_to_client (error);
          get_report_exports_reset ();
          return;
        }

      export_type =
        report_export_iterator_export_type (&report_exports);
      status =
        report_export_iterator_status (&report_exports);
      progress =
        report_export_iterator_progress (&report_exports);

      report =
        report_export_iterator_report (&report_exports);
      delta_report =
        report_export_iterator_delta_report (&report_exports);
      report_format =
        report_export_iterator_report_format (&report_exports);
      report_config =
        report_export_iterator_report_config (&report_exports);

      report_uuid_value =
        report ? report_uuid (report) : NULL;

      delta_report_uuid_value =
        delta_report ? report_uuid (delta_report) : NULL;

      report_format_uuid_value =
        report_format ? report_format_uuid (report_format) : NULL;

      report_config_uuid_value =
        report_config ? report_config_uuid (report_config) : NULL;

      SEND_GET_COMMON_NO_TRASH (report_export,
                                &get_report_exports_data.get,
                                &report_exports);

      SENDF_TO_CLIENT_OR_FAIL (
        "<type>%s</type>"
        "<status>%s</status>"
        "<progress>%s</progress>",
        report_export_type_name (export_type),
        report_export_status_name (status),
        report_export_progress_name (progress));

      SENDF_TO_CLIENT_OR_FAIL (
        "<report id=\"%s\"/>",
        report_uuid_value ? report_uuid_value : "");

      if (delta_report_uuid_value)
        SENDF_TO_CLIENT_OR_FAIL (
        "<delta_report id=\"%s\"/>",
        delta_report_uuid_value);

      SENDF_TO_CLIENT_OR_FAIL (
        "<report_format id=\"%s\"/>",
        report_format_uuid_value ? report_format_uuid_value : "");

      if (report_config_uuid_value)
        SENDF_TO_CLIENT_OR_FAIL (
        "<report_config id=\"%s\"/>",
        report_config_uuid_value);

      SENDF_TO_CLIENT_OR_FAIL (
        "<file_size>%lld</file_size>"
        "<content_type>%s</content_type>"
        "<extension>%s</extension>",
        report_export_iterator_file_size (&report_exports),
        report_export_iterator_content_type (&report_exports)
        ? report_export_iterator_content_type (&report_exports)
        : "",
        report_export_iterator_extension (&report_exports)
        ? report_export_iterator_extension (&report_exports)
        : "");

      SENDF_TO_CLIENT_OR_FAIL (
        "<error_message>%s</error_message>",
        report_export_iterator_error_message (&report_exports)
        ? report_export_iterator_error_message (&report_exports)
        : "");

      SENDF_TO_CLIENT_OR_FAIL (
        "<attempt_count>%d</attempt_count>",
        report_export_iterator_attempt_count (&report_exports));

      SENDF_TO_CLIENT_OR_FAIL (
        "<start_time>%s</start_time>"
        "<end_time>%s</end_time>",
        iso_if_time (report_export_iterator_start_time (&report_exports)),
        iso_if_time (report_export_iterator_end_time (&report_exports))
        );

      SEND_TO_CLIENT_OR_FAIL ("</report_export>");

      g_free (report_uuid_value);
      g_free (delta_report_uuid_value);
      g_free (report_format_uuid_value);
      g_free (report_config_uuid_value);

      count++;
    }

  cleanup_iterator (&report_exports);

  filtered = get_report_exports_data.get.id
               ? 1
               : report_export_count (&get_report_exports_data.get);

  SEND_GET_END ("report_export",
                &get_report_exports_data.get,
                count,
                filtered);

  get_report_exports_reset ();
}
