/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Scan report exports.
 *
 * Implements the export_scan_report GMP command.
 */

#include "gmp_scan_report_exports.h"

#include "manage_acl.h"
#include "manage_scan_report_exports.h"
#include "manage_sql_report_exports.h"

#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    gmp"

/**
 * @brief Command data for export_scan_report.
 */
typedef struct
{
  gchar *report_id;
  gchar *format_id;
  gchar *config_id;

  gchar *filter;

  int lean;
  int notes_details;
  int overrides_details;
  int result_tags;
  int ignore_pagination;
} export_scan_report_data_t;

/**
 * @brief Parser data for export_scan_report.
 */
static export_scan_report_data_t export_scan_report_data;

/**
 * @brief Reset export_scan_report command data.
 */
static void
export_scan_report_reset (void)
{
  g_free (export_scan_report_data.report_id);
  g_free (export_scan_report_data.format_id);
  g_free (export_scan_report_data.config_id);

  g_free (export_scan_report_data.filter);

  memset (&export_scan_report_data,
          0,
          sizeof (export_scan_report_data));
}

/**
 * @brief Start the export_scan_report command.
 *
 * @param[in] gmp_parser        Active GMP parser.
 * @param[in] attribute_names   Command attribute names.
 * @param[in] attribute_values  Command attribute values.
 */
void
export_scan_report_start (gmp_parser_t *gmp_parser,
                          const gchar **attribute_names,
                          const gchar **attribute_values)
{
  const gchar *attribute;

  (void) gmp_parser;

  export_scan_report_reset ();

  append_attribute (attribute_names,
                    attribute_values,
                    "report_id",
                    &export_scan_report_data.report_id);

  append_attribute (attribute_names,
                    attribute_values,
                    "format_id",
                    &export_scan_report_data.format_id);

  append_attribute (attribute_names,
                    attribute_values,
                    "config_id",
                    &export_scan_report_data.config_id);

  append_attribute (attribute_names,
                    attribute_values,
                    "filter",
                    &export_scan_report_data.filter);

  if (find_attribute (attribute_names,
                      attribute_values,
                      "lean",
                      &attribute))
    export_scan_report_data.lean = atoi (attribute);
  else
    export_scan_report_data.lean = 0;

  if (find_attribute (attribute_names,
                      attribute_values,
                      "notes_details",
                      &attribute))
    export_scan_report_data.notes_details =
      strcmp (attribute, "0");
  else
    export_scan_report_data.notes_details = 0;

  if (find_attribute (attribute_names,
                      attribute_values,
                      "overrides_details",
                      &attribute))
    export_scan_report_data.overrides_details =
      strcmp (attribute, "0");
  else
    export_scan_report_data.overrides_details = 0;

  if (find_attribute (attribute_names,
                      attribute_values,
                      "result_tags",
                      &attribute))
    export_scan_report_data.result_tags =
      strcmp (attribute, "0");
  else
    export_scan_report_data.result_tags = 0;

  if (find_attribute (attribute_names,
                      attribute_values,
                      "ignore_pagination",
                      &attribute))
    export_scan_report_data.ignore_pagination =
      atoi (attribute);
  else
    export_scan_report_data.ignore_pagination = 0;
}

/**
 * @brief Execute the export_scan_report command.
 *
 * Creates a pending scan report export or returns an existing matching
 * export that is pending, running or completed.
 *
 * Report generation is performed asynchronously by the report export worker.
 *
 * @param[in] gmp_parser  Active GMP parser.
 * @param[in] error       Error location.
 */
void
export_scan_report_run (gmp_parser_t *gmp_parser,
                        GError **error)
{
  manage_export_scan_report_response_t response;
  report_export_data_t export_data;
  report_export_t report_export;
  report_export_status_t status;
  gboolean created;

  report_export = 0;
  export_data = NULL;
  status = REPORT_EXPORT_STATUS_PENDING;
  created = FALSE;

  if (!acl_user_may ("get_reports")
      || !acl_user_may ("get_report_formats")
      || !acl_user_may ("get_report_configs")
      || !acl_user_may ("export_scan_report"))
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Permission denied"));

      export_scan_report_reset ();
      return;
    }

  if (export_scan_report_data.report_id == NULL
      || !is_uuid (export_scan_report_data.report_id))
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Missing or invalid report_id"));

      export_scan_report_reset ();
      return;
    }

  if (export_scan_report_data.format_id == NULL
      || !is_uuid (export_scan_report_data.format_id))
    {
      /**
       * Set XML report format to the default format if not specified.
       */
      export_scan_report_data.format_id = g_strdup (REPORT_FORMAT_UUID_XML);
    }

  if (export_scan_report_data.config_id
      && export_scan_report_data.config_id[0]
      && !is_uuid (export_scan_report_data.config_id))
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Invalid config_id"));

      export_scan_report_reset ();
      return;
    }

  response = manage_export_scan_report (
    export_scan_report_data.report_id,
    export_scan_report_data.format_id,
    export_scan_report_data.config_id,
    export_scan_report_data.filter
      ? export_scan_report_data.filter
      : "",
    export_scan_report_data.ignore_pagination,
    export_scan_report_data.lean,
    export_scan_report_data.notes_details,
    export_scan_report_data.overrides_details,
    export_scan_report_data.result_tags,
    &report_export,
    &status,
    &created);

  switch (response)
    {
    case MANAGE_EXPORT_SCAN_REPORT_SUCCESS:
      {
        const gchar *status_name;

        export_data = report_export_data_new ();

        if (export_data == NULL
            || load_report_export_data (report_export, export_data)
            || export_data->uuid == NULL)
          {
            report_export_data_free (export_data);

            SEND_TO_CLIENT_OR_FAIL (
              XML_INTERNAL_ERROR ("export_scan_report"));

            log_event_fail ("report_export",
                            "Report Export",
                            NULL,
                            created ? "created" : "reused");

            export_scan_report_reset ();
            return;
          }

        status_name = report_export_status_name (status);

        if (status_name == NULL)
          status_name = "unknown";

        if (created)
          {
            /*
             * A new pending report export was created.
             */
            SENDF_TO_CLIENT_OR_FAIL (
              XML_OK_CREATED_ID ("export_scan_report"),
              export_data->uuid);

            log_event ("report_export",
                       "Report Export",
                       export_data->uuid,
                       "created");
          }
        else
          {
            /*
             * An existing matching report export was reused.
             */
            SENDF_TO_CLIENT_OR_FAIL (
              "<export_scan_report_response"
              " status=\"200\""
              " status_text=\"OK\""
              " id=\"%s\""
              " export_status=\"%s\"/>",
              export_data->uuid,
              status_name);

            log_event ("report_export",
                       "Report Export",
                       export_data->uuid,
                       "reused");
          }

        report_export_data_free (export_data);
        break;
      }

    case MANAGE_EXPORT_SCAN_REPORT_NOT_FOUND:
      if (send_find_error_to_client (
            "export_scan_report",
            "report",
            export_scan_report_data.report_id,
            gmp_parser))
        error_send_to_client (error);

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_FORMAT_NOT_FOUND:
      if (send_find_error_to_client (
            "export_scan_report",
            "report_format",
            export_scan_report_data.format_id,
            gmp_parser))
        error_send_to_client (error);

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_CONFIG_NOT_FOUND:
      if (send_find_error_to_client (
            "export_scan_report",
            "report_config",
            export_scan_report_data.config_id,
            gmp_parser))
        error_send_to_client (error);

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_FILTER_NOT_FOUND:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Report filter was not found"));

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_UNSUPPORTED_TYPE:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Report is not a scan report"));

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_DELTA_REPORT_NOT_FOUND:
    case MANAGE_EXPORT_SCAN_REPORT_INVALID_DELTA_REPORT:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Delta reports are not supported"));

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_UNTRUSTED_REPORT_FORMAT:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Report format is untrusted"));

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_FORMAT_CONFIG_MISMATCH:
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX ("export_scan_report",
                          "Report format does not match report config"));

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;

    case MANAGE_EXPORT_SCAN_REPORT_ERROR:
    default:
      SEND_TO_CLIENT_OR_FAIL (
        XML_INTERNAL_ERROR ("export_scan_report"));

      log_event_fail ("report_export",
                      "Report Export",
                      NULL,
                      "created");
      break;
    }

  export_scan_report_reset ();
}

/**
 * @brief Handle the end of the export_scan_report command.
 *
 * @param[in] gmp_parser  Active GMP parser.
 * @param[in] error       Error location.
 * @param[in] name        Name of the ending XML element.
 *
 * @return 1 when the command has completed, otherwise 0.
 */
int
export_scan_report_element_end (gmp_parser_t *gmp_parser,
                                GError **error,
                                const gchar *name)
{
  if (strcasecmp (name, "export_scan_report") == 0)
    {
      export_scan_report_run (gmp_parser, error);
      return 1;
    }

  return 0;
}
