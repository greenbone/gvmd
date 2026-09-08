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
#include "manage_sql.h"

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

// DOWNLOAD_REPORT_EXPORT

/**
 * @brief Command data for the download_report_export command.
 */
typedef struct
{
  gchar *report_export_id;
} download_report_export_data_t;

/**
 * @brief Parser callback data for download_report_export.
 */
static download_report_export_data_t download_report_export_data;

/**
 * @brief Reset the internal state of the <download_report_export> command.
 */
static void
download_report_export_reset ()
{
  g_free (download_report_export_data.report_export_id);
  memset (&download_report_export_data,
          0,
          sizeof (download_report_export_data));
}

/**
 * @brief Initialize the <download_report_export> GMP command.
 *
 * @param[in] attribute_names   Null-terminated array of attribute names.
 * @param[in] attribute_values  Null-terminated array of attribute values.
 */
void
download_report_export_start (const gchar **attribute_names,
                              const gchar **attribute_values)
{
  int index;

  memset (&download_report_export_data,
          0,
          sizeof (download_report_export_data));

  for (index = 0; attribute_names[index]; index++)
    {
      if (strcmp (attribute_names[index], "report_export_id") == 0)
        download_report_export_data.report_export_id =
          g_strdup (attribute_values[index]);
    }
}

/**
 * @brief Send a report export file base64 encoded.
 *
 * @param[in] gmp_parser  GMP parser handling the current session.
 * @param[in] file_path   Path of the generated report export.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_report_export_file (gmp_parser_t *gmp_parser,
                         const gchar *file_path)
{
  FILE *stream;
  guchar chunk[MANAGE_SEND_REPORT_CHUNK_SIZE];

  stream = fopen (file_path, "rb");
  if (stream == NULL)
    {
      g_warning ("%s: failed to open %s: %s",
                 __func__,
                 file_path,
                 strerror (errno));
      return -1;
    }

  while (1)
    {
      size_t bytes_read;

      bytes_read = fread (chunk, 1, sizeof (chunk), stream);

      if (bytes_read > 0)
        {
          gchar *encoded;

          encoded = g_base64_encode (chunk, bytes_read);

          if (send_to_client (encoded,
                              gmp_parser->client_writer,
                              gmp_parser->client_writer_data))
            {
              g_free (encoded);
              fclose (stream);
              return -1;
            }

          g_free (encoded);
        }

      if (ferror (stream))
        {
          g_warning ("%s: failed to read %s",
                     __func__,
                     file_path);
          fclose (stream);
          return -1;
        }

      if (feof (stream))
        break;
    }

  fclose (stream);

  return 0;
}

/**
 * @brief Execute the <download_report_export> GMP command.
 *
 * @param[in] gmp_parser GMP parser handling the current session.
 * @param[in] error      Location to store error information.
 */
void
download_report_export_run (gmp_parser_t *gmp_parser, GError **error)
{
  report_export_t report_export;
  report_export_data_t data;
  const gchar *report_export_id;
  gchar *report_uuid_value;
  gchar *delta_report_uuid_value;
  gchar *report_format_uuid_value;
  gchar *report_config_uuid_value;
  int ret;

  report_export_id = download_report_export_data.report_export_id;

  if (report_export_id == NULL || is_uuid (report_export_id) == 0)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "download_report_export",
          "Missing or invalid report_export_id"));

      download_report_export_reset ();
      return;
    }

  report_export = 0;

  ret = find_report_export_with_permission (
    report_export_id,
    &report_export,
    "get_report_exports");

  if (ret || report_export == 0)
    {
      if (send_find_error_to_client ("download_report_export",
                                     "report_export",
                                     report_export_id,
                                     gmp_parser))
        error_send_to_client (error);

      download_report_export_reset ();
      return;
    }

  data = report_export_data_new ();

  if (load_report_export_data (report_export, data))
    {
      report_export_data_free (data);
      internal_error_send_to_client (error);
      download_report_export_reset ();
      return;
    }

  if (data->status != REPORT_EXPORT_STATUS_DONE)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "download_report_export",
          "Report export is not ready for download"));

      report_export_data_free (data);
      download_report_export_reset ();
      return;
    }

  if (data->file_path == NULL)
    {
      SEND_TO_CLIENT_OR_FAIL (
        XML_ERROR_SYNTAX (
          "download_report_export",
          "Report export file is not available"));

      report_export_data_free (data);
      download_report_export_reset ();
      return;
    }

  report_uuid_value =
    data->report ? report_uuid (data->report) : NULL;

  delta_report_uuid_value =
    data->delta_report ? report_uuid (data->delta_report) : NULL;

  report_format_uuid_value =
    data->report_format ? report_format_uuid (data->report_format) : NULL;

  report_config_uuid_value =
    data->report_config ? report_config_uuid (data->report_config) : NULL;

  SENDF_TO_CLIENT_OR_FAIL (
    "<download_report_export_response"
    " status=\"200\" status_text=\"OK\">"
    "<report_export id=\"%s\">"
    "<type>%s</type>"
    "<status>%s</status>"
    "<progress>%s</progress>",
    data->uuid,
    report_export_type_name (data->export_type),
    report_export_status_name (data->status),
    report_export_progress_name (data->progress));

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
    data->file_size,
    data->content_type ? data->content_type : "",
    data->extension ? data->extension : "");

  SEND_TO_CLIENT_OR_FAIL ("<content>");

  ret = send_report_export_file (gmp_parser, data->file_path);

  if (ret)
    {
      g_free (report_uuid_value);
      g_free (delta_report_uuid_value);
      g_free (report_format_uuid_value);
      g_free (report_config_uuid_value);

      report_export_data_free (data);
      download_report_export_reset ();
      return;
    }

  SEND_TO_CLIENT_OR_FAIL (
    "</content>"
    "</report_export>"
    "</download_report_export_response>");

  /*
   * Remove the export only after the complete response has been sent.
   */
  if (manage_delete_report_export (data->row_id, data->file_path))
    {
      g_warning ("%s: failed to delete downloaded report export %lld",
                 __func__,
                 report_export);
    }

  g_free (report_uuid_value);
  g_free (delta_report_uuid_value);
  g_free (report_format_uuid_value);
  g_free (report_config_uuid_value);

  report_export_data_free (data);
  download_report_export_reset ();
}

/**
 * @brief Handle the end of the download_report_export command.
 *
 * @param[in] gmp_parser  Active GMP parser.
 * @param[in] error       Error location.
 * @param[in] name        Name of the ending XML element.
 *
 * @return 1 when the command has completed, otherwise 0.
 */
int
download_report_export_element_end (gmp_parser_t *gmp_parser,
                                    GError **error,
                                    const gchar *name)
{
  if (strcasecmp (name, "download_report_export") == 0)
    {
      download_report_export_run (gmp_parser, error);
      return 1;
    }

  return 0;
}
