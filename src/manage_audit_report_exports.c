/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Audit report exports.
 */

#include "manage_audit_report_exports.h"

#include "manage.h"
#include "manage_report_configs.h"
#include "manage_sql_report_exports.h"
#include "manage_sql_users.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Validate and resolve resources used by an audit report export.
 *
 * @param[in]  report_id         UUID of the report to export.
 * @param[out] report            Resolved report.
 * @param[in]  report_format_id  UUID of the report format.
 * @param[out] report_format     Resolved report format.
 * @param[in]  report_config_id  Optional UUID of the report config.
 * @param[out] report_config     Resolved report config.
 *
 * @return Validation result.
 */
static manage_export_audit_report_response_t
validate_audit_report_export (const gchar *report_id,
                              report_t *report,
                              const gchar *report_format_id,
                              report_format_t *report_format,
                              const gchar *report_config_id,
                              report_config_t *report_config)
{
  task_t task;
  gchar *usage_type;
  gchar *format_report_type;
  int ret;

  if (str_blank (report_id) == TRUE
      || report == NULL
      || str_blank (report_format_id) == TRUE
      || report_format == NULL
      || report_config == NULL)
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  *report = 0;
  *report_format = 0;
  *report_config = 0;

  ret = find_report_with_permission (report_id,
                                     report,
                                     "get_reports");
  if (ret)
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  if (*report == 0)
    return MANAGE_EXPORT_AUDIT_REPORT_NOT_FOUND;

  task = 0;

  if (report_task (*report, &task))
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  if (task == 0)
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  usage_type = NULL;

  if (task_usage_type (task, &usage_type))
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  if (usage_type == NULL || strcmp (usage_type, "audit") != 0)
    {
      g_free (usage_type);
      return MANAGE_EXPORT_AUDIT_REPORT_UNSUPPORTED_TYPE;
    }

  ret = find_report_format_with_permission (report_format_id,
                                            report_format,
                                            "get_report_formats");
  if (ret)
    {
      g_free (usage_type);
      return MANAGE_EXPORT_AUDIT_REPORT_ERROR;
    }

  if (*report_format == 0)
    {
      g_free (usage_type);
      return MANAGE_EXPORT_AUDIT_REPORT_FORMAT_NOT_FOUND;
    }

  if (report_format_active (*report_format) == 0)
    {
      g_free (usage_type);
      return MANAGE_EXPORT_AUDIT_REPORT_FORMAT_NOT_FOUND;
    }

  if (report_format_predefined (*report_format) == 0
      && report_format_trust (*report_format) != TRUST_YES)
    {
      g_free (usage_type);
      return MANAGE_EXPORT_AUDIT_REPORT_UNTRUSTED_REPORT_FORMAT;
    }

  format_report_type = report_format_report_type (*report_format);

  if (format_report_type
      && strcmp (format_report_type, "all")
      && strcmp (format_report_type, usage_type))
    {
      g_free (format_report_type);
      g_free (usage_type);
      return MANAGE_EXPORT_AUDIT_REPORT_UNSUPPORTED_TYPE;
    }

  g_free (format_report_type);
  g_free (usage_type);

  if (!str_blank (report_config_id))
    {
      ret = find_report_config_with_permission (report_config_id,
                                                report_config,
                                                "get_report_configs");
      if (ret)
        return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

      if (*report_config == 0)
        return MANAGE_EXPORT_AUDIT_REPORT_CONFIG_NOT_FOUND;

      if (report_config_report_format (*report_config) != *report_format)
        return MANAGE_EXPORT_AUDIT_REPORT_FORMAT_CONFIG_MISMATCH;
    }

  return MANAGE_EXPORT_AUDIT_REPORT_SUCCESS;
}

/**
 * @brief Create a queued audit report export.
 *
 * @param[in]  report_id          UUID of the report to export.
 * @param[in]  report_format_id   UUID of the report format.
 * @param[in]  report_config_id   Optional UUID of the report config.
 * @param[in]  filter             Optional resolved result filter.
 * @param[in]  ignore_pagination  Whether result pagination is ignored.
 * @param[in]  lean               Whether lean report data is generated.
 * @param[in]  notes_details      Whether note details are included.
 * @param[in]  overrides_details  Whether override details are included.
 * @param[in]  result_tags        Whether result tags are included.
 * @param[out] report_export      Created report export.
 * @param[out] status             Status of the report export.
 * @param[out] created            Whether a new report export was created.
 *
 * @return Result of creating the audit report export.
 */
manage_export_audit_report_response_t
manage_export_audit_report (const gchar *report_id,
                            const gchar *report_format_id,
                            const gchar *report_config_id,
                            const gchar *filter,
                            gboolean ignore_pagination,
                            gboolean lean,
                            gboolean notes_details,
                            gboolean overrides_details,
                            gboolean result_tags,
                            report_export_t *report_export,
                            report_export_status_t *status,
                            gboolean *created)
{
  report_t report;
  report_format_t report_format;
  report_config_t report_config;
  manage_export_audit_report_response_t response;

  if (report_export == NULL
      || status == NULL
      || created == NULL)
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  *report_export = 0;
  *status = REPORT_EXPORT_STATUS_PENDING;
  *created = FALSE;

  response = validate_audit_report_export (report_id,
                                           &report,
                                           report_format_id,
                                           &report_format,
                                           report_config_id,
                                           &report_config);
  if (response != MANAGE_EXPORT_AUDIT_REPORT_SUCCESS)
    return response;

  if (manage_create_report_export (report,
                                   0,
                                   report_format,
                                   report_config,
                                   REPORT_EXPORT_TYPE_AUDIT,
                                   "",
                                   "",
                                   filter,
                                   ignore_pagination,
                                   lean,
                                   notes_details,
                                   overrides_details,
                                   result_tags,
                                   report_export,
                                   status,
                                   created))
    return MANAGE_EXPORT_AUDIT_REPORT_ERROR;

  return MANAGE_EXPORT_AUDIT_REPORT_SUCCESS;
}

/**
 * @brief Generate the intermediate XML used by an audit report format.
 *
 * @param[in] data      Report export data.
 * @param[in] xml_path  Destination XML path.
 *
 * @return 0 on success, 2 if the filter cannot be resolved, or -1 on error.
 */
static int
generate_audit_report_export_xml (
  const report_export_data_t data,
  gchar *xml_path)
{
  get_data_t get;
  task_t task;
  int ret;

  if (data == NULL
      || data->report == 0
      || xml_path == NULL)
    return -1;

  task = 0;

  if (report_task (data->report, &task))
    return -1;

  if (task == 0)
    return -1;

  if (init_report_export_get_data (data, &get))
    return -1;

  ret = manage_print_report_xml_start (
    data->report,
    task,
    xml_path,
    &get,
    data->notes_details,
    data->overrides_details,
    data->result_tags,
    data->ignore_pagination,
    data->lean);

  cleanup_report_export_get_data (&get);

  return ret;
}

/**
 * @brief Process a queued audit report export.
 *
 * @param[in] report_export  Report export to process.
 *
 * @return 0 on success, 1 if canceled, or -1 on failure.
 */
int
manage_process_audit_report_export (report_export_t report_export)
{
  report_export_data_t data;
  report_export_files_t files;
  report_export_user_context_t user_context;
  gboolean final_file_stored;
  int ret;

  if (report_export == 0)
    return -1;

  data = NULL;
  memset (&files, 0, sizeof (files));
  memset (&user_context, 0, sizeof (user_context));

  final_file_stored = FALSE;
  ret = -1;

  data = report_export_data_new ();
  if (data == NULL)
    return -1;

  if (load_report_export_data (report_export, data))
    {
      manage_fail_report_export (
        report_export,
        "Failed to load report export data");
      goto cleanup;
    }

  if (data->export_type != REPORT_EXPORT_TYPE_AUDIT
      || data->delta_report != 0)
    {
      manage_fail_report_export (
        report_export,
        "Unsupported audit report export type");
      goto cleanup;
    }

  if (data->status != REPORT_EXPORT_STATUS_RUNNING
      && data->status != REPORT_EXPORT_STATUS_CANCEL_REQUESTED)
    {
      manage_fail_report_export (
        report_export,
        "Report export is not running");
      goto cleanup;
    }

  ret = check_report_export_cancel (report_export);

  if (ret < 0)
    {
      manage_fail_report_export (
        report_export,
        "Failed to check report export cancellation");

      ret = -1;
      goto cleanup;
    }

  if (ret > 0)
    goto cleanup;

  if (init_report_export_user_context (&user_context,
                                       data->owner))
    {
      manage_fail_report_export (
        report_export,
        "Failed to initialize report export user context");
      ret = -1;
      goto cleanup;
    }

  if (init_report_export_files (&files))
    {
      manage_fail_report_export (
        report_export,
        "Failed to initialize report export files");
      ret = -1;
      goto cleanup;
    }

  ret = check_report_export_cancel (report_export);

  if (ret < 0)
    {
      manage_fail_report_export (
        report_export,
        "Failed to check report export cancellation");

      ret = -1;
      goto cleanup;
    }

  if (ret > 0)
    goto cleanup;

  if (manage_set_report_export_progress (
        report_export,
        REPORT_EXPORT_PROGRESS_GENERATING))
    {
      manage_fail_report_export (
        report_export,
        "Failed to update report export progress");
      ret = -1;
      goto cleanup;
    }

  ret = generate_audit_report_export_xml (
    data,
    files.xml_start_path);

  if (ret)
    {
      manage_fail_report_export (
        report_export,
        ret == 2
          ? "Report filter was not found"
          : "Failed to generate audit report XML");

      ret = -1;
      goto cleanup;
    }

  ret = check_report_export_cancel (report_export);

  if (ret < 0)
    {
      manage_fail_report_export (
        report_export,
        "Failed to check report export cancellation");

      ret = -1;
      goto cleanup;
    }

  if (ret > 0)
    goto cleanup;

  if (format_report_export (data, &files))
    {
      manage_fail_report_export (
        report_export,
        "Failed to apply report format");

      ret = -1;
      goto cleanup;
    }

  ret = check_report_export_cancel (report_export);

  if (ret < 0)
    {
      manage_fail_report_export (
        report_export,
        "Failed to check report export cancellation");

      ret = -1;
      goto cleanup;
    }

  if (ret > 0)
    goto cleanup;

  if (store_report_export_file (data, &files))
    {
      manage_fail_report_export (
        report_export,
        "Failed to store generated report");

      ret = -1;
      goto cleanup;
    }

  final_file_stored = TRUE;

  ret = check_report_export_cancel (report_export);

  if (ret < 0)
    {
      manage_fail_report_export (
        report_export,
        "Failed to check report export cancellation");

      ret = -1;
      goto cleanup;
    }

  if (ret > 0)
    goto cleanup;

  if (manage_complete_report_export (
        report_export,
        files.final_path,
        files.file_size,
        files.content_type,
        files.extension))
    {
      manage_fail_report_export (
        report_export,
        "Failed to complete report export");

      ret = -1;
      goto cleanup;
    }

  final_file_stored = FALSE;
  ret = 0;

cleanup:
  if (ret != 0 && final_file_stored)
    report_export_remove_final_file (&files);

  report_export_files_cleanup (&files);
  cleanup_report_export_user_context (&user_context);
  report_export_data_free (data);

  return ret;
}
