/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report exports.
 */

#include "manage_report_exports.h"

#include "manage_audit_report_exports.h"
#include "manage_report_configs.h"
#include "manage_scan_report_exports.h"
#include "manage_sql_report_exports.h"
#include "manage_sql_report_formats.h"
#include "manage_sql_resources.h"
#include "manage_users.h"

#include <glib/gstdio.h>
#include <util/fileutils.h>

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Get the directory for persistent report export files.
 *
 * @return Report export directory.
 */
static const gchar *
report_export_dir (void)
{
  static gchar *path = NULL;

  if (path == NULL)
    path = g_build_filename (GVMD_STATE_DIR,
                             "report-exports",
                             NULL);

  return path;
}

/**
 * @brief Allocate an empty report export model.
 *
 * @return Newly allocated report export model.
 */
report_export_data_t
report_export_data_new (void)
{
  return g_malloc0 (sizeof (struct report_export_data));
}

/**
 * @brief Free a report export model.
 *
 * @param[in] data  Model to free.
 */
void
report_export_data_free (report_export_data_t data)
{
  if (data == NULL)
    return;

  g_free (data->uuid);
  g_free (data->name);
  g_free (data->comment);
  g_free (data->filter);
  g_free (data->file_path);
  g_free (data->content_type);
  g_free (data->extension);
  g_free (data->error_message);

  g_free (data);
}

/**
 * @brief Check whether a report export type is valid.
 *
 * @param[in] type  Report export type.
 *
 * @return TRUE if valid, FALSE otherwise.
 */
gboolean
report_export_type_valid (report_export_type_t type)
{
  return type >= REPORT_EXPORT_TYPE_SCAN
         && type <= REPORT_EXPORT_TYPE_DELTA_AUDIT;
}

/**
 * @brief Check whether a report export status is valid.
 *
 * @param[in] status  Report export status.
 *
 * @return TRUE if valid, FALSE otherwise.
 */
gboolean
report_export_status_valid (report_export_status_t status)
{
  return status >= REPORT_EXPORT_STATUS_PENDING
         && status <= REPORT_EXPORT_STATUS_EXPIRED;
}

/**
 * @brief Check whether a report export progress stage is valid.
 *
 * @param[in] progress  Report export progress stage.
 *
 * @return TRUE if valid, FALSE otherwise.
 */
gboolean
report_export_progress_valid (report_export_progress_t progress)
{
  return progress >= REPORT_EXPORT_PROGRESS_QUEUED
         && progress <= REPORT_EXPORT_PROGRESS_COMPLETED;
}

/**
 * @brief Check whether a report export status is terminal.
 *
 * @param[in] status  Report export status.
 *
 * @return TRUE if terminal, FALSE otherwise.
 */
gboolean
report_export_status_terminal (report_export_status_t status)
{
  return status == REPORT_EXPORT_STATUS_DONE
         || status == REPORT_EXPORT_STATUS_ERROR
         || status == REPORT_EXPORT_STATUS_CANCELED
         || status == REPORT_EXPORT_STATUS_EXPIRED;
}

/**
 * @brief Return the textual representation of a report export type.
 *
 * @param[in] type  Report export type.
 *
 * @return Static string representation.
 */
const gchar *
report_export_type_name (report_export_type_t type)
{
  switch (type)
    {
    case REPORT_EXPORT_TYPE_SCAN:
      return "scan";

    case REPORT_EXPORT_TYPE_AUDIT:
      return "audit";

    case REPORT_EXPORT_TYPE_DELTA_SCAN:
      return "delta_scan";

    case REPORT_EXPORT_TYPE_DELTA_AUDIT:
      return "delta_audit";

    default:
      return "unknown";
    }
}

/**
 * @brief Return the textual representation of a report export status.
 *
 * @param[in] status  Report export status.
 *
 * @return Static string representation.
 */
const gchar *
report_export_status_name (report_export_status_t status)
{
  switch (status)
    {
    case REPORT_EXPORT_STATUS_PENDING:
      return "pending";

    case REPORT_EXPORT_STATUS_RUNNING:
      return "running";

    case REPORT_EXPORT_STATUS_DONE:
      return "done";

    case REPORT_EXPORT_STATUS_ERROR:
      return "error";

    case REPORT_EXPORT_STATUS_CANCEL_REQUESTED:
      return "cancel_requested";

    case REPORT_EXPORT_STATUS_CANCELED:
      return "canceled";

    case REPORT_EXPORT_STATUS_EXPIRED:
      return "expired";

    default:
      return "unknown";
    }
}

/**
 * @brief Return the textual representation of a report export progress stage.
 *
 * @param[in] progress  Report export progress stage.
 *
 * @return Static string representation.
 */
const gchar *
report_export_progress_name (report_export_progress_t progress)
{
  switch (progress)
    {
    case REPORT_EXPORT_PROGRESS_QUEUED:
      return "queued";

    case REPORT_EXPORT_PROGRESS_PREPARING:
      return "preparing";

    case REPORT_EXPORT_PROGRESS_GENERATING:
      return "generating";

    case REPORT_EXPORT_PROGRESS_COMPLETED:
      return "completed";

    default:
      return "unknown";
    }
}

/**
 * @brief Create or reuse a report export request.
 *
 * @param[in]  report              Report to export.
 * @param[in]  delta_report        Optional report used for a delta export.
 * @param[in]  report_format       Report format to use.
 * @param[in]  report_config       Optional report configuration.
 * @param[in]  export_type         Report export type.
 * @param[in]  name                Report export name.
 * @param[in]  comment             Optional report export comment.
 * @param[in]  filter              Optional report filter.
 * @param[in]  ignore_pagination   Whether pagination should be ignored.
 * @param[in]  lean                Whether lean report data should be used.
 * @param[in]  notes_details       Whether note details should be included.
 * @param[in]  overrides_details   Whether override details should be included.
 * @param[in]  result_tags         Whether result tags should be included.
 * @param[out] report_export       Existing or newly created report export.
 * @param[out] status              Current status of the returned export.
 * @param[out] created             TRUE if a new export was created.
 *
 * @return 0 on success, -1 on invalid arguments or failure.
 */
int
manage_create_report_export (report_t report,
                             report_t delta_report,
                             report_format_t report_format,
                             report_config_t report_config,
                             report_export_type_t export_type,
                             const gchar *name,
                             const gchar *comment,
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
  gboolean delta_export;

  if (report == 0
      || report_format == 0
      || name == NULL
      || report_export == NULL
      || status == NULL
      || created == NULL
      || report_export_type_valid (export_type) == FALSE)
    return -1;

  *report_export = 0;
  *status = REPORT_EXPORT_STATUS_PENDING;
  *created = FALSE;

  delta_export = export_type == REPORT_EXPORT_TYPE_DELTA_SCAN
                 || export_type == REPORT_EXPORT_TYPE_DELTA_AUDIT;

  if (delta_export)
    {
      if (delta_report == 0 || delta_report == report)
        return -1;
    }
  else if (delta_report != 0)
    {
      return -1;
    }

  return create_report_export (report,
                               delta_report,
                               report_format,
                               report_config,
                               export_type,
                               name,
                               comment,
                               filter,
                               ignore_pagination,
                               lean,
                               notes_details,
                               overrides_details,
                               result_tags,
                               report_export,
                               status,
                               created);
}

/**
 * @brief Mark a report export as running.
 *
 * @param[in] report_export  Report export.
 * @param [in] worker_pid      PID of the worker process handling the export.
 *
 * @return 0 on success, 1 if the transition is not allowed, -1 on failure.
 */
int
manage_start_report_export (report_export_t report_export, int worker_pid)
{
  report_export_status_t status;

  if (report_export == 0)
    return -1;

  if (get_report_export_status (report_export, &status))
    return -1;

  if (status != REPORT_EXPORT_STATUS_PENDING)
    return 1;

  start_report_export (report_export, worker_pid);

  return 0;
}

/**
 * @brief Update the processing progress of a report export.
 *
 * @param[in] report_export  Report export.
 * @param[in] progress       New progress stage.
 *
 * @return 0 on success, 1 if the transition is not allowed, -1 on failure.
 */
int
manage_set_report_export_progress (
  report_export_t report_export,
  report_export_progress_t progress)
{
  report_export_status_t status;
  report_export_progress_t current_progress;

  if (report_export == 0
      || report_export_progress_valid (progress) == FALSE)
    return -1;

  if (get_report_export_status_and_progress (report_export,
                                             &status,
                                             &current_progress))
    return -1;

  if (status != REPORT_EXPORT_STATUS_RUNNING)
    return 1;

  /*
   * QUEUED is assigned when the request is created
   * COMPLETED is assigned when the generated file is stored.
   */
  if (progress == REPORT_EXPORT_PROGRESS_QUEUED
      || progress == REPORT_EXPORT_PROGRESS_COMPLETED)
    return 1;

  /*
   * Do not allow progress to move backwards.
   */
  if (progress < current_progress)
    return 1;

  if (progress == current_progress)
    return 0;

  set_report_export_progress (report_export, progress);

  return 0;
}

/**
 * @brief Mark a report export as completed.
 *
 * @param[in] report_export  Report export.
 * @param[in] file_path      Generated file path.
 * @param[in] file_size      Generated file size.
 * @param[in] content_type   Generated file content type.
 * @param[in] extension      Generated file extension.
 *
 * @return 0 on success, 1 if the transition is not allowed, -1 on failure.
 */
int
manage_complete_report_export (report_export_t report_export,
                               const gchar *file_path,
                               long long file_size,
                               const gchar *content_type,
                               const gchar *extension)
{
  report_export_status_t status;

  if (report_export == 0
      || file_path == NULL
      || content_type == NULL
      || extension == NULL
      || file_size < 0)
    return -1;

  if (get_report_export_status (report_export, &status))
    return -1;

  if (status != REPORT_EXPORT_STATUS_RUNNING)
    return 1;

  complete_report_export (report_export,
                          file_path,
                          file_size,
                          content_type,
                          extension);

  return 0;
}

/**
 * @brief Mark a report export as failed.
 *
 * @param[in] report_export  Report export.
 * @param[in] error_message  Error description.
 *
 * @return 0 on success, 1 if the transition is not allowed, -1 on failure.
 */
int
manage_fail_report_export (report_export_t report_export,
                           const gchar *error_message)
{
  report_export_status_t status;

  if (report_export == 0 || error_message == NULL)
    return -1;

  if (get_report_export_status (report_export, &status))
    return -1;

  if (report_export_status_terminal (status))
    return 1;

  fail_report_export (report_export, error_message);
  return 0;
}

/**
 * @brief Request cancellation of a report export.
 *
 * A pending report export is canceled immediately. A running report export
 * is moved to the cancel-requested state.
 *
 * @param[in] report_export  Report export.
 *
 * @return 0 on success, 1 if cancellation is not allowed, -1 on failure.
 */
int
manage_request_report_export_cancel (report_export_t report_export)
{
  report_export_status_t status;

  if (report_export == 0)
    return -1;

  if (get_report_export_status (report_export, &status))
    return -1;

  switch (status)
    {
    case REPORT_EXPORT_STATUS_PENDING:
      cancel_report_export (report_export);
      return 0;

    case REPORT_EXPORT_STATUS_RUNNING:
      request_report_export_cancel (report_export);
      return 0;

    case REPORT_EXPORT_STATUS_CANCEL_REQUESTED:
    case REPORT_EXPORT_STATUS_CANCELED:
      return 0;

    default:
      return 1;
    }
}

/**
 * @brief Finish cancellation of a report export.
 *
 * @param[in] report_export  Report export.
 *
 * @return 0 on success, 1 if cancellation was not requested, -1 on failure.
 */
int
manage_finish_report_export_cancel (report_export_t report_export)
{
  report_export_status_t status;

  if (report_export == 0)
    return -1;

  if (get_report_export_status (report_export, &status))
    return -1;

  if (status == REPORT_EXPORT_STATUS_CANCELED)
    return 0;

  if (status != REPORT_EXPORT_STATUS_CANCEL_REQUESTED)
    return 1;

  cancel_report_export (report_export);
  return 0;
}

/**
 * @brief Check whether cancellation was requested for a report export.
 *
 * @param[in] report_export  Report export.
 *
 * @return 1 if cancellation was requested, 0 otherwise, -1 on failure.
 */
int
manage_report_export_cancel_requested (report_export_t report_export)
{
  report_export_status_t status;

  if (report_export == 0)
    return -1;

  if (get_report_export_status (report_export, &status))
    return -1;

  return status == REPORT_EXPORT_STATUS_CANCEL_REQUESTED;
}

/**
 * @brief Check whether a report export worker process is still running.
 *
 * @param[in] worker_pid  PID of the worker process.
 *
 * @return TRUE if the worker is running, FALSE otherwise.
 */
static gboolean
report_export_worker_running (int worker_pid)
{
  if (worker_pid <= 0)
    return FALSE;

  if (kill (worker_pid, 0) == 0)
    return TRUE;

  return errno == EPERM;
}

/**
 * @brief Reset stale report exports.
 *
 * A running report export is considered stale when it has not been updated
 * for the configured timeout and its worker process is no longer running.
 *
 * Stale exports are reset to pending while processing attempts remain.
 * Otherwise they are marked as failed.
 *
 * @param[in] max_attempts  Maximum number of processing attempts.
 * @param[in] stale_timeout Maximum inactivity time in seconds.
 */
void
reset_stale_report_exports (int max_attempts,
                            time_t stale_timeout)
{
  iterator_t iterator;
  get_data_t get = {0};
  time_t threshold;

  threshold = time (NULL) - stale_timeout;

  if (init_report_export_iterator_stale (&iterator,
                                         &get,
                                         threshold))
    {
      g_warning ("%s: failed to initialize stale report export iterator",
                 __func__);
      return;
    }

  while (next (&iterator))
    {
      report_export_t report_export;
      int worker_pid;
      int attempt_count;

      report_export = get_iterator_resource (&iterator);
      worker_pid = report_export_iterator_worker_pid (&iterator);
      attempt_count = report_export_iterator_attempt_count (&iterator);

      /*
       * A worker still exists, so the export is not stale.
       */
      if (report_export_worker_running (worker_pid))
        continue;

      g_warning ("%s: report export %lld has stale worker %d",
                 __func__,
                 report_export,
                 worker_pid);

      if (attempt_count < max_attempts)
        reset_report_export (report_export);
      else
        fail_report_export (
          report_export,
          "Report export worker terminated unexpectedly");
    }

  cleanup_iterator (&iterator);
}

/**
 * @brief Process a report export according to its export type.
 *
 * @param[in] report_export  Report export to process.
 *
 * @return 0 on success, -1 on failure.
 */
int
process_report_export (report_export_t report_export)
{
  report_export_type_t export_type;
  int ret;

  if (get_report_export_type (report_export, &export_type))
    {
      g_warning ("%s: failed to get report export type for %lld",
                 __func__,
                 report_export);
      return -1;
    }

  switch (export_type)
    {
    case REPORT_EXPORT_TYPE_SCAN:
      ret = manage_process_scan_report_export (report_export);
      break;

    case REPORT_EXPORT_TYPE_AUDIT:
      ret = manage_process_audit_report_export (report_export);
      break;

    case REPORT_EXPORT_TYPE_DELTA_SCAN:
    case REPORT_EXPORT_TYPE_DELTA_AUDIT:
      g_warning ("%s: unsupported report export type %s",
                 __func__,
                 report_export_type_name (export_type));

      manage_fail_report_export (
        report_export,
        "Unsupported report export type");

      ret = -1;
      break;

    default:
      g_warning ("%s: invalid report export type %d",
                 __func__,
                 export_type);

      manage_fail_report_export (
        report_export,
        "Invalid report export type");

      ret = -1;
      break;
    }

  return ret;
}

/**
 * @brief Check if a report export is writable.
 *
 * @param report_export Resource identifier.
 * @return Always returns 1 (writable).
 */
int
report_export_writable (report_export_t report_export)
{
  (void) report_export;
  return 1;
}

/**
 * @brief Check if a report export is in-use.
 *
 * @param report_export Resource identifier.
 * @return Always returns 1 (writable).
 */
int
report_export_in_use (report_export_t report_export)
{
  (void) report_export;
  return 0;
}

/**
 * @brief Recover report exports left active by a previous gvmd instance.
 *
 * Running exports are requeued if retries remain. Exports with cancellation
 * requested are marked as canceled.
 *
 * @param[in] max_attempts  Maximum allowed processing attempts.
 */
void
recover_report_exports (int max_attempts)
{
  iterator_t iterator;

  if (init_report_export_iterator_active (&iterator))
    {
      g_warning ("%s: failed to initialize active report export iterator",
                 __func__);
      return;
    }

  while (next (&iterator))
    {
      report_export_t report_export;
      report_export_status_t status;
      int attempt_count;

      report_export = get_iterator_resource (&iterator);
      status = iterator_int (&iterator, 1);
      attempt_count = iterator_int (&iterator, 2);

      if (status == REPORT_EXPORT_STATUS_CANCEL_REQUESTED)
        {
          g_debug ("%s: canceling report export %lld after restart",
                   __func__,
                   report_export);

          cancel_report_export (report_export);
          continue;
        }

      if (attempt_count < max_attempts)
        {
          g_debug ("%s: requeueing report export %lld after restart",
                   __func__,
                   report_export);

          reset_report_export (report_export);
        }
      else
        {
          g_warning ("%s: report export %lld exceeded retry limit",
                     __func__,
                     report_export);

          fail_report_export (
            report_export,
            "Report export worker terminated unexpectedly");
        }
    }

  cleanup_iterator (&iterator);
}

/**
 * @brief Delete a completed report export and its generated file.
 *
 * @param[in] report_export  Report export row id  to delete.
 * @param [in]file_path Path to the generated report export file to delete.
 *
 * @return 0 on success, -1 on failure.
 */
int
manage_delete_report_export (report_export_t report_export,
                             const gchar *file_path)
{
  if (report_export == 0)
    return -1;

  if (file_path
      && g_unlink (file_path)
      && errno != ENOENT)
    {
      g_warning ("%s: failed to remove report export file %s: %s",
                 __func__,
                 file_path,
                 strerror (errno));
      return -1;
    }

  delete_report_export (report_export);

  return 0;
}

/**
 * @brief Find a report export for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of report export.
 * @param[out]  report_export Report Export return,
 *                            0 if successfully failed to find target.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find target), TRUE on error.
 */
gboolean
find_report_export_with_permission (const char *uuid,
                                    report_export_t *report_export,
                                    const char *permission)
{
  return find_resource_with_permission ("report_export", uuid, report_export,
                                        permission, 0);
}

/**
 * @brief Remove old terminal report exports and their generated files.
 *
 * @param[in] retention_seconds Maximum age of report exports in seconds.
 */
void
manage_cleanup_old_report_exports (time_t retention_seconds)
{
  iterator_t iterator;
  time_t threshold;

  threshold = time (NULL) - retention_seconds;
  init_report_export_iterator_cleanup (&iterator, threshold);

  while (next (&iterator))
    {
      report_export_t report_export;
      const gchar *file_path;

      report_export =
        (report_export_t) iterator_int64 (&iterator, 0);

      file_path = iterator_string (&iterator, 1);

      if (manage_delete_report_export (report_export, file_path))
        {
          g_warning ("%s: failed to clean up report export %lld",
                     __func__,
                     report_export);
        }
    }

  cleanup_iterator (&iterator);
}


/**
 * @brief Clean up scan report export file information.
 *
 * @param[in] files  File information to clean up.
 */
void
report_export_files_cleanup (report_export_files_t *files)
{
  if (files == NULL)
    return;

  if (files->work_dir)
    gvm_file_remove_recurse (files->work_dir);

  g_free (files->work_dir);
  g_free (files->xml_start_path);
  g_free (files->xml_target_path);
  g_free (files->formatted_path);
  g_free (files->final_path);
  g_free (files->content_type);
  g_free (files->extension);

  memset (files, 0, sizeof (*files));
}

/**
 * @brief Remove the completed file belonging to an export.
 *
 * @param[in] files  Report export file information.
 */
void
report_export_remove_final_file (
  const report_export_files_t *files)
{
  if (files && files->final_path)
    g_unlink (files->final_path);
}

/**
 * @brief Initialize temporary paths used for report generation.
 *
 * @param[out] files  File information to initialize.
 *
 * @return 0 on success or -1 on failure.
 */
int
init_report_export_files (report_export_files_t *files)
{
  GError *error;

  if (files == NULL)
    return -1;

  memset (files, 0, sizeof (*files));

  error = NULL;

  files->work_dir = g_dir_make_tmp (
    "gvmd-report-export-XXXXXX",
    &error);

  if (files->work_dir == NULL)
    {
      g_warning ("%s: failed to create temporary directory: %s",
                 __func__,
                 error ? error->message : "Unknown error");

      g_clear_error (&error);
      return -1;
    }

  files->xml_start_path = g_build_filename (
    files->work_dir,
    "report-start.xml",
    NULL);

  files->xml_target_path = g_build_filename (
    files->work_dir,
    "report.xml",
    NULL);

  if (files->xml_start_path == NULL
      || files->xml_target_path == NULL)
    {
      report_export_files_cleanup (files);
      return -1;
    }

  return 0;
}

/**
 * @brief Switch report generation to the export owner's user context.
 *
 * @param[out] context  User context to initialize.
 * @param[in]  owner    Owner of the report export.
 *
 * @return 0 on success or -1 on failure.
 */
int
init_report_export_user_context (
  report_export_user_context_t *context,
  user_t owner)
{
  if (context == NULL || owner == 0)
    return -1;

  memset (context, 0, sizeof (*context));

  context->previous_user_uuid = current_credentials.uuid;
  context->export_user_uuid = user_uuid (owner);

  if (context->export_user_uuid == NULL)
    return -1;

  current_credentials.uuid = context->export_user_uuid;
  manage_session_init (current_credentials.uuid);

  context->active = TRUE;

  return 0;
}

/**
 * @brief Restore the user context active before report generation.
 *
 * @param[in] context  User context to restore.
 */
void
cleanup_report_export_user_context (
  report_export_user_context_t *context)
{
  if (context == NULL)
    return;

  if (context->active)
    {
      current_credentials.uuid = context->previous_user_uuid;
      manage_session_init (current_credentials.uuid);
    }

  g_free (context->export_user_uuid);

  memset (context, 0, sizeof (*context));
}

/**
 * @brief Initialize GET data used by the existing XML report generator.
 *
 * @param[in]  data  Stored report export data.
 * @param[out] get   GET data to initialize.
 *
 * @return 0 on success or -1 on failure.
 */
int
init_report_export_get_data (
  const report_export_data_t data,
  get_data_t *get)
{
  if (data == NULL || get == NULL)
    return -1;

  memset (get, 0, sizeof (*get));

  get->type = g_strdup ("result");
  get->filter = g_strdup (data->filter ? data->filter : "");
  get->details = 1;
  get->ignore_pagination = data->ignore_pagination;
  get->ignore_max_rows_per_page = data->ignore_pagination;

  if (get->type == NULL || get->filter == NULL)
    {
      g_free (get->type);
      g_free (get->filter);
      memset (get, 0, sizeof (*get));
      return -1;
    }

  return 0;
}

/**
 * @brief Clean up GET data initialized for report generation.
 *
 * @param[in] get  GET data to clean up.
 */
void
cleanup_report_export_get_data (get_data_t *get)
{
  if (get == NULL)
    return;

  g_free (get->type);
  g_free (get->filter);

  memset (get, 0, sizeof (*get));
}

/**
 * @brief Apply the selected report format to generated scan report XML.
 *
 * @param[in]  data   Report export data.
 * @param[out] files  Report export file information.
 *
 * @return 0 on success or -1 on failure.
 */
int
format_report_export (
  const report_export_data_t data,
  report_export_files_t *files)
{
  gchar *format_uuid;
  GList *used_report_formats;

  if (data == NULL
      || files == NULL
      || files->work_dir == NULL
      || files->xml_start_path == NULL
      || files->xml_target_path == NULL
      || data->report_format == 0)
    return -1;

  if (report_format_active (data->report_format) == 0)
    {
      g_warning ("%s: report format is not active", __func__);
      return -1;
    }

  if (report_format_predefined (data->report_format) == 0
      && report_format_trust (data->report_format) != TRUST_YES)
    {
      g_warning ("%s: report format is not trusted", __func__);
      return -1;
    }

  if (data->report_config
      && report_config_report_format (data->report_config)
      != data->report_format)
    {
      g_warning ("%s: report config is not compatible with report format",
                 __func__);
      return -1;
    }

  format_uuid = report_format_uuid (data->report_format);
  if (format_uuid == NULL)
    return -1;

  used_report_formats = NULL;

  files->formatted_path = apply_report_format (
    format_uuid,
    data->report_config,
    files->xml_start_path,
    files->xml_target_path,
    files->work_dir,
    &used_report_formats);

  g_list_free (used_report_formats);
  g_free (format_uuid);

  if (files->formatted_path == NULL)
    {
      g_warning ("%s: report format returned no output file",
                 __func__);
      return -1;
    }

  return 0;
}

/**
 * @brief Build the final destination path of an exported report.
 *
 * @param[in] export_uuid  UUID of the report export.
 * @param[in] extension    File extension.
 *
 * @return Newly allocated path or NULL on failure.
 */
static gchar *
build_report_export_path (const gchar *export_uuid,
                               const gchar *extension)
{
  gchar *filename;
  gchar *path;

  if (str_blank (export_uuid) || extension == NULL)
    return NULL;

  if (g_mkdir_with_parents (report_export_dir (), 0700))
    {
      g_warning ("%s: failed to create %s: %s",
                 __func__,
                 report_export_dir (),
                 strerror (errno));
      return NULL;
    }

  if (extension[0])
    filename = g_strdup_printf ("%s.%s",
                                export_uuid,
                                extension);
  else
    filename = g_strdup (export_uuid);

  if (filename == NULL)
    return NULL;

  path = g_build_filename (report_export_dir (),
                           filename,
                           NULL);

  g_free (filename);

  return path;
}

/**
 * @brief Store a generated report in its persistent location.
 *
 * @param[in]  data   Report export data.
 * @param[out] files  Report export file information.
 *
 * @return 0 on success or -1 on failure.
 */
int
store_report_export_file (
  const report_export_data_t data,
  report_export_files_t *files)
{
  GStatBuf stat_buffer;

  if (data == NULL
      || files == NULL
      || data->uuid == NULL
      || files->formatted_path == NULL)
    return -1;

  files->extension = report_format_extension (data->report_format);
  files->content_type = report_format_content_type (data->report_format);

  if (files->extension == NULL || files->content_type == NULL)
    {
      g_warning ("%s: report format metadata is incomplete",
                 __func__);
      return -1;
    }

  files->final_path = build_report_export_path (
    data->uuid,
    files->extension);

  if (files->final_path == NULL)
    return -1;

  /*
   * Set the permissions before moving the file. The permissions are preserved
   */
  if (g_chmod (files->formatted_path, 0600))
    {
      g_warning ("%s: failed to set permissions on %s: %s",
                 __func__,
                 files->formatted_path,
                 strerror (errno));
      return -1;
    }

  if (gvm_file_move (files->formatted_path, files->final_path) == FALSE)
    return -1;

  if (g_stat (files->final_path, &stat_buffer))
    {
      g_warning ("%s: failed to stat %s: %s",
                 __func__,
                 files->final_path,
                 strerror (errno));

      g_unlink (files->final_path);
      return -1;
    }

  files->file_size = (long long) stat_buffer.st_size;

  return 0;
}

/**
 * @brief Check whether cancellation was requested.
 *
 * When cancellation is requested, the export is marked as canceled.
 *
 * @param[in] report_export  Report export.
 *
 * @return 0 to continue, 1 if canceled, or -1 on failure.
 */
int
check_report_export_cancel (report_export_t report_export)
{
  int ret;

  ret = manage_report_export_cancel_requested (report_export);
  if (ret < 0)
    return -1;

  if (ret == 0)
    return 0;

  if (manage_finish_report_export_cancel (report_export))
    return -1;

  return 1;
}
