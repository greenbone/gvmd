/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report exports.
 */

#include "manage_report_exports.h"

#include "manage_sql_report_exports.h"

#undef G_LOG_DOMAIN

/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

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
 * @brief Create a report export request.
 *
 * @param[in]  report              Report to export.
 * @param[in]  delta_report        Optional report used for a delta export.
 * @param[in]  report_format       Report format to use.
 * @param[in]  report_config       Optional report configuration.
 * @param[in]  export_type         Report export type.
 * @param[in]  filter              Optional report filter.
 * @param[in]  ignore_pagination   Whether pagination should be ignored.
 * @param[in]  lean                Whether lean report data should be used.
 * @param[out] report_export       Created report export.
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
                             report_export_t *report_export)
{
  gboolean delta_export;

  if (report == 0
      || report_format == 0
      || name == NULL
      || report_export == NULL
      || report_export_type_valid (export_type) == FALSE)
    return -1;

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
                               report_export);
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
