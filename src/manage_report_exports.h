/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report exports.
 */

#ifndef _GVMD_MANAGE_REPORT_EXPORTS_H
#define _GVMD_MANAGE_REPORT_EXPORTS_H

#include "manage.h"

#include <glib.h>

/**
 * @brief Type of report export.
 */
typedef enum
{
  /**
   * Export of a regular vulnerability scan report.
   */
  REPORT_EXPORT_TYPE_SCAN = 0,

  /**
   * Export of an audit or compliance report.
   */
  REPORT_EXPORT_TYPE_AUDIT,

  /**
   * Export comparing two vulnerability scan reports.
   */
  REPORT_EXPORT_TYPE_DELTA_SCAN,

  /**
   * Export comparing two audit or compliance reports.
   */
  REPORT_EXPORT_TYPE_DELTA_AUDIT
} report_export_type_t;

/**
 * @brief Status of a report export.
 */
typedef enum
{
  /**
   * The export is queued and waiting to be processed.
   */
  REPORT_EXPORT_STATUS_PENDING = 0,

  /**
   * The export is currently being processed.
   */
  REPORT_EXPORT_STATUS_RUNNING,

  /**
   * The export completed successfully and its file is available.
   */
  REPORT_EXPORT_STATUS_DONE,

  /**
   * The export failed during processing.
   */
  REPORT_EXPORT_STATUS_ERROR,

  /**
   * Cancellation was requested, but processing has not stopped yet.
   */
  REPORT_EXPORT_STATUS_CANCEL_REQUESTED,

  /**
   * The export was canceled.
   */
  REPORT_EXPORT_STATUS_CANCELED,

  /**
   * The export expired and is no longer available.
   */
  REPORT_EXPORT_STATUS_EXPIRED
} report_export_status_t;

/**
 * @brief Processing progress of a report export.
 *
 * The values represent processing stages, not percentages.
 */
typedef enum
{
  /**
   * The export is queued and waiting for a worker.
   */
  REPORT_EXPORT_PROGRESS_QUEUED = 0,

  /**
   * The worker is preparing report data and temporary files.
   */
  REPORT_EXPORT_PROGRESS_PREPARING,

  /**
   * The report file is being generated and formatted.
   */
  REPORT_EXPORT_PROGRESS_GENERATING,

  /**
   * Report generation completed successfully.
   */
  REPORT_EXPORT_PROGRESS_COMPLETED
} report_export_progress_t;

/**
 * @brief Represents a report export and its metadata.
 */
struct report_export_data
{
  report_export_t row_id;

  gchar *uuid;
  gchar *name;
  gchar *comment;

  user_t owner;

  report_t report;
  report_t delta_report;

  report_format_t report_format;
  report_config_t report_config;

  report_export_type_t export_type;
  report_export_status_t status;
  report_export_progress_t progress;

  gchar *filter;

  gboolean ignore_pagination;
  gboolean lean;
  int worker_pid;

  gboolean notes_details;
  gboolean overrides_details;
  gboolean result_tags;

  gchar *file_path;
  long long file_size;
  gchar *content_type;
  gchar *extension;
  gchar *error_message;

  int attempt_count;

  time_t creation_time;
  time_t start_time;
  time_t end_time;
  time_t modification_time;
};

typedef struct report_export_data *report_export_data_t;

report_export_data_t
report_export_data_new (void);

void
report_export_data_free (report_export_data_t);

int
manage_create_report_export (report_t,
                             report_t,
                             report_format_t,
                             report_config_t,
                             report_export_type_t,
                             const gchar *,
                             const gchar *,
                             const gchar *,
                             gboolean,
                             gboolean,
                             gboolean,
                             gboolean,
                             gboolean,
                             report_export_t *,
                             report_export_status_t *,
                             gboolean *);

int
manage_start_report_export (report_export_t, int);

int
manage_set_report_export_progress (
  report_export_t,
  report_export_progress_t);

int
manage_complete_report_export (report_export_t,
                               const gchar *,
                               long long,
                               const gchar *,
                               const gchar *);

int
manage_fail_report_export (report_export_t,
                           const gchar *);

int
manage_request_report_export_cancel (report_export_t);

int
manage_finish_report_export_cancel (report_export_t);

int
manage_report_export_cancel_requested (report_export_t);

const gchar *
report_export_type_name (report_export_type_t);

const gchar *
report_export_status_name (report_export_status_t);

const gchar *
report_export_progress_name (report_export_progress_t);

gboolean
report_export_type_valid (report_export_type_t);

gboolean
report_export_status_valid (report_export_status_t);

gboolean
report_export_progress_valid (report_export_progress_t);

gboolean
report_export_status_terminal (report_export_status_t);

int
load_report_export_data (report_export_t,
                         report_export_data_t);

void
reset_report_export (report_export_t);

int
init_report_export_iterator_pending (iterator_t *,
                                     get_data_t *,
                                     int);

int
init_report_export_iterator_stale (iterator_t *,
                                   get_data_t *,
                                   time_t);

int
process_report_export (report_export_t);

void
reset_stale_report_exports (int, time_t);

int
report_export_worker_pid_count ();

int
get_report_export_type (report_export_t, report_export_type_t *);

int
init_report_export_iterator (iterator_t *, get_data_t *);

report_t
report_export_iterator_report (iterator_t *);

report_t
report_export_iterator_delta_report (iterator_t *);

report_format_t
report_export_iterator_report_format (iterator_t *);

report_config_t
report_export_iterator_report_config (iterator_t *);

report_export_type_t
report_export_iterator_export_type (iterator_t *);

report_export_status_t
report_export_iterator_status (iterator_t *);

report_export_progress_t
report_export_iterator_progress (iterator_t *);

const gchar *
report_export_iterator_filter (iterator_t *);

int
report_export_iterator_ignore_pagination (iterator_t *);

int
report_export_iterator_lean (iterator_t *);

int
report_export_iterator_worker_pid (iterator_t *);

int
report_export_iterator_notes_details (iterator_t *);

int
report_export_iterator_overrides_details (iterator_t *);

int
report_export_iterator_result_tags (iterator_t *);

const gchar *
report_export_iterator_file_path (iterator_t *);

long long
report_export_iterator_file_size (iterator_t *);

const gchar *
report_export_iterator_content_type (iterator_t *);

const gchar *
report_export_iterator_extension (iterator_t *);

const gchar *
report_export_iterator_error_message (iterator_t *);

int
report_export_iterator_attempt_count (iterator_t *);

time_t
report_export_iterator_start_time (iterator_t *);

time_t
report_export_iterator_end_time (iterator_t *);

const gchar *
report_export_iterator_report_uuid (iterator_t *);

const gchar *
report_export_iterator_delta_report_uuid (iterator_t *);

const gchar *
report_export_iterator_report_format_uuid (iterator_t *);

const gchar *
report_export_iterator_report_format_name (iterator_t *);

const gchar *
report_export_iterator_report_config_uuid (iterator_t *);

const gchar *
report_export_iterator_report_config_name (iterator_t *);

int
report_export_writable (report_export_t);

int
report_export_in_use (resource_t);

int
report_export_count (const get_data_t *);

int
init_report_export_iterator_active (iterator_t *);

void
recover_report_exports (int);

#endif /* _GVMD_MANAGE_REPORT_EXPORTS_H */
