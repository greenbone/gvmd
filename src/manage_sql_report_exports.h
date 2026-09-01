/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL management layer: Report exports.
 */

#ifndef _GVM_MANAGE_SQL_REPORT_EXPORTS_H
#define _GVM_MANAGE_SQL_REPORT_EXPORTS_H

#include "manage_report_exports.h"
#include "manage_sql.h"

#include <glib.h>
#include <time.h>

/**
 * @brief Report export iterator columns.
 */
#define REPORT_EXPORT_ITERATOR_COLUMNS                                     \
  {                                                                        \
    GET_ITERATOR_COLUMNS (report_exports),                                 \
    { "report", NULL, KEYWORD_TYPE_INTEGER },                              \
    { "delta_report", NULL, KEYWORD_TYPE_INTEGER },                        \
    { "report_format", NULL, KEYWORD_TYPE_INTEGER },                       \
    { "report_config", NULL, KEYWORD_TYPE_INTEGER },                       \
    { "export_type", NULL, KEYWORD_TYPE_INTEGER },                         \
    { "status", NULL, KEYWORD_TYPE_INTEGER },                              \
    { "progress", NULL, KEYWORD_TYPE_INTEGER },                            \
    { "filter", NULL, KEYWORD_TYPE_STRING },                               \
    { "ignore_pagination", NULL, KEYWORD_TYPE_INTEGER },                   \
    { "lean", NULL, KEYWORD_TYPE_INTEGER },                                \
    { "worker_pid", NULL, KEYWORD_TYPE_INTEGER },                          \
    { "notes_details", NULL, KEYWORD_TYPE_INTEGER },                       \
    { "overrides_details", NULL, KEYWORD_TYPE_INTEGER },                   \
    { "result_tags", NULL, KEYWORD_TYPE_INTEGER },                         \
    { "file_path", NULL, KEYWORD_TYPE_STRING },                            \
    { "file_size", NULL, KEYWORD_TYPE_INTEGER },                           \
    { "content_type", NULL, KEYWORD_TYPE_STRING },                         \
    { "extension", NULL, KEYWORD_TYPE_STRING },                            \
    { "error_message", NULL, KEYWORD_TYPE_STRING },                        \
    { "attempt_count", NULL, KEYWORD_TYPE_INTEGER },                       \
    { "start_time", NULL, KEYWORD_TYPE_INTEGER },                          \
    { "end_time", NULL, KEYWORD_TYPE_INTEGER },                            \
    { "report_uuid", "report_uuid", KEYWORD_TYPE_STRING },                 \
    { "delta_report_uuid", "delta_report_uuid", KEYWORD_TYPE_STRING },     \
    { "report_format_uuid", "report_format_uuid", KEYWORD_TYPE_STRING },   \
    { "report_format_name", "report_format_name", KEYWORD_TYPE_STRING },   \
    { "report_config_uuid", "report_config_uuid", KEYWORD_TYPE_STRING },   \
    { "report_config_name", "report_config_name", KEYWORD_TYPE_STRING },   \
    { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                                   \
  }

/**
 * @brief Filter columns for report export iterator.
 */
#define REPORT_EXPORT_ITERATOR_FILTER_COLUMNS                              \
  {                                                                        \
    GET_ITERATOR_FILTER_COLUMNS,                                           \
    "report",                                                              \
    "report_uuid",                                                         \
    "delta_report",                                                        \
    "delta_report_uuid",                                                   \
    "report_format",                                                       \
    "report_format_uuid",                                                  \
    "report_format_name",                                                  \
    "report_config",                                                       \
    "report_config_uuid",                                                  \
    "report_config_name",                                                  \
    "export_type",                                                         \
    "status",                                                              \
    "progress",                                                            \
    "ignore_pagination",                                                   \
    "lean",                                                                \
    "worker_pid",                                                          \
    "notes_details",                                                       \
    "overrides_details",                                                   \
    "result_tags",                                                         \
    "file_size",                                                           \
    "content_type",                                                        \
    "extension",                                                           \
    "attempt_count",                                                       \
    "start_time",                                                          \
    "end_time",                                                            \
    NULL                                                                   \
  }

int
create_report_export (report_t,
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
get_report_export_status (report_export_t,
                          report_export_status_t *);

int
get_report_export_status_and_progress (
  report_export_t,
  report_export_status_t *,
  report_export_progress_t *);

int
get_report_export_worker_pid (report_export_t,
                              int *);

void
set_report_export_status (report_export_t,
                          report_export_status_t);

void
set_report_export_progress (report_export_t,
                            report_export_progress_t);

void
start_report_export (report_export_t, int);

void
complete_report_export (report_export_t,
                        const gchar *,
                        long long ,
                        const gchar *,
                        const gchar *);

void
fail_report_export (report_export_t,
                    const gchar *);

void
request_report_export_cancel (report_export_t);

void
cancel_report_export (report_export_t);

#endif /* _GVM_MANAGE_SQL_REPORT_EXPORTS_H */
