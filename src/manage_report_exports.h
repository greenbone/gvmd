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
  REPORT_EXPORT_TYPE_SCAN = 0,
  REPORT_EXPORT_TYPE_AUDIT,
  REPORT_EXPORT_TYPE_DELTA_SCAN,
  REPORT_EXPORT_TYPE_DELTA_AUDIT
} report_export_type_t;

/**
 * @brief Status of a report export.
 */
typedef enum
{
  REPORT_EXPORT_STATUS_PENDING = 0,
  REPORT_EXPORT_STATUS_RUNNING,
  REPORT_EXPORT_STATUS_DONE,
  REPORT_EXPORT_STATUS_ERROR,
  REPORT_EXPORT_STATUS_CANCEL_REQUESTED,
  REPORT_EXPORT_STATUS_CANCELED,
  REPORT_EXPORT_STATUS_EXPIRED
} report_export_status_t;

/**
 * @brief Processing progress of a report export.
 *
 * The values represent processing stages, not percentages.
 */
typedef enum
{
  REPORT_EXPORT_PROGRESS_QUEUED = 0,
  REPORT_EXPORT_PROGRESS_PREPARING,
  REPORT_EXPORT_PROGRESS_GENERATING,
  REPORT_EXPORT_PROGRESS_COMPLETED
} report_export_progress_t;

int
manage_create_report_export (report_t,
                             report_t ,
                             report_format_t,
                             report_config_t,
                             report_export_type_t,
                             const gchar *,
                             const gchar *,
                             const gchar *,
                             gboolean,
                             gboolean,
                             report_export_t *);

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

#endif /* _GVMD_MANAGE_REPORT_EXPORTS_H */
