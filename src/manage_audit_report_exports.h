/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_AUDIT_REPORT_EXPORTS_H
#define _GVMD_MANAGE_AUDIT_REPORT_EXPORTS_H

#include "manage_report_exports.h"
#include "manage_report_formats.h"

/**
 * @brief Result of creating an audit report export.
 */
typedef enum
{
  MANAGE_EXPORT_AUDIT_REPORT_ERROR = -1,
  MANAGE_EXPORT_AUDIT_REPORT_SUCCESS = 0,
  MANAGE_EXPORT_AUDIT_REPORT_NOT_FOUND = 1,
  MANAGE_EXPORT_AUDIT_REPORT_FILTER_NOT_FOUND = 2,
  MANAGE_EXPORT_AUDIT_REPORT_UNSUPPORTED_TYPE = 3,
  MANAGE_EXPORT_AUDIT_REPORT_FORMAT_NOT_FOUND = 4,
  MANAGE_EXPORT_AUDIT_REPORT_CONFIG_NOT_FOUND = 5,
  MANAGE_EXPORT_AUDIT_REPORT_UNTRUSTED_REPORT_FORMAT = 6,
  MANAGE_EXPORT_AUDIT_REPORT_FORMAT_CONFIG_MISMATCH = 7
} manage_export_audit_report_response_t;

manage_export_audit_report_response_t
manage_export_audit_report (const gchar *,
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
manage_process_audit_report_export (report_export_t);

#endif /* _GVMD_MANAGE_AUDIT_REPORT_EXPORTS_H */
