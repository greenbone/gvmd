/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVMD_MANAGE_DELTA_AUDIT_REPORT_EXPORTS_H
#define _GVMD_MANAGE_DELTA_AUDIT_REPORT_EXPORTS_H

#include "manage_audit_report_exports.h"
#include "manage_report_exports.h"

manage_export_audit_report_response_t
manage_export_delta_audit_report (const gchar *,
                                  const gchar *,
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
manage_process_delta_audit_report_export (report_export_t);

#endif /* _GVMD_MANAGE_DELTA_AUDIT_REPORT_EXPORTS_H */
