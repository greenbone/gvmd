/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Structured scan report summary loading.
 */

#ifndef _GVMD_MANAGE_SQL_SCAN_REPORT_H
#define _GVMD_MANAGE_SQL_SCAN_REPORT_H

#include "manage_scan_report.h"

int
manage_sql_fill_report_summary (report_t,
                                const get_data_t *,
                                const gchar *,
                                scan_report_summary_t);

#endif /* _GVMD_MANAGE_SQL_SCAN_REPORT_H */
