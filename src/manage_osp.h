/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file manage_osp.h
 * @brief Greenbone Vulnerability Manager OSP scan handling.
 */

#ifndef _GVMD_SCAN_HANDLER_H
#define _GVMD_SCAN_HANDLER_H

#include <gvm/osp/osp.h>
#include <glib.h>
#include "manage_resources.h"

osp_connection_t *
osp_connect_with_data (const char *,
                       int,
                       const char *,
                       const char *,
                       const char *,
                       gboolean);

osp_connection_t *
osp_scanner_connect (scanner_t);

int
run_osp_scan_get_report (task_t, int, char **);

int
handle_osp_scan_start (task_t, target_t, const char *, int);

int
handle_osp_scan (task_t, report_t, const char *);

int
handle_osp_scan_end (task_t, int);

#endif /* _GVMD_SCAN_HANDLER_H */
