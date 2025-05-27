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

#include <glib.h>
#include "manage_resources.h"

int
run_osp_scan_get_report (task_t, int, char **);

int
handle_osp_scan_start (task_t, target_t, const char *, int);

int
handle_osp_scan (task_t, report_t, const char *);

int
handle_osp_scan_end (task_t, int);

#endif /* _GVMD_SCAN_HANDLER_H */
