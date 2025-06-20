/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file scan_handler.h
 * @brief Headers for Greenbone Vulnerability Manager scan handler.
 */

#ifndef _GVMD_SCAN_HANDLER_H
#define _GVMD_SCAN_HANDLER_H

#include "manage_scan_queue.h"
#include <glib.h>

int
fork_scan_handler (const char *, report_t, task_t, user_t, int);

#endif /* _GVMD_SCAN_HANDLER_H */
