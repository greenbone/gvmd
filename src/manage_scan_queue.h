/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Greenbone Vulnerability Manager scan queue.
 */

#ifndef _GVMD_MANAGE_SCAN_QUEUE_H
#define _GVMD_MANAGE_SCAN_QUEUE_H

#include <glib.h>
#include "manage_resources.h"

/**
 * @brief Default maximum number of active scan handlers
 */
#define DEFAULT_MAX_ACTIVE_SCAN_HANDLERS 3

void
set_use_scan_queue (gboolean);

gboolean
get_use_scan_queue ();

void
set_scan_handler_active_time (int);

int
get_scan_handler_active_time ();

void
set_max_active_scan_handlers (int);

int get_max_active_scan_handlers ();

void
manage_handle_scan_queue ();

// Functions defined in manage_sql_scan_queue.c

void
scan_queue_clear ();

void
scan_queue_add (report_t);

void
scan_queue_move_to_end (report_t);

void
scan_queue_set_handler_pid (report_t, pid_t);

void
scan_queue_remove (report_t);

int
scan_queue_length ();

#endif /* _GVMD_SCAN_QUEUE_H */
