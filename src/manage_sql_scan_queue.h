/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for Greenbone Vulnerability Manager scan queue SQL.
 */

#ifndef _GVMD_MANAGE_SQL_SCAN_QUEUE_H
#define _GVMD_MANAGE_SQL_SCAN_QUEUE_H

#include "manage_scan_queue.h"
#include "iterator.h"
#include "manage_resources_types.h"
#include "time.h"

void
init_scan_queue_iterator (iterator_t *);

report_t
scan_queue_iterator_report (iterator_t*);

pid_t
scan_queue_iterator_handler_pid (iterator_t *);

int
scan_queue_iterator_start_from (iterator_t*);

const char *
scan_queue_iterator_report_uuid (iterator_t *);

task_t
scan_queue_iterator_task (iterator_t*);

user_t
scan_queue_iterator_owner (iterator_t*);


#endif /* not _GVMD_MANAGE_SQL_SCAN_QUEUE_H */
