/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report export SQL.
 *
 * SQL report export code for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_REPORT_EXPORT_H
#define _GVMD_MANAGE_SQL_REPORT_EXPORT_H

#include "iterator.h"
#include "manage_resources_types.h"

gboolean
export_enabled_for_report (report_t report);

int
queue_report_for_export (report_t report);

void
set_report_export_status_and_reason (report_t report, const gchar *status,
                                     const gchar *reason);

void
set_report_export_next_retry_time (report_t report, long long next_retry_time);

void
set_report_export_retry_count (report_t report, int retry_count);


int
init_report_export_iterator_due_exports (iterator_t *iterator);

report_t
report_export_iterator_report_id (iterator_t *iterator);

const char *
report_export_iterator_status (iterator_t *iterator);

const char *
report_export_iterator_reason (iterator_t *iterator);

int
report_export_iterator_retry_count (iterator_t *iterator);

time_t
report_export_iterator_next_retry_time (iterator_t *iterator);

time_t
report_export_iterator_creation_time (iterator_t *iterator);

time_t
report_export_iterator_modification_time (iterator_t *iterator);

#endif // _GVMD_MANAGE_SQL_REPORT_EXPORT_H
