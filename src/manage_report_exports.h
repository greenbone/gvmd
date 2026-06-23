/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report exports.
 *
 * Report export code for the GVM management layer.
 */

#ifndef _GVMD_MANAGE_SQL_REPORT_EXPORT_H
#define _GVMD_MANAGE_SQL_REPORT_EXPORT_H

#include "iterator.h"
#include "manage_resources_types.h"
#include "manage_integration_configs.h"


#define REPORT_EXPORT_STATUS_REQUESTED "report_export_requested"
#define REPORT_EXPORT_STATUS_STARTED "report_export_started"
#define REPORT_EXPORT_STATUS_FINISHED "report_export_finished"
#define REPORT_EXPORT_STATUS_FAILED "report_export_failed"

/**
 * @brief Maximum number of report results included in one export page.
 */
#define SECURITY_INTELLIGENCE_REPORT_PAGE_SIZE 25000

/**
 * @brief  Type for return result of export_report()
 */
typedef enum export_report_result
{
  EXPORT_REPORT_RESULT_SUCCESS = 0,
  EXPORT_REPORT_RESULT_TIMEOUT,
  EXPORT_REPORT_RESULT_TOKEN_GENERATION_FAILED,
  EXPORT_REPORT_RESULT_FAILURE = -1,
} export_report_result_t;

export_report_result_t
export_report_security_intelligence (report_t report,
                                     integration_config_data_t config);

gboolean
export_enabled_for_report_owner (report_t report);

int
queue_report_for_export (report_t report);

void
set_report_export_status_and_reason (report_t report, const gchar *status,
                                     const gchar *reason);

void
set_report_export_next_retry_time (report_t report, time_t next_retry_time);

void
set_report_export_retry_count (report_t report, int retry_count);


int
init_report_export_iterator_due_exports (iterator_t *iterator, int max_retries);

int
init_report_export_iterator_stale_exports (iterator_t *iterator,
                                           time_t threshold);

report_t
report_export_iterator_report_id (iterator_t *iterator);

const gchar *
report_export_iterator_status (iterator_t *iterator);

const gchar *
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
