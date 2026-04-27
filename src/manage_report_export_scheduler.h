/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM management layer: Report export scheduler.
 *
 * Scheduler code for exporting reports, part of the GVM management layer.
 */

#ifndef _GVMD_MANAGE_REPORT_EXPORT_SCHEDULER_H
#define _GVMD_MANAGE_REPORT_EXPORT_SCHEDULER_H

#include "manage_resources_types.h"

/**
 * @brief  Type for return result of export_report()
 */
typedef enum export_report_result
{
  EXPORT_REPORT_RESULT_SUCCESS = 0,
  EXPORT_REPORT_RESULT_TIMEOUT,
  EXPORT_REPORT_RESULT_FAILURE = -1,
} export_report_result_t;

void
init_report_export_scheduler_from_config ();

int
manage_report_export_scheduler ();

export_report_result_t
export_report (report_t report);

#endif //_GVMD_MANAGE_REPORT_EXPORT_SCHEDULER_H
