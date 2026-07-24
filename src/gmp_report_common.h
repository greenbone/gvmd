/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Common structured report serialization.
 */

#ifndef _GVM_GMP_REPORT_COMMON_H
#define _GVM_GMP_REPORT_COMMON_H

#include "gmp_base.h"
#include "manage_report_common.h"

gboolean
send_report_xml (gmp_parser_t *, const gchar *, ...);

gboolean
send_report_base_start (gmp_parser_t *, report_summary_base_t);

gboolean
send_report_task (gmp_parser_t *, report_task_reference_t);

gboolean
send_report_scan_information (gmp_parser_t *, report_summary_base_t);

gboolean
send_report_base_end (gmp_parser_t *, report_summary_base_t);

#endif /* _GVM_GMP_REPORT_COMMON_H */
