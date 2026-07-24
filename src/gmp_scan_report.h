/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Scan Report summary command headers.
 */

#ifndef _GVM_GMP_SCAN_REPORT_H
#define _GVM_GMP_SCAN_REPORT_H

#include "gmp_base.h"

/* GET_SCAN_REPORT. */

void
get_scan_report_start (const gchar **attribute_names,
                       const gchar **attribute_values);

void
get_scan_report_run (gmp_parser_t *gmp_parser,
                     GError **error);

#endif /* _GVM_GMP_SCAN_REPORT_H */
