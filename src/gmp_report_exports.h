/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report Exports headers
 *
 * Headers for GMP report exports.
 */

#ifndef _GVM_GMP_REPORT_EXPORTS_H
#define _GVM_GMP_REPORT_EXPORTS_H

#include "gmp_base.h"

/* GET_REPORT_EXPORTS. */

void
get_report_exports_start (const gchar **, const gchar **);

void
get_report_exports_run (gmp_parser_t *, GError **);

#endif /* _GVM_GMP_REPORT_EXPORTS_H */
