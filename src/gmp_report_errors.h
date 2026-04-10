/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVM_GMP_REPORT_ERRORS_H
#define _GVM_GMP_REPORT_ERRORS_H

#include "gmp_base.h"

/* GET_REPORT_ERRORS. */

void
get_report_errors_start (const gchar **, const gchar **);

void
get_report_errors_run (gmp_parser_t *, GError **);

#endif //_GVM_GMP_REPORT_ERRORS_H
