/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report Applications headers
 *
 * Headers for GMP report applications.
 */
#ifndef _GVM_GMP_REPORT_APPLICATIONS_H
#define _GVM_GMP_REPORT_APPLICATIONS_H

#include "gmp_base.h"

/* GET_REPORT_APPLICATIONS. */

void
get_report_applications_start (const gchar **, const gchar **);

void
get_report_applications_run (gmp_parser_t *, GError **);

#endif //_GVM_GMP_REPORT_APPLICATIONS_H
