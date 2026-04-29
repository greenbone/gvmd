/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report vulnerabilities headers
 *
 * Headers for GMP report vulnerabilities.
 */

#ifndef _GVM_GMP_REPORT_CVES_H
#define _GVM_GMP_REPORT_CVES_H

#include "gmp_base.h"

/* GET_REPORT_CVES. */

void
get_report_vulns_start (const gchar **, const gchar **);

void
get_report_vulns_run (gmp_parser_t *, GError **);

#endif //_GVM_GMP_REPORT_CVES_H
