/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report Closed CVEs headers
 *
 * Headers for GMP report closed CVEs.
 */
#ifndef _GVM_GMP_REPORT_CLOSED_CVES_H
#define _GVM_GMP_REPORT_CLOSED_CVES_H

#include "gmp_base.h"

/* GET_REPORT_CLOSED_CVES. */

void
get_report_closed_cves_start (const gchar **, const gchar **);

void
get_report_closed_cves_run (gmp_parser_t *, GError **);


#endif //_GVM_GMP_REPORT_CLOSED_CVES_H
