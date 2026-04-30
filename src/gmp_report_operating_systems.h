/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Report operating system headers
 *
 * Headers for GMP report operating systems.
 */

#ifndef _GVM_GMP_REPORT_OPERATING_SYSTEMS_H
#define _GVM_GMP_REPORT_OPERATING_SYSTEMS_H

#include "gmp_base.h"

/* GET_REPORT_OPERATING_SYSTEMS. */

void
get_report_operating_systems_start (const gchar **, const gchar **);

void
get_report_operating_systems_run (gmp_parser_t *, GError **);

#endif //_GVM_GMP_REPORT_OPERATING_SYSTEMS_H
