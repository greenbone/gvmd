/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVM_GMP_REPORT_HOSTS_H
#define _GVM_GMP_REPORT_HOSTS_H

#include "gmp_base.h"

#include <gvm/base/array.h>
#include <gvm/util/xmlutils.h>

/* GET_REPORT_HOSTS. */

void
get_report_hosts_start (const gchar **,
                            const gchar **);

void
get_report_hosts_run (gmp_parser_t *gmp_parser, GError **error);

#endif //_GVM_GMP_REPORT_HOSTS_H
