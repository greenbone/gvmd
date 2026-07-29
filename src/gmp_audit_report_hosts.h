/* Copyright (C) 2026 Greenbone AG
*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#ifndef _GVM_GMP_AUDIT_REPORT_HOSTS_H
#define _GVM_GMP_AUDIT_REPORT_HOSTS_H

#include "gmp_base.h"

/* GET_AUDIT_REPORT_HOSTS. */

void
get_audit_report_hosts_start (const gchar **, const gchar **);

void
get_audit_report_hosts_run (gmp_parser_t *, GError **);

#endif /* _GVM_GMP_AUDIT_REPORT_HOSTS_H */
