/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM GMP layer: Audit report exports.
 */

#ifndef _GVM_GMP_AUDIT_REPORT_EXPORTS_H
#define _GVM_GMP_AUDIT_REPORT_EXPORTS_H

#include "gmp_base.h"

void
export_audit_report_start (gmp_parser_t *,
                           const gchar **,
                           const gchar **);

void
export_audit_report_run (gmp_parser_t *,
                         GError **);

int
export_audit_report_element_end (gmp_parser_t *,
                                 GError **,
                                 const gchar *);

#endif /* _GVM_GMP_AUDIT_REPORT_EXPORTS_H */
