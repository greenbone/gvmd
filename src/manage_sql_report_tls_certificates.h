/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief GVM SQL layer: Report tls certificates.
 *
 * Headers for SQL handlers for report tls certificates XML.
 */

#include "manage_sql.h"

#ifndef _GVM_MANAGE_SQL_REPORT_TLS_CERTIFICATES_H
#define _GVM_MANAGE_SQL_REPORT_TLS_CERTIFICATES_H

int
print_report_tls_certificates_xml (report_t,
                                   gboolean,
                                   array_t *,
                                   FILE *);

#endif //_GVM_MANAGE_SQL_REPORT_TLS_CERTIFICATES_H
